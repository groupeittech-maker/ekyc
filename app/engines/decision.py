"""KYC Decision Engine: turns per-step results into a single status and score.

Each decidable step contributes a confidence (0..1) weighted by its business
importance. The weighted average produces an overall risk/confidence score
(0..100). The score then maps to:

    score >= accept_threshold  -> ACCEPT / VERIFIED
    score >= review_threshold  -> REVIEW
    else                       -> REJECT

Hard-fail steps (e.g. liveness) still short-circuit to REJECT regardless of
the global score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.config import settings
from app.engines.policy import FlowPolicy
from app.models.enums import CheckStatus, SessionStatus, Step

# Steps handled by other engines and not reported on their own.
_HIDDEN_STEPS = {Step.OCR, Step.SELFIE, Step.DOCUMENT}

# Steps that always trigger a hard rejection, no matter the global score.
_HARD_REJECT_STEPS = {Step.LIVENESS}

# Business weights for the overall confidence score. They sum to 100.
_STEP_WEIGHTS: dict[Step, float] = {
    Step.DOCUMENT_VERIFICATION: 30.0,
    Step.LIVENESS: 25.0,
    Step.FACE_MATCH: 25.0,
    Step.OTP: 15.0,
    Step.SIGNATURE: 5.0,
}


@dataclass
class StepContribution:
    step: str
    status: str
    weight: float
    confidence: float
    score: float


@dataclass
class Decision:
    status: SessionStatus
    reasons: list[str]
    completed: bool
    score: float = 0.0
    risk_level: str = "UNKNOWN"
    contributions: list[StepContribution] = field(default_factory=list)


def decidable_steps(policy: FlowPolicy) -> list[Step]:
    return [step for step in policy.steps if step not in _HIDDEN_STEPS]


def _step_confidence(step: Step, status: str, internal: dict[str, Any] | None) -> float:
    data = (internal or {}).get(str(step), {})
    if status in (str(CheckStatus.PASSED), str(CheckStatus.REVIEW)):
        if step == Step.DOCUMENT_VERIFICATION:
            return float(
                data.get(
                    "authenticity_confidence",
                    data.get("ocr_confidence", 0.5 if status == str(CheckStatus.REVIEW) else 1.0),
                )
            )
        if step in (Step.LIVENESS, Step.FACE_MATCH):
            return float(data.get("score", 0.5 if status == str(CheckStatus.REVIEW) else 1.0))
        if step == Step.OTP:
            return 1.0 if status == str(CheckStatus.PASSED) else 0.5
        return 0.5 if status == str(CheckStatus.REVIEW) else 1.0
    if status == str(CheckStatus.FAILED):
        return 0.0
    return 0.0


def _compute_risk(
    policy: FlowPolicy, checks: dict[str, str], internal: dict[str, Any] | None
) -> tuple[float, list[StepContribution]]:
    contributions: list[StepContribution] = []
    total = 0.0
    weighted = 0.0
    for step in decidable_steps(policy):
        status = checks.get(str(step), CheckStatus.PENDING)
        if str(status) in (str(CheckStatus.PENDING), str(CheckStatus.SKIPPED)):
            continue
        weight = _STEP_WEIGHTS.get(step, 10.0)
        confidence = _step_confidence(step, str(status), internal)
        contributions.append(
            StepContribution(
                step=str(step),
                status=str(status),
                weight=weight,
                confidence=confidence,
                score=round(confidence * weight, 2),
            )
        )
        total += weight
        weighted += confidence * weight
    if total == 0:
        return 0.0, contributions
    return round((weighted / total) * 100, 2), contributions


def _risk_level(score: float, has_reviews: bool) -> str:
    if score < settings.risk_review_threshold:
        return "REJECT"
    if score < settings.risk_accept_threshold or has_reviews:
        return "REVIEW"
    return "ACCEPT"


def decide(
    policy: FlowPolicy,
    checks: dict[str, str],
    internal: dict[str, Any] | None = None,
) -> Decision:
    required = decidable_steps(policy)
    pending = [
        step
        for step in required
        if checks.get(str(step), CheckStatus.PENDING) == CheckStatus.PENDING
    ]
    failed = [step for step in required if checks.get(str(step)) == CheckStatus.FAILED]
    review = [step for step in required if checks.get(str(step)) == CheckStatus.REVIEW]
    hard_failures = [
        step
        for step in failed
        if step in _HARD_REJECT_STEPS or step not in policy.review_on_failure
    ]
    soft_failures = [step for step in failed if step not in hard_failures]

    if hard_failures:
        return Decision(
            SessionStatus.REJECTED,
            [f"{step}_FAILED" for step in hard_failures],
            completed=True,
            score=0.0,
            risk_level="REJECT",
        )

    has_reviews = bool(soft_failures or review)
    score, contributions = _compute_risk(policy, checks, internal)

    if pending:
        return Decision(
            SessionStatus.IN_PROGRESS,
            [f"{step}_PENDING" for step in pending],
            completed=False,
            score=score,
            risk_level="PENDING",
            contributions=contributions,
        )

    if has_reviews:
        reasons = [f"{step}_REVIEW" for step in soft_failures + review]
        return Decision(
            SessionStatus.REVIEW,
            reasons,
            completed=True,
            score=score,
            risk_level="REVIEW",
            contributions=contributions,
        )

    if score < settings.risk_review_threshold:
        return Decision(
            SessionStatus.REJECTED,
            ["LOW_CONFIDENCE"],
            completed=True,
            score=score,
            risk_level="REJECT",
            contributions=contributions,
        )
    if score < settings.risk_accept_threshold:
        return Decision(
            SessionStatus.REVIEW,
            ["MEDIUM_CONFIDENCE"],
            completed=True,
            score=score,
            risk_level="REVIEW",
            contributions=contributions,
        )

    return Decision(
        SessionStatus.VERIFIED,
        [],
        completed=True,
        score=score,
        risk_level="ACCEPT",
        contributions=contributions,
    )
