"""KYC Decision Engine: turns per-step results into a single tenant-facing status."""

from __future__ import annotations

from dataclasses import dataclass

from app.engines.policy import FlowPolicy
from app.models.enums import CheckStatus, SessionStatus, Step

# Steps that are internal to the identity engine and never reported on their own.
_HIDDEN_STEPS = {Step.OCR, Step.SELFIE, Step.DOCUMENT}


@dataclass
class Decision:
    status: SessionStatus
    reasons: list[str]
    completed: bool


def decidable_steps(policy: FlowPolicy) -> list[Step]:
    return [step for step in policy.steps if step not in _HIDDEN_STEPS]


def decide(policy: FlowPolicy, checks: dict[str, str]) -> Decision:
    reasons: list[str] = []
    required = decidable_steps(policy)

    pending = [
        step
        for step in required
        if checks.get(str(step), CheckStatus.PENDING) == CheckStatus.PENDING
    ]
    failed = [step for step in required if checks.get(str(step)) == CheckStatus.FAILED]
    review = [step for step in required if checks.get(str(step)) == CheckStatus.REVIEW]

    hard_failures = [step for step in failed if step not in policy.review_on_failure]
    soft_failures = [step for step in failed if step in policy.review_on_failure]

    if hard_failures:
        reasons = [f"{step}_FAILED" for step in hard_failures]
        return Decision(SessionStatus.REJECTED, reasons, completed=True)

    if pending:
        return Decision(SessionStatus.IN_PROGRESS, [f"{step}_PENDING" for step in pending], False)

    if soft_failures or review:
        reasons = [f"{step}_REVIEW" for step in soft_failures + review]
        return Decision(SessionStatus.REVIEW, reasons, completed=True)

    return Decision(SessionStatus.VERIFIED, [], completed=True)
