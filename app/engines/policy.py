"""KYC Policy Engine.

A flow declares which checks a tenant requires; the rest of the platform is
flow-agnostic. Adding a client vertical means adding a policy, not code.
"""

from dataclasses import dataclass, field

from app.models.enums import DocumentType, Step


@dataclass(frozen=True)
class FlowPolicy:
    name: str
    label: str
    accepted_documents: tuple[DocumentType, ...]
    steps: tuple[Step, ...]
    # Steps that put the session in REVIEW instead of REJECTED when they fail.
    review_on_failure: frozenset[Step] = field(default_factory=frozenset)
    requires_signature: bool = False

    def requires(self, step: Step) -> bool:
        return step in self.steps


TRAVEL_INSURANCE = FlowPolicy(
    name="TRAVEL_INSURANCE",
    label="Souscription assurance voyage",
    accepted_documents=(DocumentType.PASSPORT,),
    steps=(
        Step.DOCUMENT,
        Step.OCR,
        Step.DOCUMENT_VERIFICATION,
        Step.SELFIE,
        Step.LIVENESS,
        Step.FACE_MATCH,
        Step.OTP,
    ),
    review_on_failure=frozenset({Step.DOCUMENT_VERIFICATION, Step.FACE_MATCH}),
    requires_signature=True,
)

BANK_ACCOUNT = FlowPolicy(
    name="BANK_ACCOUNT",
    label="Ouverture de compte bancaire",
    accepted_documents=(DocumentType.NATIONAL_ID, DocumentType.PASSPORT),
    steps=(
        Step.DOCUMENT,
        Step.OCR,
        Step.DOCUMENT_VERIFICATION,
        Step.SELFIE,
        Step.LIVENESS,
        Step.FACE_MATCH,
        Step.OTP,
    ),
    review_on_failure=frozenset({Step.FACE_MATCH}),
    requires_signature=True,
)

CITIZEN = FlowPolicy(
    name="CITIZEN",
    label="Service administratif citoyen",
    accepted_documents=(DocumentType.NATIONAL_ID, DocumentType.RESIDENCE_PERMIT),
    steps=(Step.DOCUMENT, Step.OCR, Step.DOCUMENT_VERIFICATION, Step.OTP),
    review_on_failure=frozenset({Step.DOCUMENT_VERIFICATION}),
)

FLOWS: dict[str, FlowPolicy] = {
    policy.name: policy for policy in (TRAVEL_INSURANCE, BANK_ACCOUNT, CITIZEN)
}


class UnknownFlowError(ValueError):
    pass


def get_policy(flow: str) -> FlowPolicy:
    try:
        return FLOWS[flow]
    except KeyError as exc:
        raise UnknownFlowError(f"Unknown KYC flow: {flow}") from exc
