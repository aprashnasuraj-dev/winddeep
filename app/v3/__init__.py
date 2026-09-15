"""Windeep v3 release wiring: frozen contracts, verification, and pipeline coordination."""

from app.v3.contracts import PUBLIC_CONTRACTS, V3_EVENT_TYPES, frozen_contract_manifest
from app.v3.pipeline import V3PipelineCoordinator, V3_STAGE_ORDER
from app.v3.verification import VerificationError, VerificationPass

__all__ = [
    "PUBLIC_CONTRACTS",
    "V3_EVENT_TYPES",
    "V3PipelineCoordinator",
    "V3_STAGE_ORDER",
    "VerificationError",
    "VerificationPass",
    "frozen_contract_manifest",
]
