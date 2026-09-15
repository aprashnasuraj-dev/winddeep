"""CVSS v3.1 scoring primitives used by deterministic P3 reports."""
from __future__ import annotations

from types import MappingProxyType
from typing import Final

from app.database import cvss31_base_score

CVSS31_METRICS: Final = MappingProxyType(
    {
        "AV": MappingProxyType({"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}),
        "AC": MappingProxyType({"L": 0.77, "H": 0.44}),
        "UI": MappingProxyType({"N": 0.85, "R": 0.62}),
        "CIA": MappingProxyType({"H": 0.56, "L": 0.22, "N": 0.0}),
        "PR": MappingProxyType(
            {
                "U": MappingProxyType({"N": 0.85, "L": 0.62, "H": 0.27}),
                "C": MappingProxyType({"N": 0.85, "L": 0.68, "H": 0.50}),
            }
        ),
    }
)


def score_cvss31(vector: str) -> tuple[float, str]:
    """Return the CVSS v3.1 base score and severity for an explicit vector.

    P3 never guesses missing CVSS metrics.  A report must carry an explicit
    v3.1 vector from the normalized finding; this function recomputes its score
    from the documented metric table before rendering.
    """
    normalized = vector.strip()
    if not normalized.startswith("CVSS:3.1/"):
        raise ValueError("P3 reports require an explicit CVSS:3.1 vector")
    score, severity = cvss31_base_score(normalized)
    return score, severity
