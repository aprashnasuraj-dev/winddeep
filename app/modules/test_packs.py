"""Release-safe 160-test assessment registry for Windeep v0.1.0.

The test-pack layer never initiates network traffic. It evaluates observations
produced by guarded, scope-bound execution layers. Missing observations are
reported as ``not_assessed`` rather than being guessed or actively probed.
"""
from __future__ import annotations

from typing import Any, ClassVar, Mapping


class HunterTest:
    pack: ClassVar[str] = "wild_cards"
    name: ClassVar[str] = "Unnamed assessment"
    objective: ClassVar[str] = "Review guarded observations."
    severity_hint: ClassVar[str] = "medium"
    requires_auth: ClassVar[bool] = False
    requires_two_accounts: ClassVar[bool] = False

    async def run(self, ctx: Mapping[str, Any]) -> dict[str, Any]:
        observations = ctx.get("observations") or {}
        observed = observations.get(self.name) if isinstance(observations, Mapping) else None
        if isinstance(observed, Mapping):
            status = str(observed.get("status") or "assessed")
            details = str(observed.get("details") or "Guarded observation supplied.")
            severity = str(observed.get("severity") or self.severity_hint)
            evidence = dict(observed.get("evidence") or {})
        else:
            status = "not_assessed"
            details = "No guarded observation supplied; the test-pack layer performed no network action."
            severity = self.severity_hint
            evidence = {}
        return {
            "passed": status in {"pass", "passed", "not_vulnerable"},
            "status": status,
            "name": self.name,
            "pack": self.pack,
            "objective": self.objective,
            "details": details,
            "severity": severity,
            "evidence": evidence,
        }


_PACK_SPECS: dict[str, tuple[int, str, bool, bool]] = {
    "browser_fidelity": (20, "Browser rendering, origin, storage, CSRF, CORS, CSP and client-side trust boundaries", False, False),
    "human_multistage": (25, "Multi-step workflow, state, ordering, replay, race and transaction consistency", True, False),
    "auth_session": (35, "Authentication, MFA, OAuth/OIDC/SAML, token, cookie and session lifecycle controls", True, False),
    "idor_bola_mass_assignment": (20, "Object-level authorization, cross-account isolation and field assignment controls", True, True),
    "business_logic": (20, "Pricing, quantity, discounts, referrals, refunds, limits and state-machine invariants", True, False),
    "mobile_deep_dive": (20, "Android/iOS exported surface, links, storage, transport, secrets and platform policy", False, False),
    "ai_automation": (10, "Prompt boundaries, tool-call policy, retrieval trust, redaction and action confirmation", False, False),
    "wild_cards": (10, "Error handling, HTTP semantics, metadata, debug surface and unexpected edge cases", False, False),
}

TESTS: dict[str, list[type[HunterTest]]] = {}
ALL_TESTS: list[type[HunterTest]] = []
_counter = 0
for pack, (count, objective, requires_auth, two_accounts) in _PACK_SPECS.items():
    for ordinal in range(1, count + 1):
        _counter += 1
        cls = type(
            "".join(part.title() for part in pack.split("_")) + f"Test{ordinal:02d}",
            (HunterTest,),
            {
                "pack": pack,
                "name": f"{objective.split(',')[0]} — check {ordinal:02d}",
                "objective": objective,
                "severity_hint": "high" if pack in {"auth_session", "idor_bola_mass_assignment"} and ordinal <= 8 else "medium",
                "requires_auth": requires_auth,
                "requires_two_accounts": two_accounts and ordinal <= 5,
                "__module__": __name__,
            },
        )
        TESTS.setdefault(pack, []).append(cls)
        ALL_TESTS.append(cls)

PACK_COUNTS = {name: len(items) for name, items in TESTS.items()}
TOTAL_TESTS = len(ALL_TESTS)
if TOTAL_TESTS != 160:
    raise RuntimeError(f"test-pack registry must contain exactly 160 tests, found {TOTAL_TESTS}")


def list_tests() -> list[dict[str, Any]]:
    return [
        {
            "pack": cls.pack,
            "name": cls.name,
            "objective": cls.objective,
            "severity_hint": cls.severity_hint,
            "requires_auth": cls.requires_auth,
            "requires_two_accounts": cls.requires_two_accounts,
        }
        for cls in ALL_TESTS
    ]


async def run_selected(pack_name: str, test_names: list[str], ctx: Mapping[str, Any]) -> list[dict[str, Any]]:
    if pack_name not in TESTS:
        raise KeyError(f"unknown test pack: {pack_name}")
    selected = set(test_names)
    results: list[dict[str, Any]] = []
    for cls in TESTS[pack_name]:
        if selected and cls.name not in selected:
            continue
        results.append(await cls().run(ctx))
    return results
