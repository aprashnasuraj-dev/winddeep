"""Guardrail-preserving 160-test production test-pack registry.

The pack runner is deliberately evidence-driven. It never performs exploit
traffic by itself. Tests inspect encrypted-at-rest captured evidence, imported
metadata, and explicit analyst signals. Tests that require authenticated state,
two accounts, a mobile device, or manual business confirmation skip closed when
the prerequisite is absent. Network activity remains the responsibility of the
guarded scheduler/tool/browser layers.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


@dataclass(slots=True)
class HunterContext:
    """Evidence supplied to one test-pack execution."""

    target_url: str
    target_id: int | None = None
    flows: list[Mapping[str, Any]] = field(default_factory=list)
    findings: list[Mapping[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    signals: set[str] = field(default_factory=set)
    authenticated: bool = False
    account_count: int = 0
    mobile_artifact: bool = False
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("windeep.test_packs"))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "HunterContext":
        return cls(
            target_url=str(value.get("target_url") or value.get("target") or ""),
            target_id=value.get("target_id"),
            flows=list(value.get("flows") or []),
            findings=list(value.get("findings") or []),
            metadata=dict(value.get("metadata") or {}),
            signals={str(v) for v in value.get("signals") or []},
            authenticated=bool(value.get("authenticated", False)),
            account_count=int(value.get("account_count") or 0),
            mobile_artifact=bool(value.get("mobile_artifact", False)),
            logger=value.get("logger") or logging.getLogger("windeep.test_packs"),
        )


@dataclass(frozen=True, slots=True)
class TestSpec:
    pack: str
    name: str
    severity_hint: str = "medium"
    requires_auth: bool = False
    requires_two_accounts: bool = False
    requires_mobile: bool = False
    execution_mode: str = "passive_evidence"
    aliases: tuple[str, ...] = ()

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-z0-9]+", "_", self.name.casefold()).strip("_")


class HunterTest:
    """Base class for all release test-pack tests."""

    spec: TestSpec
    pack = ""
    name = ""
    severity_hint = "medium"
    requires_auth = False
    requires_two_accounts = False
    requires_mobile = False
    execution_mode = "passive_evidence"

    async def run(self, ctx: HunterContext | Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(ctx, HunterContext):
            ctx = HunterContext.from_mapping(ctx)
        if not ctx.target_url:
            return self._result("skipped", False, "Target is missing from test context.")
        if self.requires_auth and not ctx.authenticated:
            return self._result("skipped", False, "Authenticated evidence is required for this test.")
        if self.requires_two_accounts and ctx.account_count < 2:
            return self._result("skipped", False, "Two explicitly authorized test accounts are required.")
        if self.requires_mobile and not ctx.mobile_artifact:
            return self._result("skipped", False, "A locally supplied mobile artifact/device evidence set is required.")

        signal_keys = {self.spec.slug, *self.spec.aliases}
        explicit = signal_keys.intersection({s.casefold() for s in ctx.signals})
        if explicit:
            return self._result(
                "observed",
                True,
                "Explicit analyst/tool evidence signal is present; manual confirmation is still required before reporting.",
                evidence={"signals": sorted(explicit)},
                confidence=0.8,
            )

        observed = self._passive_observation(ctx)
        if observed:
            return self._result(
                "review",
                False,
                "Passive evidence contains a review indicator. No vulnerability is asserted automatically.",
                evidence=observed,
                confidence=0.35,
            )
        if self.execution_mode == "manual_review":
            return self._result("skipped", False, "This business/state test requires explicit analyst confirmation evidence.")
        return self._result("not_observed", False, "No matching evidence was observed in the supplied capture/findings set.")

    def _passive_observation(self, ctx: HunterContext) -> dict[str, Any]:
        """Return bounded, non-exploit evidence hints for a small set of safe checks."""
        slug = self.spec.slug
        flows = ctx.flows[-500:]
        if slug == "missing_csp":
            return self._missing_header(flows, "content-security-policy")
        if slug == "clickjacking_exposure":
            for flow in flows:
                headers = _headers(flow.get("response_headers"))
                if headers and "x-frame-options" not in headers and "content-security-policy" not in headers:
                    return {"flow_id": flow.get("id"), "indicator": "frame protections not observed"}
        if slug == "cookie_secure_flag_weakness":
            return self._cookie_flag(flows, "secure")
        if slug == "cookie_httponly_weakness":
            return self._cookie_flag(flows, "httponly")
        if slug == "cookie_samesite_weakness":
            return self._cookie_flag(flows, "samesite")
        if slug == "cors_wildcard_origin":
            for flow in flows:
                headers = _headers(flow.get("response_headers"))
                if headers.get("access-control-allow-origin") == "*":
                    return {"flow_id": flow.get("id"), "header": "Access-Control-Allow-Origin: *"}
        if slug == "verbose_error_disclosure":
            needles = ("traceback", "stack trace", "exception", "sqlstate")
            for flow in flows:
                body = _body_text(flow.get("response_body"))[:200_000].casefold()
                match = next((n for n in needles if n in body), None)
                if match:
                    return {"flow_id": flow.get("id"), "indicator": match}
        if slug == "server_version_disclosure":
            for flow in flows:
                server = _headers(flow.get("response_headers")).get("server", "")
                if re.search(r"\d+\.\d+", server):
                    return {"flow_id": flow.get("id"), "server": server[:200]}
        if slug == "jwt_expiration_validation":
            for flow in flows:
                text = json.dumps(flow, default=str)[:300_000]
                if re.search(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", text):
                    return {"flow_id": flow.get("id"), "indicator": "JWT-shaped token observed; validation requires guarded auth suite"}
        return {}

    @staticmethod
    def _missing_header(flows: Iterable[Mapping[str, Any]], header: str) -> dict[str, Any]:
        for flow in flows:
            headers = _headers(flow.get("response_headers"))
            if headers and header not in headers:
                return {"flow_id": flow.get("id"), "missing_header": header}
        return {}

    @staticmethod
    def _cookie_flag(flows: Iterable[Mapping[str, Any]], flag: str) -> dict[str, Any]:
        for flow in flows:
            cookie = _headers(flow.get("response_headers")).get("set-cookie", "")
            if cookie and flag.casefold() not in cookie.casefold():
                return {"flow_id": flow.get("id"), "cookie_flag_not_observed": flag}
        return {}

    def _result(
        self,
        status: str,
        passed: bool,
        details: str,
        *,
        evidence: Mapping[str, Any] | None = None,
        confidence: float = 0.0,
    ) -> dict[str, Any]:
        return {
            "pack": self.pack,
            "name": self.name,
            "test_id": self.spec.slug,
            "status": status,
            "passed": passed,
            "details": details,
            "severity": self.severity_hint if passed else "info",
            "severity_hint": self.severity_hint,
            "confidence": confidence,
            "evidence": dict(evidence or {}),
            "execution_mode": self.execution_mode,
            "requires_auth": self.requires_auth,
            "requires_two_accounts": self.requires_two_accounts,
            "requires_mobile": self.requires_mobile,
        }


def _headers(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k).casefold(): str(v) for k, v in value.items()}


def _body_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


PACK_NAMES: dict[str, list[str]] = {
    "browser_fidelity": [
        "Reflected input marker", "DOM sink exposure", "Stored content reflection", "HTML attribute reflection", "JavaScript context reflection",
        "Missing CSRF token", "Weak CSRF token binding", "CORS wildcard origin", "CORS credential reflection", "Clickjacking exposure",
        "Missing CSP", "Weak CSP unsafe-inline", "Cache key variance", "Cache control on sensitive response", "Host header reflection",
        "Open redirect indicator", "Mixed content reference", "Cookie SameSite weakness", "Cookie Secure flag weakness", "Cookie HttpOnly weakness",
    ],
    "human_multistage": [
        "Multi-step state transition", "Out-of-order workflow step", "Repeated state transition", "State token replay indicator", "AJAX sequencing dependency",
        "Workflow resume after logout", "Cross-tab state reuse", "Stale form resubmission", "Duplicate action idempotency", "Concurrent request ordering",
        "Cart-to-checkout state drift", "Profile change then privileged action", "Password change session continuity", "Email change confirmation flow", "Recovery flow state persistence",
        "Invite acceptance state reuse", "Role change propagation delay", "Upload then processing transition", "Export job ownership transition", "Background job result ownership",
        "WebSocket state synchronization", "API-to-browser state mismatch", "Mobile-to-web state mismatch", "Retry-after partial failure", "Long-running transaction recovery",
    ],
    "auth_session": [
        "Session cookie entropy signal", "Session fixation indicator", "Session rotation after login", "Session rotation after privilege change", "Session invalidation after logout",
        "Concurrent session policy", "Idle timeout enforcement", "Absolute timeout enforcement", "Remember-me token scope", "Password reset token expiry",
        "Password reset token reuse", "Password reset user binding", "Email verification token expiry", "Email verification token reuse", "MFA enrollment confirmation",
        "MFA recovery code handling", "MFA step-up enforcement", "JWT expiration validation", "JWT not-before validation", "JWT audience validation",
        "JWT issuer validation", "JWT algorithm allowlist", "JWT key identifier handling", "OAuth state validation", "OAuth PKCE enforcement",
        "OAuth redirect URI binding", "OAuth token audience", "SAML response destination", "SAML assertion expiry", "SAML recipient binding",
        "Account lockout policy", "Credential stuffing rate limit", "Default credential indicator", "Authentication error enumeration", "Post-auth redirect integrity",
    ],
    "idor_bola": [
        "Sequential object identifier", "Predictable UUID indicator", "Cross-user object read signal", "Cross-user object update signal", "Cross-user object delete signal",
        "Nested resource ownership", "File download ownership", "Export ownership", "Invoice ownership", "Message ownership",
        "Profile field overposting", "Role field overposting", "Tenant identifier override", "Owner identifier override", "Account identifier override",
        "Duplicate parameter ambiguity", "Array parameter authorization", "GraphQL node authorization", "Bulk endpoint authorization", "Indirect reference ownership",
    ],
    "business_logic": [
        "Price field client control", "Quantity boundary handling", "Negative quantity handling", "Discount boundary handling", "Coupon reuse policy",
        "Coupon stacking policy", "Referral self-credit", "Referral loop indicator", "Inventory race protection", "Payment idempotency",
        "Refund amount binding", "Currency binding", "Shipping fee binding", "Plan downgrade boundary", "Trial reuse policy",
        "Quota reset boundary", "Approval workflow bypass signal", "One-time action replay", "Order state transition integrity", "Feature entitlement drift",
    ],
    "mobile_deep_dive": [
        "Android exported activity review", "Android exported service review", "Android exported receiver review", "Android exported provider review", "Android debuggable flag",
        "Android backup flag", "Android cleartext traffic policy", "Android network security config", "Android WebView debugging", "Android deep-link validation",
        "Android intent input trust", "Android shared preferences exposure", "Android local database exposure", "Android hardcoded secret signal", "Android certificate pinning presence",
        "iOS ATS configuration", "iOS URL scheme validation", "iOS keychain accessibility", "iOS pasteboard exposure", "Mobile root-jailbreak trust boundary",
    ],
    "ai_automation": [
        "Prompt injection boundary", "Indirect prompt injection boundary", "System prompt disclosure signal", "Tool call authorization boundary", "Tool argument scope enforcement",
        "Retrieved content trust marking", "Model output action confirmation", "Sensitive context minimization", "Cross-tenant context isolation", "Training data retention disclosure",
    ],
    "wild_cards": [
        "Verbose error disclosure", "Server version disclosure", "HTTP method inconsistency", "Unexpected content type handling", "Header injection indicator",
        "Unicode normalization boundary", "Path normalization boundary", "Case sensitivity authorization drift", "Alternate port behavior", "Metadata endpoint exposure",
    ],
}

_EXPECTED_COUNTS = {
    "browser_fidelity": 20,
    "human_multistage": 25,
    "auth_session": 35,
    "idor_bola": 20,
    "business_logic": 20,
    "mobile_deep_dive": 20,
    "ai_automation": 10,
    "wild_cards": 10,
}


def _severity(pack: str, name: str) -> str:
    high_words = ("cross-user", "role", "owner", "mfa", "password reset", "prompt injection", "hardcoded secret")
    if any(word in name.casefold() for word in high_words):
        return "high"
    if pack in {"auth_session", "idor_bola", "business_logic"}:
        return "medium"
    return "low"


def _build_spec(pack: str, name: str) -> TestSpec:
    auth = pack in {"auth_session", "idor_bola", "business_logic", "human_multistage"}
    two = pack == "idor_bola" or "cross-user" in name.casefold()
    mobile = pack == "mobile_deep_dive"
    manual = pack in {"human_multistage", "idor_bola", "business_logic"}
    return TestSpec(
        pack=pack,
        name=name,
        severity_hint=_severity(pack, name),
        requires_auth=auth,
        requires_two_accounts=two,
        requires_mobile=mobile,
        execution_mode="manual_review" if manual else "passive_evidence",
    )


def _class_name(pack: str, name: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", f"{pack} {name}")
    return "".join(word[:1].upper() + word[1:] for word in words) + "Test"


TESTS: dict[str, list[type[HunterTest]]] = {}
for _pack, _names in PACK_NAMES.items():
    if len(_names) != _EXPECTED_COUNTS[_pack]:
        raise RuntimeError(f"test-pack count mismatch for {_pack}: {len(_names)}")
    _classes: list[type[HunterTest]] = []
    for _name in _names:
        _spec = _build_spec(_pack, _name)
        _class = type(
            _class_name(_pack, _name),
            (HunterTest,),
            {
                "spec": _spec,
                "pack": _spec.pack,
                "name": _spec.name,
                "severity_hint": _spec.severity_hint,
                "requires_auth": _spec.requires_auth,
                "requires_two_accounts": _spec.requires_two_accounts,
                "requires_mobile": _spec.requires_mobile,
                "execution_mode": _spec.execution_mode,
                "__module__": __name__,
            },
        )
        globals()[_class.__name__] = _class
        _classes.append(_class)
    TESTS[_pack] = _classes


def all_tests() -> list[type[HunterTest]]:
    return [test for pack in TESTS.values() for test in pack]


def list_test_metadata() -> list[dict[str, Any]]:
    return [
        {
            "id": cls.spec.slug,
            "pack": cls.pack,
            "name": cls.name,
            "severity_hint": cls.severity_hint,
            "requires_auth": cls.requires_auth,
            "requires_two_accounts": cls.requires_two_accounts,
            "requires_mobile": cls.requires_mobile,
            "execution_mode": cls.execution_mode,
        }
        for cls in all_tests()
    ]


async def run_selected_tests(
    ctx: HunterContext | Mapping[str, Any],
    *,
    packs: Iterable[str] | None = None,
    test_ids: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Execute selected evidence tests without generating network traffic."""
    context = ctx if isinstance(ctx, HunterContext) else HunterContext.from_mapping(ctx)
    selected_packs = set(packs or TESTS.keys())
    selected_ids = {str(v) for v in test_ids or []}
    classes = [
        cls for pack, group in TESTS.items() if pack in selected_packs
        for cls in group if not selected_ids or cls.spec.slug in selected_ids
    ]
    results: list[dict[str, Any]] = []
    for cls in classes:
        try:
            results.append(await cls().run(context))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            context.logger.exception("test pack failure: %s", cls.name)
            results.append({
                "pack": cls.pack,
                "name": cls.name,
                "test_id": cls.spec.slug,
                "status": "error",
                "passed": False,
                "details": str(exc),
                "severity": "info",
                "severity_hint": cls.severity_hint,
                "confidence": 0.0,
                "evidence": {},
            })
    return results


if len(all_tests()) != 160:
    raise RuntimeError(f"Windeep must expose exactly 160 release tests, found {len(all_tests())}")
