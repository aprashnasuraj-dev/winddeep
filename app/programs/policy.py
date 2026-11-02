"""Program-rule enforcement for bug-bounty workflows.

Program scope is more than a host allow-list. This module models execution
constraints that determine which Windeep capabilities may be used after scope
and consent are established. The policy remains fail-closed for unresolved
operator-specific target templates.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, replace
from typing import Any, Mapping
from urllib.parse import urlparse


class ProgramPolicyViolation(PermissionError):
    """Raised when a program rule forbids a requested testing action."""


_HOST_VALUE_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_TEMPLATE_VALUE_RE = re.compile(r"^[A-Za-z0-9-]+$")


def _hostname(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or "").rstrip(".").casefold()


def _host_matches(host: str, rule: str) -> bool:
    normalized = _hostname(rule)
    if not host or not normalized:
        return False
    if normalized.startswith("*."):
        suffix = normalized[2:]
        return host.endswith("." + suffix) and host != suffix
    if any(char in normalized for char in "*?["):
        return fnmatch.fnmatchcase(host, normalized)
    return host == normalized


@dataclass(frozen=True, slots=True)
class ProgramTestingPolicy:
    """Normalized execution policy derived from a program's rules of engagement."""

    automated_tooling_allowed: bool = True
    browser_automation_allowed: bool = True
    network_probing_allowed: bool = True
    manual_testing_allowed: bool = True
    no_pivoting: bool = False
    owned_instance_only: bool = False
    requires_app_context: bool = False
    latest_version_only: bool = False
    allowed_hosts: tuple[str, ...] = ()
    allowed_host_templates: tuple[str, ...] = ()
    denied_hosts: tuple[str, ...] = ()
    reporting_only_hosts: tuple[str, ...] = ()
    focus_classes: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None) -> "ProgramTestingPolicy":
        """Normalize a policy mapping while ignoring unrelated descriptive fields."""
        source = dict(payload or {})
        if isinstance(source.get("testing_requirements"), Mapping):
            merged = dict(source["testing_requirements"])
            for key, value in source.items():
                if key != "testing_requirements" and key not in merged:
                    merged[key] = value
            source = merged

        def values(key: str) -> tuple[str, ...]:
            raw = source.get(key) or ()
            if isinstance(raw, str):
                raw = (raw,)
            if not isinstance(raw, (list, tuple, set, frozenset)):
                raise ValueError(f"{key} must be a sequence of strings")
            return tuple(str(item).strip() for item in raw if str(item).strip())

        return cls(
            automated_tooling_allowed=bool(source.get("automated_tooling_allowed", True)),
            browser_automation_allowed=bool(source.get("browser_automation_allowed", source.get("automated_tooling_allowed", True))),
            network_probing_allowed=bool(source.get("network_probing_allowed", source.get("automated_tooling_allowed", True))),
            manual_testing_allowed=bool(source.get("manual_testing_allowed", True)),
            no_pivoting=bool(source.get("no_pivoting", False)),
            owned_instance_only=bool(source.get("owned_instance_only", False)),
            requires_app_context=bool(source.get("requires_app_context", False)),
            latest_version_only=bool(source.get("latest_version_only", False)),
            allowed_hosts=values("allowed_hosts"),
            allowed_host_templates=values("allowed_host_templates"),
            denied_hosts=values("denied_hosts"),
            reporting_only_hosts=values("reporting_only_hosts"),
            focus_classes=values("focus_classes"),
            notes=values("notes"),
        )

    def bind(self, values: Mapping[str, str]) -> "ProgramTestingPolicy":
        """Bind operator-specific host templates to exact concrete hosts."""
        bound: list[str] = list(self.allowed_hosts)
        for template in self.allowed_host_templates:
            try:
                host = template.format_map(dict(values))
            except KeyError as exc:
                raise ProgramPolicyViolation(f"program target template is missing value: {exc.args[0]}") from exc
            if "{" in host or "}" in host:
                raise ProgramPolicyViolation("program target template contains unresolved placeholders")
            host = host.strip().rstrip(".").casefold()
            if not _HOST_VALUE_RE.fullmatch(host):
                raise ProgramPolicyViolation(f"bound program host is invalid: {host}")
            for value in values.values():
                if not _TEMPLATE_VALUE_RE.fullmatch(str(value)):
                    raise ProgramPolicyViolation("program target template values may contain only letters, digits, and hyphens")
            bound.append(host)
        return replace(self, allowed_hosts=tuple(dict.fromkeys(bound)), allowed_host_templates=())

    def to_mapping(self) -> dict[str, Any]:
        """Return a serializable representation suitable for ScanContext."""
        return {
            "automated_tooling_allowed": self.automated_tooling_allowed,
            "browser_automation_allowed": self.browser_automation_allowed,
            "network_probing_allowed": self.network_probing_allowed,
            "manual_testing_allowed": self.manual_testing_allowed,
            "no_pivoting": self.no_pivoting,
            "owned_instance_only": self.owned_instance_only,
            "requires_app_context": self.requires_app_context,
            "latest_version_only": self.latest_version_only,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_host_templates": list(self.allowed_host_templates),
            "denied_hosts": list(self.denied_hosts),
            "reporting_only_hosts": list(self.reporting_only_hosts),
            "focus_classes": list(self.focus_classes),
            "notes": list(self.notes),
        }

    def public_summary(self) -> dict[str, Any]:
        """Expose non-secret policy facts to local planning/reasoning components."""
        return {
            "automated_tooling_allowed": self.automated_tooling_allowed,
            "browser_automation_allowed": self.browser_automation_allowed,
            "network_probing_allowed": self.network_probing_allowed,
            "manual_testing_allowed": self.manual_testing_allowed,
            "no_pivoting": self.no_pivoting,
            "owned_instance_only": self.owned_instance_only,
            "requires_app_context": self.requires_app_context,
            "latest_version_only": self.latest_version_only,
            "focus_classes": list(self.focus_classes),
        }

    def assert_target_context(self, target: str, metadata: Mapping[str, Any] | None = None) -> None:
        """Validate target identity and operator attestations for target-facing work."""
        meta = dict(metadata or {})
        host = _hostname(target)
        if not host:
            raise ProgramPolicyViolation("program policy requires a concrete target hostname")
        if self.allowed_host_templates:
            raise ProgramPolicyViolation("program target template must be bound to the operator before target-facing work")
        if any(_host_matches(host, rule) for rule in self.reporting_only_hosts):
            raise ProgramPolicyViolation(f"target is a reporting/listing host, not an authorized test target: {host}")
        if any(_host_matches(host, rule) for rule in self.denied_hosts):
            raise ProgramPolicyViolation(f"target is explicitly denied by program policy: {host}")
        if self.allowed_hosts and not any(_host_matches(host, rule) for rule in self.allowed_hosts):
            raise ProgramPolicyViolation(f"target is not the operator-bound program instance: {host}")
        if self.owned_instance_only and meta.get("instance_owned") is not True:
            raise ProgramPolicyViolation("program policy requires an operator-owned test instance")
        if self.requires_app_context and not meta.get("program_app_context"):
            raise ProgramPolicyViolation("program policy requires confirmation that testing is limited to the in-scope app")
        if self.latest_version_only and meta.get("latest_product_version") is not True:
            raise ProgramPolicyViolation("program policy requires the latest eligible product version")

    def assert_execution(
        self,
        execution_kind: str,
        *,
        target: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        """Fail closed when a requested capability conflicts with program rules."""
        kind = str(execution_kind or "").strip().casefold()
        if not kind:
            raise ProgramPolicyViolation("execution kind is required")
        if kind == "automated_tool" and not self.automated_tooling_allowed:
            raise ProgramPolicyViolation("program rules prohibit automated tools/scanners")
        if kind == "browser_automation" and not self.browser_automation_allowed:
            raise ProgramPolicyViolation("program rules prohibit browser automation")
        if kind == "network_probe" and not self.network_probing_allowed:
            raise ProgramPolicyViolation("program rules prohibit automated network probing")
        if kind == "manual_interaction" and not self.manual_testing_allowed:
            raise ProgramPolicyViolation("program rules prohibit manual target interaction")
        if kind == "pivot" and self.no_pivoting:
            raise ProgramPolicyViolation("program rules prohibit pivoting/post-exploitation")

        target_facing = {"automated_tool", "browser_automation", "network_probe", "manual_interaction", "pivot"}
        if kind in target_facing:
            self.assert_target_context(target, metadata)

    def allows_execution(
        self,
        execution_kind: str,
        *,
        target: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> bool:
        try:
            self.assert_execution(execution_kind, target=target, metadata=metadata)
        except ProgramPolicyViolation:
            return False
        return True

    def sanitize_chain_hints(self, hints: tuple[str, ...] | list[str]) -> list[str]:
        """Suppress active chaining hints when the program forbids pivoting."""
        return [] if self.no_pivoting else [str(item) for item in hints]
