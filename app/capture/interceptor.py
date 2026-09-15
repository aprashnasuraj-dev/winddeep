"""Deterministic scoped traffic-interception rule engine for Windeep."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

Action = Literal["forward", "modify", "drop", "replay", "tag"]
_ALLOWED_ACTIONS = {"forward", "modify", "drop", "replay", "tag"}


@dataclass(frozen=True, slots=True)
class InterceptorRule:
    """One ordered match/action rule for captured HTTP traffic."""

    name: str
    action: Action
    host: str = "*"
    path: str = "*"
    method: str = "*"
    regex: str | None = None
    set_headers: Mapping[str, str] = field(default_factory=dict)
    set_params: Mapping[str, str] = field(default_factory=dict)
    body: bytes | str | None = None
    tags: tuple[str, ...] = ()
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("rule name cannot be empty")
        if self.action not in _ALLOWED_ACTIONS:
            raise ValueError(f"unsupported interceptor action: {self.action}")
        if self.regex is not None:
            re.compile(self.regex)


@dataclass(slots=True)
class InterceptDecision:
    """Result of applying ordered interceptor rules to one normalized flow."""

    action: Action = "forward"
    matched_rules: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""
    body: bytes = b""
    tags: list[str] = field(default_factory=list)
    replay_requested: bool = False
    dropped: bool = False
    out_of_scope: bool = False


class Interceptor:
    """Apply host/path/method/regex rules without crossing configured scope."""

    def __init__(
        self,
        rules: Sequence[InterceptorRule] = (),
        *,
        scope_validator: Callable[[str], bool] | None,
    ) -> None:
        self.rules = list(rules)
        self.scope_validator = scope_validator

    def add_rule(self, rule: InterceptorRule) -> None:
        """Append a validated rule to the ordered rule set."""
        self.rules.append(rule)

    def remove_rule(self, name: str) -> bool:
        """Remove the first rule with a matching name."""
        for index, rule in enumerate(self.rules):
            if rule.name == name:
                self.rules.pop(index)
                return True
        return False

    def evaluate(self, flow: Mapping[str, Any]) -> InterceptDecision:
        """Evaluate rules and return a mutation/drop/replay decision."""
        url = str(flow.get("url") or "")
        if not url:
            raise ValueError("flow url is required")
        if self.scope_validator is None:
            return self._initial_decision(flow, out_of_scope=True)
        if not self.scope_validator(url):
            return self._initial_decision(flow, out_of_scope=True)

        decision = self._initial_decision(flow, out_of_scope=False)
        for rule in self.rules:
            if not rule.enabled or not self._matches(rule, decision, flow):
                continue
            decision.matched_rules.append(rule.name)
            self._apply(rule, decision)
            if decision.dropped:
                break
        return decision

    @staticmethod
    def _initial_decision(flow: Mapping[str, Any], *, out_of_scope: bool) -> InterceptDecision:
        raw_body = flow.get("request_body")
        if raw_body is None:
            body = b""
        elif isinstance(raw_body, bytes):
            body = raw_body
        elif isinstance(raw_body, memoryview):
            body = raw_body.tobytes()
        else:
            body = str(raw_body).encode("utf-8")
        return InterceptDecision(
            action="forward",
            headers={str(key): str(value) for key, value in dict(flow.get("request_headers") or {}).items()},
            url=str(flow.get("url") or ""),
            body=body,
            tags=list(flow.get("tags") or []),
            out_of_scope=out_of_scope,
        )

    @staticmethod
    def _matches(rule: InterceptorRule, decision: InterceptDecision, original: Mapping[str, Any]) -> bool:
        parts = urlsplit(decision.url)
        host = (parts.hostname or str(original.get("host") or "")).casefold()
        path = parts.path or "/"
        method = str(original.get("method") or "").upper()
        if not fnmatch.fnmatchcase(host, rule.host.casefold()):
            return False
        if not fnmatch.fnmatchcase(path, rule.path):
            return False
        if rule.method != "*" and method != rule.method.upper():
            return False
        if rule.regex is not None:
            haystack = "\n".join(
                [
                    method,
                    decision.url,
                    "\n".join(f"{key}: {value}" for key, value in decision.headers.items()),
                    decision.body.decode("utf-8", errors="replace"),
                ]
            )
            if re.search(rule.regex, haystack) is None:
                return False
        return True

    def _apply(self, rule: InterceptorRule, decision: InterceptDecision) -> None:
        if rule.action == "forward":
            decision.action = "forward"
            return
        if rule.action == "drop":
            decision.action = "drop"
            decision.dropped = True
            return
        if rule.action == "replay":
            decision.action = "replay"
            decision.replay_requested = True
            return
        if rule.action == "tag":
            decision.action = "tag"
            self._merge_tags(decision.tags, rule.tags or (rule.name,))
            return
        if rule.action == "modify":
            decision.action = "modify"
            for key, value in rule.set_headers.items():
                self._set_header(decision.headers, str(key), str(value))
            if rule.set_params:
                decision.url = self._set_params(decision.url, rule.set_params)
            if rule.body is not None:
                decision.body = rule.body if isinstance(rule.body, bytes) else rule.body.encode("utf-8")
            self._merge_tags(decision.tags, rule.tags)
            return
        raise ValueError(f"unsupported action: {rule.action}")

    @staticmethod
    def _set_header(headers: dict[str, str], name: str, value: str) -> None:
        lowered = name.casefold()
        for key in list(headers):
            if key.casefold() == lowered:
                headers.pop(key)
        headers[name] = value

    @staticmethod
    def _set_params(url: str, values: Mapping[str, str]) -> str:
        parts = urlsplit(url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        names = set(values)
        params = [(key, value) for key, value in params if key not in names]
        params.extend((str(key), str(value)) for key, value in values.items())
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params, doseq=True), parts.fragment))

    @staticmethod
    def _merge_tags(existing: list[str], incoming: Sequence[str]) -> None:
        for tag in incoming:
            if tag and tag not in existing:
                existing.append(tag)
