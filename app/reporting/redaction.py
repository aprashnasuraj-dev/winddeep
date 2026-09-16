"""Deterministic redacted views for P3 reports and exports."""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"(?:authorization|proxy-authorization|cookie|set-cookie|api[_-]?key|token|password|passwd|secret|credential|session)",
    re.I,
)
_BEARER = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+\-/]+=*")
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[_-]?key|token|password|passwd|secret|credential|session)\b\s*[:=]\s*)([^\s,;&]+)"
)
_JSON_SECRET = re.compile(
    r'(?i)(["\'](?:api[_-]?key|token|password|passwd|secret|credential|session|authorization|cookie)["\']\s*:\s*["\'])(.*?)(["\'])'
)


def redact_text(value: str) -> str:
    """Return a stable textual redacted view without mutating source evidence."""
    text = _BEARER.sub(lambda match: match.group(1) + _REDACTED, value)
    text = _JSON_SECRET.sub(lambda match: match.group(1) + _REDACTED + match.group(3), text)
    text = _ASSIGNMENT.sub(lambda match: match.group(1) + _REDACTED, text)
    return text


def redact_mapping(value: Any) -> Any:
    """Recursively redact values whose keys carry secret semantics."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item).casefold()):
            text_key = str(key)
            result[text_key] = _REDACTED if _SECRET_KEY.search(text_key) else redact_mapping(value[key])
        return result
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    if isinstance(value, tuple):
        return [redact_mapping(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    """Return sorted HTTP headers with security-sensitive values removed."""
    return {
        str(key): (_REDACTED if _SECRET_KEY.search(str(key)) else redact_text(str(value)))
        for key, value in sorted(headers.items(), key=lambda item: str(item[0]).casefold())
    }


def redact_url(url: str) -> str:
    """Redact secret-shaped query parameters while preserving the captured URL."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return redact_text(url)
    pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        pairs.append((key, _REDACTED if _SECRET_KEY.search(key) else redact_text(value)))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs, doseq=True), parsed.fragment))


def redact_body(body: bytes | str, *, content_type: str = "") -> str:
    """Produce a deterministic textual redacted representation of an HTTP body."""
    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
    else:
        text = str(body)
    if "json" in content_type.casefold() or text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return redact_text(text)
        return json.dumps(redact_mapping(parsed), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return redact_text(text)


def redacted_http_request(flow: Mapping[str, Any]) -> str:
    """Render one captured request as a redacted deterministic HTTP transcript."""
    headers = redact_headers(flow.get("request_headers") or {})
    path = str(flow.get("path") or "/")
    query = str(flow.get("query") or "")
    if query:
        url = redact_url(f"https://placeholder.invalid{path}?{query}")
        parsed = urlsplit(url)
        target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    else:
        target = path
    lines = [f"{str(flow.get('method') or 'GET')} {target} HTTP/1.1"]
    if not any(key.casefold() == "host" for key in headers):
        lines.append(f"Host: {flow.get('host') or ''}")
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    content_type = next((value for key, value in headers.items() if key.casefold() == "content-type"), "")
    body = redact_body(flow.get("request_body") or b"", content_type=content_type)
    if body:
        lines.extend(["", body])
    return "\n".join(lines)


def redacted_http_response(flow: Mapping[str, Any]) -> str:
    """Render one captured response as a redacted deterministic HTTP transcript."""
    headers = redact_headers(flow.get("response_headers") or {})
    status = flow.get("status")
    lines = [f"HTTP/1.1 {status if status is not None else ''}".rstrip()]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    content_type = next((value for key, value in headers.items() if key.casefold() == "content-type"), "")
    body = redact_body(flow.get("response_body") or b"", content_type=content_type)
    if body:
        lines.extend(["", body])
    return "\n".join(lines)
