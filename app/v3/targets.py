"""V3-A full-target declarations and guarded IP/CIDR capture planning.

This module does not create an alternate network path. A connector is injected
from the capture layer and is invoked only after declaration validation, live
preflight authorization, and per-IP/per-host rate acquisition.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from app.evidence.redaction import EvidenceRedactor

TARGET_CLASSES = frozenset(
    {
        "domain",
        "subdomain",
        "ipv4",
        "ipv6",
        "cidr",
        "ip_range",
        "url",
        "ip_url",
        "service",
        "contract",
        "source_repo",
    }
)
_MAX_AUDITABLE_RANGE_HOSTS = 4096
_CONTRACT_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class TargetClassError(PermissionError):
    """Raised before send when a v3 target declaration or route is invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if "%" in value:
        raise TargetClassError("IPv6 zone ids are not allowed in v3 target declarations")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise TargetClassError(f"invalid IP address: {value}") from exc


def _url_ip(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise TargetClassError("ip_url requires an absolute http(s) URL")
    return str(_parse_ip(parts.hostname))


def _service(value: str) -> tuple[str, int]:
    text = value.strip()
    if text.startswith("["):
        end = text.find("]")
        if end < 0 or end + 2 > len(text) or text[end + 1] != ":":
            raise TargetClassError("IPv6 service must use [address]:port syntax")
        host, port_text = text[1:end], text[end + 2 :]
    else:
        host, sep, port_text = text.rpartition(":")
        if not sep:
            raise TargetClassError("service target requires an explicit port")
    if "%" in host:
        raise TargetClassError("IPv6 zone ids are not allowed in service targets")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise TargetClassError("service port must be numeric") from exc
    if not 1 <= port <= 65535:
        raise TargetClassError("service port must be between 1 and 65535")
    return host, port


def _ip_range(value: str) -> tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]:
    left, sep, right = value.partition("-")
    if not sep:
        raise TargetClassError("ip_range requires start-end")
    start, end = _parse_ip(left.strip()), _parse_ip(right.strip())
    if start.version != end.version or int(end) < int(start):
        raise TargetClassError("ip_range endpoints must share a family and be ascending")
    return start, end


def _enc(database: Any, value: Any, *, field: str) -> str:
    encoder = getattr(database, "_enc", None)
    if not callable(encoder):
        raise TargetClassError("v3 target declarations require encrypted database fields")
    return encoder(_canonical(value).decode("utf-8"), field=field)


def _dec(database: Any, value: str, *, field: str) -> Any:
    decoder = getattr(database, "_dec", None)
    if not callable(decoder):
        raise TargetClassError("v3 target declarations require encrypted database fields")
    return json.loads(decoder(value, field=field))


class TargetDeclarationStore:
    """Persist explicit target-class consent and route constraints."""

    def __init__(self, database: Any, audit: Any, guard: Any, *, artifacts: Any | None = None) -> None:
        self.database = database
        self.audit = audit
        self.guard = guard
        self.artifacts = artifacts

    @staticmethod
    def _ports(ports: Sequence[int]) -> list[int]:
        values = sorted({int(value) for value in ports})
        if not values or any(value < 1 or value > 65535 for value in values):
            raise TargetClassError("at least one declared port between 1 and 65535 is required")
        return values

    @staticmethod
    def _validate_value(target_class: str, value: str) -> str:
        text = value.strip()
        if not text:
            raise TargetClassError("target value is required")
        if target_class == "ipv4":
            address = _parse_ip(text)
            if address.version != 4:
                raise TargetClassError("ipv4 class requires an IPv4 address")
            return str(address)
        if target_class == "ipv6":
            address = _parse_ip(text)
            if address.version != 6:
                raise TargetClassError("ipv6 class requires an IPv6 address")
            return str(address)
        if target_class == "cidr":
            if "%" in text:
                raise TargetClassError("IPv6 zone ids are not allowed in CIDR targets")
            try:
                return str(ipaddress.ip_network(text, strict=False))
            except ValueError as exc:
                raise TargetClassError("invalid CIDR range") from exc
        if target_class == "ip_range":
            start, end = _ip_range(text)
            return f"{start}-{end}"
        if target_class == "ip_url":
            _url_ip(text)
            return text
        if target_class in {"url", "source_repo"}:
            parts = urlsplit(text)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise TargetClassError(f"{target_class} requires an absolute http(s) URL")
            if parts.hostname and "%" in parts.hostname:
                raise TargetClassError("IPv6 zone ids are not allowed in URLs")
            return text
        if target_class == "service":
            _service(text)
            return text
        if target_class == "contract" and not _CONTRACT_RE.fullmatch(text):
            raise TargetClassError("contract target requires a 20-byte hexadecimal address")
        if target_class in {"domain", "subdomain"}:
            if "://" in text or "/" in text or not text.strip("."):
                raise TargetClassError(f"invalid {target_class} value")
            return text.casefold().rstrip(".")
        return text

    def declare(
        self,
        *,
        scan_id: int,
        target_class: str,
        value: str,
        ports: Sequence[int],
        sni: Sequence[str],
        host_headers: Sequence[str],
        consent_token_id: str,
        justification: str,
        max_hosts: int | None = None,
    ) -> int:
        klass = target_class.strip().casefold()
        if klass not in TARGET_CLASSES:
            raise TargetClassError(f"unsupported target class: {target_class}")
        consent = consent_token_id.strip()
        reason = justification.strip()
        if not consent:
            raise TargetClassError("consent_token_id is required for every target class")
        if not reason:
            raise TargetClassError("justification is required for every target class")
        normalized = self._validate_value(klass, value)
        declared_ports = self._ports(ports)
        sni_values = sorted({str(item).strip().casefold() for item in sni if str(item).strip()})
        host_values = sorted({str(item).strip() for item in host_headers if str(item).strip()})
        bound = None if max_hosts is None else int(max_hosts)
        if klass in {"cidr", "ip_range"} and (bound is None or bound < 1):
            raise TargetClassError("CIDR/ip_range targets require an explicit positive max_hosts cap")
        if klass not in {"cidr", "ip_range"} and bound is not None:
            raise TargetClassError("max_hosts applies only to CIDR/ip_range targets")
        self.guard.authorize_scan(target=normalized, consent_id=consent)
        now = time.time()
        with self.database._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO v3_targets(
                    scan_id, class, value, ports, sni, host_header,
                    consent_token_id, justification, max_hosts, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(scan_id),
                    klass,
                    _enc(self.database, normalized, field="v3_target.value"),
                    _enc(self.database, declared_ports, field="v3_target.ports"),
                    _enc(self.database, sni_values, field="v3_target.sni"),
                    _enc(self.database, host_values, field="v3_target.host_header"),
                    _enc(self.database, consent, field="v3_target.consent_token_id"),
                    _enc(self.database, reason, field="v3_target.justification"),
                    bound,
                    now,
                ),
            )
            declaration_id = int(cursor.lastrowid)
        self.audit.append(
            "v3.target.declared",
            {
                "declaration_id": declaration_id,
                "scan_id": int(scan_id),
                "class": klass,
                "value_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
                "ports": declared_ports,
                "max_hosts": bound,
                "consent_token_id": consent,
                "justification": reason,
            },
        )
        return declaration_id

    def _decode_row(self, row: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["target_class"] = str(item.pop("class"))
        for column in ("value", "ports", "sni", "host_header", "consent_token_id", "justification"):
            item[column] = _dec(self.database, str(item[column]), field=f"v3_target.{column}")
        item["host_headers"] = list(item.pop("host_header"))
        item["ports"] = [int(value) for value in item["ports"]]
        item["sni"] = [str(value) for value in item["sni"]]
        return item

    def get(self, declaration_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM v3_targets WHERE id = ?", (int(declaration_id),)).fetchone()
        if row is None:
            raise KeyError(f"v3 target declaration not found: {declaration_id}")
        return self._decode_row(dict(row))

    def list(self, scan_id: int) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            rows = conn.execute("SELECT * FROM v3_targets WHERE scan_id = ? ORDER BY id ASC", (int(scan_id),)).fetchall()
        return [self._decode_row(dict(row)) for row in rows]

    def root_target_id(self, scan_id: int) -> int:
        with self.database._connect() as conn:
            row = conn.execute("SELECT target_id FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
        if row is None:
            raise TargetClassError(f"scan not found: {scan_id}")
        return int(row["target_id"])

    def authorize_route(
        self,
        declaration_id: int,
        *,
        port: int,
        sni: str | None,
        host_header: str | None,
    ) -> dict[str, Any]:
        declaration = self.get(declaration_id)
        if int(port) not in declaration["ports"]:
            self._route_denial(declaration, "port", str(port))
            raise TargetClassError(f"port {port} was not declared for target")
        normalized_sni = (sni or "").strip().casefold()
        if normalized_sni not in declaration["sni"] and normalized_sni != "":
            self._route_denial(declaration, "SNI", normalized_sni)
            raise TargetClassError(f"SNI {sni!r} was not declared for target")
        normalized_host = (host_header or "").strip()
        if normalized_host not in declaration["host_headers"] and normalized_host != "":
            self._route_denial(declaration, "Host", normalized_host)
            raise TargetClassError(f"Host {host_header!r} was not declared for target")
        self.guard.authorize_scan(
            target=str(declaration["value"]),
            consent_id=str(declaration["consent_token_id"]),
        )
        return declaration

    def _route_denial(self, declaration: Mapping[str, Any], field: str, value: str) -> None:
        self.audit.append(
            "v3.target.route_denied",
            {
                "declaration_id": int(declaration["id"]),
                "scan_id": int(declaration["scan_id"]),
                "field": field,
                "value": value,
                "reason": "undeclared",
            },
        )

    def record_ptr(self, declaration_id: int, *, ptr_name: str):
        if self.artifacts is None:
            raise TargetClassError("PTR evidence requires the encrypted artifact store")
        declaration = self.get(declaration_id)
        payload = _canonical(
            {
                "schema": "windeep.recon.ptr.v1",
                "declaration_id": int(declaration_id),
                "target": declaration["value"],
                "ptr": ptr_name.strip().casefold(),
                "expands_scope": False,
            }
        )
        return self.artifacts.put(
            scan_id=int(declaration["scan_id"]),
            tool_run_id=None,
            kind="recon.ptr",
            media_type="application/json",
            content=payload,
            reason=f"record PTR observation for target declaration {declaration_id}",
        )


class CIDRPlanner:
    """Deterministically expand a declared range under explicit host/rate caps."""

    def __init__(self, store: TargetDeclarationStore, guard: Any, audit: Any) -> None:
        self.store = store
        self.guard = guard
        self.audit = audit

    @staticmethod
    def _candidates(declaration: Mapping[str, Any]) -> list[str]:
        klass = declaration["target_class"]
        if klass == "cidr":
            network = ipaddress.ip_network(str(declaration["value"]), strict=False)
            count = max(0, int(network.num_addresses) - (2 if network.version == 4 and network.prefixlen <= 30 else 0))
            if count > _MAX_AUDITABLE_RANGE_HOSTS:
                raise TargetClassError(
                    f"CIDR has {count} usable hosts; split it so each declaration has <= {_MAX_AUDITABLE_RANGE_HOSTS} auditable hosts"
                )
            return [str(value) for value in network.hosts()]
        if klass == "ip_range":
            start, end = _ip_range(str(declaration["value"]))
            count = int(end) - int(start) + 1
            if count > _MAX_AUDITABLE_RANGE_HOSTS:
                raise TargetClassError(
                    f"IP range has {count} hosts; split it so each declaration has <= {_MAX_AUDITABLE_RANGE_HOSTS} auditable hosts"
                )
            return [str(ipaddress.ip_address(value)) for value in range(int(start), int(end) + 1)]
        raise TargetClassError("CIDR planner requires a cidr or ip_range declaration")

    async def expand_and_authorize(self, declaration_id: int, *, seed: str) -> dict[str, Any]:
        declaration = self.store.get(declaration_id)
        candidates = self._candidates(declaration)
        max_hosts = int(declaration["max_hosts"])
        ordered = sorted(
            candidates,
            key=lambda value: hashlib.sha256(f"{seed}\x00{value}".encode("utf-8")).digest(),
        )
        selected, skipped = ordered[:max_hosts], ordered[max_hosts:]
        self.guard.authorize_scan(
            target=str(declaration["value"]),
            consent_id=str(declaration["consent_token_id"]),
        )
        await self.guard.acquire_rate(f"{declaration['target_class']}:{declaration['value']}")
        for value in selected:
            await self.guard.acquire_rate(f"ip:{value}")
            self.audit.append(
                "v3.target.cidr_host",
                {"declaration_id": declaration_id, "host": value, "status": "attempted", "reason": "selected_under_cap"},
            )
        for value in skipped:
            self.audit.append(
                "v3.target.cidr_host",
                {"declaration_id": declaration_id, "host": value, "status": "skipped", "reason": "max_hosts_cap"},
            )
        return {"selected": selected, "skipped": skipped, "max_hosts": max_hosts}


Connector = Callable[..., Awaitable[Mapping[str, Any]]]


class IPLiteralHTTPSProbe:
    """Capture non-destructive HTTPS-by-IP observations after declaration guardrails."""

    def __init__(self, *, store: TargetDeclarationStore, forensic: Any, guard: Any, audit: Any, connector: Connector) -> None:
        self.store = store
        self.forensic = forensic
        self.guard = guard
        self.audit = audit
        self.connector = connector

    @staticmethod
    def _ip_and_path(value: str) -> tuple[str, str, str]:
        parts = urlsplit(value)
        if parts.scheme and parts.hostname:
            ip = str(_parse_ip(parts.hostname))
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            return ip, parts.scheme, path
        return str(_parse_ip(value)), "https", "/"

    async def probe_once(
        self,
        declaration_id: int,
        *,
        port: int,
        sni: str | None,
        host_header: str | None,
        verification_attempt: str,
    ) -> int:
        declaration = self.store.authorize_route(
            declaration_id,
            port=int(port),
            sni=sni,
            host_header=host_header,
        )
        ip, scheme, path = self._ip_and_path(str(declaration["value"]))
        if scheme != "https":
            raise TargetClassError("IP-literal TLS probe requires an https target")
        await self.guard.acquire_rate(f"ip:{ip}")
        await self.guard.acquire_rate(f"host:{host_header or ip}")
        result = await self.connector(
            ip=ip,
            port=int(port),
            sni=sni,
            host_header=host_header,
            path=path,
            url=str(declaration["value"]),
            verification_attempt=verification_attempt,
        )
        if self.forensic is None:
            raise TargetClassError("IP HTTPS evidence capture requires the forensic store")
        response_headers = result.get("response_headers") or {}
        response_body = bytes(result.get("response_body") or b"")
        tls = dict(result.get("tls") or {})
        tls.update(
            {
                "peer_ip": str(result.get("peer_ip") or ip),
                "server_ip": str(result.get("server_ip") or ip),
                "sni_sent": sni or "",
                "host_sent": host_header or "",
                "target_class": str(declaration["target_class"]),
                "target_declaration_id": int(declaration_id),
                "verification_attempt": verification_attempt,
                "verification_outcome": str(tls.get("verification_outcome") or "unknown"),
            }
        )
        authority = host_header or (f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}")
        raw_request = (
            f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        ).encode("utf-8")
        raw_response = bytes(result.get("raw_response") or b"")
        if not raw_response:
            raw_response = (
                f"HTTP/1.1 {int(result.get('status') or 0)}\r\n"
                + "".join(f"{key}: {value}\r\n" for key, value in response_headers.items())
                + "\r\n"
            ).encode("utf-8") + response_body
        flow_id = self.forensic.capture(
            target_id=self.store.root_target_id(int(declaration["scan_id"])),
            scan_id=int(declaration["scan_id"]),
            tool_run_id=None,
            task_id=f"v3-target:{declaration_id}",
            method="GET",
            url=str(declaration["value"]),
            request_headers={"Host": authority, "Connection": "close"},
            request_body=b"",
            status=int(result.get("status") or 0),
            response_headers=response_headers,
            response_body=response_body,
            raw_request=raw_request,
            raw_response=raw_response,
            timings=dict(result.get("timings") or {}),
            tls=tls,
            server_ip=str(result.get("server_ip") or ip),
            created_at=float(result.get("created_at") or time.time()),
        )
        self.audit.append(
            "v3.target.ip_https_observed",
            {
                "declaration_id": declaration_id,
                "flow_id": flow_id,
                "ip": ip,
                "port": int(port),
                "sni": sni or "",
                "host": host_header or "",
                "verification_attempt": verification_attempt,
                "verification_outcome": tls["verification_outcome"],
            },
        )
        return flow_id

    async def probe_ip_url(self, declaration_id: int) -> list[int]:
        declaration = self.store.get(declaration_id)
        if declaration["target_class"] != "ip_url":
            raise TargetClassError("probe_ip_url requires an ip_url declaration")
        parts = urlsplit(str(declaration["value"]))
        port = int(parts.port or 443)
        if port not in declaration["ports"]:
            raise TargetClassError("ip_url authority port must be explicitly declared")
        host = declaration["host_headers"][0] if declaration["host_headers"] else (parts.netloc or parts.hostname or "")
        sni = declaration["sni"][0] if declaration["sni"] else None
        first = await self.probe_once(
            declaration_id,
            port=port,
            sni=sni,
            host_header=host,
            verification_attempt="ip-san",
        )
        second = await self.probe_once(
            declaration_id,
            port=port,
            sni=None,
            host_header=host,
            verification_attempt="sni-less-name-check",
        )
        return [first, second]

    def export_har(self, *, scan_id: int, redactor: EvidenceRedactor) -> bytes:
        base = json.loads(self.forensic.export_har(scan_id=scan_id, redactor=redactor))
        for entry in base.get("log", {}).get("entries", []):
            block = entry.get("_windeep") or {}
            flow_id = block.get("flow_id")
            if flow_id is None:
                continue
            flow = self.forensic.get(int(flow_id))
            tls = dict(flow.get("tls") or {})
            block.update(
                {
                    "target_class": tls.get("target_class"),
                    "target_declaration_id": tls.get("target_declaration_id"),
                    "peer_ip": tls.get("peer_ip"),
                    "server_ip": tls.get("server_ip") or flow.get("server_ip"),
                    "sni_sent": tls.get("sni_sent", ""),
                    "host_sent": tls.get("host_sent", ""),
                    "tls_version": tls.get("tls_version", ""),
                    "cipher": tls.get("cipher", ""),
                    "cert_fingerprint_sha256": tls.get("cert_fingerprint_sha256", ""),
                    "verification_attempt": tls.get("verification_attempt", ""),
                    "verification_outcome": tls.get("verification_outcome", ""),
                    "pinned_ip": tls.get("server_ip") or flow.get("server_ip"),
                }
            )
            entry["_windeep"] = block
        encoded = _canonical(base) + b"\n"
        ref = self.forensic.artifacts.put(
            scan_id=int(scan_id),
            tool_run_id=None,
            kind="export.har.redacted.v3-target",
            media_type="application/json",
            content=encoded,
            reason="persist v3 target metadata HAR view",
            metadata={"har_extension": "windeep.har-extension.v1", "additive_v3_target_fields": True},
        )
        self.forensic.artifacts.export(ref.sha256, scan_id=int(scan_id), reason="v3 target HAR export")
        return encoded


def build_ip_pinned_replay(flow: Mapping[str, Any]) -> dict[str, Any]:
    """Return replay metadata that keeps literal-IP flows pinned to the observed IP."""
    parts = urlsplit(str(flow.get("url") or ""))
    if not parts.hostname:
        raise TargetClassError("captured flow URL has no authority")
    pinned = str(_parse_ip(parts.hostname))
    tls = dict(flow.get("tls") or flow.get("tls_info") or {})
    server_ip = str(tls.get("server_ip") or flow.get("server_ip") or pinned)
    if server_ip != pinned:
        raise TargetClassError("IP replay evidence does not match the literal target IP")
    return {
        "flow_id": int(flow["id"]),
        "flow_sha256": str(flow.get("flow_sha256") or ""),
        "url": str(flow["url"]),
        "pinned_ip": pinned,
        "port": parts.port or (443 if parts.scheme == "https" else 80),
        "sni": str(tls.get("sni_sent") or ""),
        "host_header": str(tls.get("host_sent") or ""),
        "verification_attempt": str(tls.get("verification_attempt") or ""),
        "verification_outcome": str(tls.get("verification_outcome") or ""),
    }
