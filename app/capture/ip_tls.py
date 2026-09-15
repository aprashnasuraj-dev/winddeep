"""Capture-layer HTTPS connector for declared literal-IP v3 targets.

The connector is intentionally narrow: one observation-only GET request, bounded
response size/time, literal-IP socket destination, and a second live preflight at
the transport boundary. It never resolves DNS or invents SNI/Host values.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import ssl
import time
from collections.abc import Mapping
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_CONNECT_TIMEOUT = 15.0
_READ_TIMEOUT = 20.0


class CaptureTLSFailure(RuntimeError):
    """Raised when a declared literal-IP TLS observation cannot be captured."""


def _ip_sans(der_certificate: bytes) -> set[str]:
    if not der_certificate:
        return set()
    try:
        cert = x509.load_der_x509_certificate(der_certificate)
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return {str(value) for value in extension.value.get_values_for_type(x509.IPAddress)}
    except (ValueError, x509.ExtensionNotFound):
        return set()


def _chain(ssl_object: Any) -> list[str]:
    """Return best-available DER chain as base64, always including the leaf."""
    leaf = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
    encoded: list[str] = []
    internal = getattr(ssl_object, "_sslobj", None)
    getter = getattr(internal, "get_unverified_chain", None)
    if callable(getter):
        try:
            for item in getter() or []:
                raw: bytes | None = None
                if isinstance(item, bytes):
                    raw = item
                else:
                    public_bytes = getattr(item, "public_bytes", None)
                    if callable(public_bytes):
                        try:
                            value = public_bytes()
                            raw = value if isinstance(value, bytes) else ssl.PEM_cert_to_DER_cert(str(value))
                        except Exception:
                            raw = None
                if raw:
                    value = base64.b64encode(raw).decode("ascii")
                    if value not in encoded:
                        encoded.append(value)
        except Exception:
            encoded = []
    if leaf:
        leaf_value = base64.b64encode(leaf).decode("ascii")
        if leaf_value not in encoded:
            encoded.insert(0, leaf_value)
    return encoded


def _parse_response(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    head, marker, body = raw.partition(b"\r\n\r\n")
    if not marker:
        head, marker, body = raw.partition(b"\n\n")
    lines = head.replace(b"\r\n", b"\n").split(b"\n") if head else []
    status = 0
    if lines:
        parts = lines[0].decode("latin-1", errors="replace").split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        name = key.decode("latin-1", errors="replace")
        text = value.lstrip().decode("latin-1", errors="replace")
        headers[name] = text if name not in headers else headers[name] + "\n" + text
    return status, headers, body


class CaptureTLSConnector:
    """Perform one preflight-gated literal-IP HTTPS observation."""

    def __init__(
        self,
        guard: Any,
        *,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        connect_timeout: float = _CONNECT_TIMEOUT,
        read_timeout: float = _READ_TIMEOUT,
    ) -> None:
        if max_response_bytes < 1024:
            raise ValueError("max_response_bytes must be at least 1024")
        if connect_timeout <= 0 or read_timeout <= 0:
            raise ValueError("TLS connector timeouts must be positive")
        self.guard = guard
        self.max_response_bytes = int(max_response_bytes)
        self.connect_timeout = float(connect_timeout)
        self.read_timeout = float(read_timeout)

    @staticmethod
    def _context(*, verified: bool) -> ssl.SSLContext:
        if verified:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            return context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    async def _open(
        self,
        *,
        ip: str,
        port: int,
        context: ssl.SSLContext,
        server_hostname: str | None,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(
                host=ip,
                port=int(port),
                ssl=context,
                server_hostname=server_hostname,
            ),
            timeout=self.connect_timeout,
        )

    async def __call__(
        self,
        *,
        ip: str,
        port: int,
        sni: str | None,
        host_header: str | None,
        path: str,
        url: str,
        verification_attempt: str,
        declared_target: str,
        consent_id: str,
    ) -> Mapping[str, Any]:
        address = ipaddress.ip_address(ip)
        if address.zone_id if isinstance(address, ipaddress.IPv6Address) else False:
            raise CaptureTLSFailure("IPv6 zone ids are forbidden")
        self.guard.authorize_scan(target=declared_target, consent_id=consent_id)
        await self.guard.acquire_rate(f"transport:{address}")
        started = time.monotonic()
        verification_error: str | None = None
        writer: asyncio.StreamWriter | None = None
        reader: asyncio.StreamReader | None = None
        connect_started = time.monotonic()
        try:
            if verification_attempt == "ip-san":
                try:
                    reader, writer = await self._open(
                        ip=str(address),
                        port=port,
                        context=self._context(verified=True),
                        server_hostname=str(address),
                    )
                except ssl.SSLCertVerificationError as exc:
                    verification_error = str(exc)
                    reader, writer = await self._open(
                        ip=str(address),
                        port=port,
                        context=self._context(verified=False),
                        server_hostname=None,
                    )
            elif verification_attempt == "sni-less-name-check":
                reader, writer = await self._open(
                    ip=str(address),
                    port=port,
                    context=self._context(verified=False),
                    server_hostname=None,
                )
            else:
                raise CaptureTLSFailure(f"unsupported TLS verification attempt: {verification_attempt}")
            connect_ms = (time.monotonic() - connect_started) * 1000.0
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise CaptureTLSFailure("TLS socket has no SSL object")
            leaf = ssl_object.getpeercert(binary_form=True) or b""
            ip_sans = _ip_sans(leaf)
            if verification_attempt == "ip-san":
                outcome = "verified_ip_san" if verification_error is None else "ip_san_verification_failed"
            else:
                outcome = "sni_less_ip_san_present" if str(address) in ip_sans else "name_mismatch_observed"
            authority = host_header or (f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}")
            request = (
                f"GET {path or '/'} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: Windeep/3.0\r\n\r\n"
            ).encode("ascii", errors="strict")
            writer.write(request)
            await writer.drain()
            first_byte_started = time.monotonic()
            raw = await asyncio.wait_for(reader.read(self.max_response_bytes + 1), timeout=self.read_timeout)
            if len(raw) > self.max_response_bytes:
                raise CaptureTLSFailure("TLS response exceeded configured evidence byte cap")
            total_ms = (time.monotonic() - started) * 1000.0
            ttfb_ms = (time.monotonic() - first_byte_started) * 1000.0
            status, headers, body = _parse_response(raw)
            cipher = ssl_object.cipher() or ("", "", 0)
            chain = _chain(ssl_object)
            peer = writer.get_extra_info("peername")
            peer_ip = str(peer[0]) if isinstance(peer, tuple) and peer else str(address)
            return {
                "status": status,
                "response_headers": headers,
                "response_body": body,
                "raw_response": raw,
                "timings": {"connect": connect_ms, "tls": connect_ms, "ttfb": ttfb_ms, "total": total_ms},
                "peer_ip": peer_ip,
                "server_ip": peer_ip,
                "created_at": time.time(),
                "tls": {
                    "tls_version": ssl_object.version() or "",
                    "cipher": str(cipher[0]),
                    "cert_fingerprint_sha256": hashlib.sha256(leaf).hexdigest() if leaf else "",
                    "cert_chain": chain,
                    "cert_chain_complete": len(chain) > 1,
                    "ip_sans": sorted(ip_sans),
                    "verification_attempt": verification_attempt,
                    "verification_outcome": outcome,
                    "verification_error": verification_error or "",
                    "sni_sent": sni or "",
                },
            }
        except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
            raise CaptureTLSFailure(f"literal-IP TLS observation failed: {type(exc).__name__}: {exc}") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


__all__ = ["CaptureTLSConnector", "CaptureTLSFailure"]
