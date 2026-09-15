"""Transport-level coverage for V3-A literal-IP TLS capture."""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import ipaddress
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.capture.ip_tls import CaptureTLSConnector, CaptureTLSFailure, _chain, _ip_sans, _parse_response


class Guard:
    def __init__(self):
        self.authorized: list[tuple[str, str]] = []
        self.rate: list[str] = []

    def authorize_scan(self, *, target: str, consent_id: str):
        self.authorized.append((target, consent_id))

    async def acquire_rate(self, key: str, *, cost: float = 1.0):
        self.rate.append(key)


def _cert(ip: str = "198.51.100.7") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class SSLObject:
    def __init__(self, leaf: bytes, *, chain=None):
        self.leaf = leaf
        self._sslobj = type("Internal", (), {"get_unverified_chain": lambda _self: list(chain or [leaf])})()

    def getpeercert(self, binary_form=False):
        return self.leaf if binary_form else {}

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def version(self):
        return "TLSv1.3"


class Reader:
    def __init__(self, raw: bytes):
        self.raw = raw

    async def read(self, _size: int):
        return self.raw


class Writer:
    def __init__(self, ssl_object, *, peer=("198.51.100.7", 8443), wait_error=False):
        self.ssl_object = ssl_object
        self.peer = peer
        self.wait_error = wait_error
        self.writes: list[bytes] = []
        self.closed = False

    def get_extra_info(self, name: str):
        if name == "ssl_object":
            return self.ssl_object
        if name == "peername":
            return self.peer
        return None

    def write(self, value: bytes):
        self.writes.append(value)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        if self.wait_error:
            raise RuntimeError("fixture close")


class Connector(CaptureTLSConnector):
    def __init__(self, guard, results, **kwargs):
        super().__init__(guard, **kwargs)
        self.results = list(results)
        self.opens: list[tuple[str, int, str | None, bool]] = []

    async def _open(self, *, ip, port, context, server_hostname):
        self.opens.append((ip, port, server_hostname, bool(context.check_hostname)))
        value = self.results.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def _call(connector, **overrides):
    values = {
        "ip": "198.51.100.7",
        "port": 8443,
        "sni": None,
        "host_header": "198.51.100.7:8443",
        "path": "/health",
        "url": "https://198.51.100.7:8443/health",
        "verification_attempt": "ip-san",
        "declared_target": "https://198.51.100.7:8443/health",
        "consent_id": "consent-ip-url",
    }
    values.update(overrides)
    return asyncio.run(connector(**values))


def test_certificate_helpers_and_http_parser_cover_valid_and_invalid_inputs() -> None:
    der = _cert()
    assert _ip_sans(der) == {"198.51.100.7"}
    assert _ip_sans(b"") == set()
    assert _ip_sans(b"not-a-cert") == set()
    ssl_object = SSLObject(der, chain=[der, b"issuer"])
    chain = _chain(ssl_object)
    assert chain[0] == base64.b64encode(der).decode("ascii")
    assert len(chain) == 2
    assert _chain(None) == []
    status, headers, body = _parse_response(b"HTTP/1.1 200 OK\r\nX-A: one\r\nX-A: two\r\n\r\nok")
    assert status == 200
    assert headers["X-A"] == "one\ntwo"
    assert body == b"ok"
    assert _parse_response(b"garbage\nHeader: v\n\nbody")[0] == 0


def test_connector_success_rechecks_preflight_rate_and_captures_cert_metadata() -> None:
    guard = Guard()
    der = _cert()
    writer = Writer(SSLObject(der))
    connector = Connector(guard, [(Reader(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"), writer)])
    result = _call(connector)
    assert result["status"] == 200
    assert result["response_body"] == b"ok"
    assert result["tls"]["verification_outcome"] == "verified_ip_san"
    assert result["tls"]["cert_fingerprint_sha256"]
    assert result["tls"]["ip_sans"] == ["198.51.100.7"]
    assert result["peer_ip"] == "198.51.100.7"
    assert guard.authorized == [("https://198.51.100.7:8443/health", "consent-ip-url")]
    assert guard.rate == ["transport:198.51.100.7"]
    assert b"Host: 198.51.100.7:8443" in writer.writes[0]
    assert writer.closed is True


def test_connector_cert_verification_failure_is_recorded_then_observed_read_only() -> None:
    guard = Guard()
    der = _cert()
    writer = Writer(SSLObject(der), wait_error=True)
    error = ssl.SSLCertVerificationError(1, "fixture mismatch")
    connector = Connector(
        guard,
        [error, (Reader(b"HTTP/1.1 204 No Content\r\n\r\n"), writer)],
    )
    result = _call(connector)
    assert result["status"] == 204
    assert result["tls"]["verification_outcome"] == "ip_san_verification_failed"
    assert "fixture mismatch" in result["tls"]["verification_error"]
    assert len(connector.opens) == 2
    assert connector.opens[0][2] == "198.51.100.7"
    assert connector.opens[1][2] is None


def test_connector_sni_less_ipv6_and_failure_branches() -> None:
    guard = Guard()
    writer = Writer(SSLObject(b"bad"), peer=("2001:db8::7", 9443))
    connector = Connector(guard, [(Reader(b"HTTP/1.1 200 OK\n\nbody"), writer)])
    result = _call(
        connector,
        ip="2001:db8::7",
        port=9443,
        host_header="[2001:db8::7]:9443",
        url="https://[2001:db8::7]:9443/",
        declared_target="https://[2001:db8::7]:9443/",
        verification_attempt="sni-less-name-check",
        path="/",
    )
    assert result["server_ip"] == "2001:db8::7"
    assert result["tls"]["verification_outcome"] == "name_mismatch_observed"
    assert b"Host: [2001:db8::7]:9443" in writer.writes[0]

    unsupported = Connector(Guard(), [])
    with pytest.raises(CaptureTLSFailure, match="unsupported"):
        _call(unsupported, verification_attempt="other")

    missing_ssl = Writer(None)
    no_ssl = Connector(Guard(), [(Reader(b""), missing_ssl)])
    with pytest.raises(CaptureTLSFailure, match="no SSL object"):
        _call(no_ssl)

    overflow = Writer(SSLObject(_cert()))
    too_big = Connector(Guard(), [(Reader(b"x" * 1025), overflow)], max_response_bytes=1024)
    with pytest.raises(CaptureTLSFailure, match="byte cap"):
        _call(too_big)


def test_connector_validation_open_wrapper_and_os_error(monkeypatch) -> None:
    guard = Guard()
    with pytest.raises(ValueError, match="at least 1024"):
        CaptureTLSConnector(guard, max_response_bytes=1)
    with pytest.raises(ValueError, match="positive"):
        CaptureTLSConnector(guard, connect_timeout=0)

    async def open_connection(**_kwargs):
        return Reader(b""), Writer(SSLObject(b"bad"))

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    connector = CaptureTLSConnector(guard)
    reader, writer = asyncio.run(
        connector._open(ip="198.51.100.7", port=443, context=connector._context(verified=False), server_hostname=None)
    )
    assert isinstance(reader, Reader)
    assert isinstance(writer, Writer)
    assert connector._context(verified=True).verify_mode == ssl.CERT_REQUIRED

    failing = Connector(Guard(), [OSError("network fixture")])
    with pytest.raises(CaptureTLSFailure, match="OSError"):
        _call(failing)
