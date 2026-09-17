"""Pure-Python fallback adapters for API-shaped and retired CLI integrations.

These adapters are deliberately observation-oriented. They preserve historical
tool names while avoiding a hard dependency on archived Python 2 projects or
small CLIs whose behavior can be reproduced through documented public APIs.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, urlparse

import httpx


_FALLBACKS = {
    "wayback_cdx",
    "rdap",
    "dns_query",
    "http_probe",
    "crtsh",
    "github_subdomains",
    "js_analysis",
    "repo_secret_scan",
}

_REQUIRED_ENV = {
    "github_subdomains": ("GITHUB_TOKEN",),
}

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{20,255}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})")),
)
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_ENDPOINT_PATTERN = re.compile(r"[\"'](/(?:api|graphql|v\d+|admin|auth|oauth|internal)/[^\"']*)[\"']", re.IGNORECASE)
_HOST_PATTERN = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


def supports(name: str) -> bool:
    return name in _FALLBACKS


def required_env(name: str) -> tuple[str, ...]:
    return _REQUIRED_ENV.get(name, ())


def _finding(requested: str, target: str, title: str, *, evidence: Mapping[str, Any], endpoint: str | None = None, confidence: float = 0.75) -> dict[str, Any]:
    return {
        "title": title,
        "severity": "info",
        "vuln_type": "builtin_fallback",
        "tool": requested,
        "endpoint": endpoint or target,
        "description": "Windeep v4 builtin fallback observation.",
        "evidence": {"builtin_fallback": True, **dict(evidence)},
        "confidence": confidence,
    }


def _target_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or target.split("/")[0]).strip("[]")


async def _wayback_cdx(target: str, requested: str) -> list[dict[str, Any]]:
    host = _target_host(target)
    params = {
        "url": f"{host}/*",
        "output": "json",
        "fl": "original,statuscode,timestamp",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": "500",
    }
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        response = await client.get("https://web.archive.org/cdx/search/cdx", params=params, headers={"User-Agent": "Windeep/4"})
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, list) or len(payload) < 2:
        return []
    headers = [str(value) for value in payload[0]]
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in payload[1:]:
        if not isinstance(raw, list):
            continue
        item = dict(zip(headers, raw))
        url = str(item.get("original") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        rows.append(_finding(requested, target, url, endpoint=url, evidence={"adapter": "wayback_cdx", "url": url, "timestamp": item.get("timestamp"), "statuscode": item.get("statuscode")}))
        if len(rows) >= 500:
            break
    return rows


async def _rdap(target: str, requested: str) -> list[dict[str, Any]]:
    host = _target_host(target)
    try:
        ipaddress.ip_address(host)
        url = f"https://rdap.org/ip/{quote(host)}"
    except ValueError:
        url = f"https://rdap.org/domain/{quote(host)}"
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        response = await client.get(url, headers={"User-Agent": "Windeep/4"})
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict):
        return []
    evidence = {
        "adapter": "rdap",
        "handle": payload.get("handle"),
        "ldhName": payload.get("ldhName"),
        "name": payload.get("name"),
        "status": payload.get("status"),
        "events": payload.get("events", [])[:20] if isinstance(payload.get("events"), list) else [],
        "nameservers": payload.get("nameservers", [])[:50] if isinstance(payload.get("nameservers"), list) else [],
    }
    return [_finding(requested, target, f"RDAP record for {host}", endpoint=host, evidence=evidence, confidence=0.9)]


async def _dns_query(target: str, requested: str) -> list[dict[str, Any]]:
    host = _target_host(target)
    rows: list[dict[str, Any]] = []
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        try:
            infos = await __import__("asyncio").get_running_loop().run_in_executor(None, socket.getaddrinfo, host, None)
        except socket.gaierror:
            return []
        seen = sorted({str(item[4][0]) for item in infos})
        return [_finding(requested, target, f"DNS address {value}", endpoint=host, evidence={"adapter": "socket_dns", "type": "A/AAAA", "value": value}) for value in seen]

    resolver = dns.resolver.Resolver(configure=True)
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        try:
            answer = await __import__("asyncio").get_running_loop().run_in_executor(None, lambda rt=record_type: resolver.resolve(host, rt, lifetime=5.0))
        except Exception:
            continue
        for value in answer:
            text = str(value).strip()
            rows.append(_finding(requested, target, f"{record_type} {text}", endpoint=host, evidence={"adapter": "dnspython", "type": record_type, "value": text}, confidence=0.9))
    return rows


async def _http_probe(target: str, requested: str) -> list[dict[str, Any]]:
    raw = target.strip()
    urls = [raw] if raw.startswith(("http://", "https://")) else [f"https://{raw}", f"http://{raw}"]
    rows: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=True) as client:
        for url in urls:
            try:
                response = await client.get(url, headers={"User-Agent": "Windeep/4"})
            except httpx.HTTPError:
                continue
            rows.append(_finding(requested, target, f"HTTP {response.status_code} {response.url}", endpoint=str(response.url), evidence={"adapter": "http_probe", "status": response.status_code, "final_url": str(response.url), "server": response.headers.get("server")}, confidence=0.95))
    return rows


async def _crtsh(target: str, requested: str) -> list[dict[str, Any]]:
    host = _target_host(target)
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        response = await client.get("https://crt.sh/", params={"q": f"%.{host}", "output": "json"}, headers={"User-Agent": "Windeep/4"})
        response.raise_for_status()
        payload = response.json()
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        for name in str(item.get("name_value") or "").splitlines():
            normalized = name.strip().lower().lstrip("*.")
            if normalized and normalized not in seen:
                seen.add(normalized)
                rows.append(_finding(requested, target, normalized, endpoint=normalized, evidence={"adapter": "crtsh", "hostname": normalized}, confidence=0.9))
    return rows[:500]


async def _github_subdomains(target: str, requested: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    token = str(environment.get("GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN") or "").strip()
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required for github_subdomains builtin fallback")
    host = _target_host(target)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": "Windeep/4"}
    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        response = await client.get("https://api.github.com/search/code", params={"q": f'".{host}"', "per_page": 100})
        response.raise_for_status()
        payload = response.json()
    rows: list[dict[str, Any]] = []
    for item in payload.get("items", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
        rows.append(_finding(requested, target, f"GitHub code reference: {repo.get('full_name') or item.get('name')}", endpoint=str(item.get("html_url") or target), evidence={"adapter": "github_code_search", "repository": repo.get("full_name"), "path": item.get("path"), "url": item.get("html_url")}, confidence=0.65))
    return rows[:100]


async def _read_js_sources(target: str) -> list[tuple[str, str]]:
    path = Path(target).expanduser()
    if path.exists():
        files = [path] if path.is_file() else [item for item in path.rglob("*.js") if item.is_file()][:500]
        output: list[tuple[str, str]] = []
        for item in files:
            try:
                if item.stat().st_size <= 4 * 1024 * 1024:
                    output.append((str(item), item.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
        return output
    if target.startswith(("http://", "https://")):
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(target, headers={"User-Agent": "Windeep/4"})
            response.raise_for_status()
            return [(str(response.url), response.text[:4 * 1024 * 1024])]
    return []


async def _js_analysis(target: str, requested: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source, text in await _read_js_sources(target):
        for match in _URL_PATTERN.finditer(text):
            value = match.group(0).rstrip("),.;")
            key = ("url", value)
            if key not in seen:
                seen.add(key)
                rows.append(_finding(requested, target, f"JS URL {value}", endpoint=value, evidence={"adapter": "js_analysis", "source": source, "kind": "url", "value": value}, confidence=0.75))
        for match in _ENDPOINT_PATTERN.finditer(text):
            value = match.group(1)
            key = ("endpoint", value)
            if key not in seen:
                seen.add(key)
                rows.append(_finding(requested, target, f"JS endpoint {value}", endpoint=value, evidence={"adapter": "js_analysis", "source": source, "kind": "endpoint", "value": value}, confidence=0.7))
        for label, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(1) if match.lastindex else match.group(0)
                redacted = raw[:4] + "…" + raw[-4:] if len(raw) > 10 else "*" * len(raw)
                key = (label, f"{source}:{match.start()}")
                if key not in seen:
                    seen.add(key)
                    rows.append(_finding(requested, target, f"Potential {label} in JavaScript", endpoint=source, evidence={"adapter": "js_analysis", "source": source, "kind": label, "value": redacted, "offset": match.start()}, confidence=0.65))
        if len(rows) >= 500:
            break
    return rows[:500]


async def _repo_secret_scan(target: str, requested: str) -> list[dict[str, Any]]:
    path = Path(target).expanduser()
    temp: tempfile.TemporaryDirectory[str] | None = None
    try:
        if not path.exists() and target.startswith(("https://", "ssh://", "git@")):
            git = shutil_which("git")
            if not git:
                return []
            temp = tempfile.TemporaryDirectory(prefix="windeep-repo-")
            completed = subprocess.run([git, "clone", "--depth", "1", "--", target, temp.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90, check=False)
            if completed.returncode != 0:
                return []
            path = Path(temp.name)
        if not path.exists():
            return []
        files = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file() and ".git" not in item.parts][:1000]
        rows: list[dict[str, Any]] = []
        for item in files:
            try:
                if item.stat().st_size > 2 * 1024 * 1024:
                    continue
                raw = item.read_bytes()
                if b"\x00" in raw[:4096]:
                    continue
                text = raw.decode("utf-8", errors="replace")
            except OSError:
                continue
            for label, pattern in _SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    value = match.group(1) if match.lastindex else match.group(0)
                    redacted = value[:4] + "…" + value[-4:] if len(value) > 10 else "*" * len(value)
                    rows.append(_finding(requested, target, f"Potential {label} in {item.name}", endpoint=str(item), evidence={"adapter": "repo_secret_scan", "source": str(item), "pattern": label, "value": redacted, "offset": match.start()}, confidence=0.65))
                    if len(rows) >= 500:
                        return rows
        return rows
    finally:
        if temp is not None:
            temp.cleanup()


def shutil_which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


async def run_adapter(name: str, target: str, *, environment: Mapping[str, str] | None = None, requested_name: str | None = None) -> list[dict[str, Any]]:
    requested = requested_name or name
    env = {**os.environ, **dict(environment or {})}
    if name == "wayback_cdx":
        return await _wayback_cdx(target, requested)
    if name == "rdap":
        return await _rdap(target, requested)
    if name == "dns_query":
        return await _dns_query(target, requested)
    if name == "http_probe":
        return await _http_probe(target, requested)
    if name == "crtsh":
        return await _crtsh(target, requested)
    if name == "github_subdomains":
        return await _github_subdomains(target, requested, env)
    if name == "js_analysis":
        return await _js_analysis(target, requested)
    if name == "repo_secret_scan":
        return await _repo_secret_scan(target, requested)
    raise KeyError(f"unknown builtin fallback adapter: {name}")
