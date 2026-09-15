"""Built-in adapters for catalog integrations that are not ordinary local CLIs.

The adapters are deliberately narrow and scope-neutral: caller-side Windeep
preflight/scope/consent checks still run before these functions are invoked.
They provide real API/internal execution paths without pretending that every
catalog item is a redistributable Windows executable.
"""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

import httpx


_BUILTIN_REQUIRED_ENV: dict[str, tuple[str, ...]] = {
    "shodan": ("SHODAN_API_KEY",),
    "censys": ("CENSYS_API_ID", "CENSYS_API_SECRET"),
    "etherscan": ("ETHERSCAN_API_KEY",),
    "corellium": ("CORELLIUM_BASE_URL", "CORELLIUM_API_TOKEN"),
    "mobsf": ("MOBSF_URL", "MOBSF_API_KEY"),
}

_BUILTINS = {
    "crtsh",
    "shodan",
    "censys",
    "etherscan",
    "corellium",
    "mobsf",
    "remix",
    "custom_regex",
}

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{20,255}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})")),
)


def supports(name: str) -> bool:
    return name in _BUILTINS


def required_env(name: str) -> tuple[str, ...]:
    return _BUILTIN_REQUIRED_ENV.get(name, ())


def _env(environment: Mapping[str, str], name: str) -> str:
    value = str(environment.get(name) or os.getenv(name) or "").strip()
    if not value:
        raise RuntimeError(f"{name} is required for this integration")
    return value


def _finding(
    tool: str,
    target: str,
    title: str,
    *,
    description: str = "",
    evidence: Mapping[str, Any] | None = None,
    endpoint: str | None = None,
    confidence: float = 0.8,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": "info",
        "vuln_type": "integration_result",
        "tool": tool,
        "endpoint": endpoint or target,
        "description": description,
        "evidence": dict(evidence or {}),
        "confidence": confidence,
    }


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"


async def _crtsh(target: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    del environment
    url = f"https://crt.sh/?q=%25.{quote(target)}&output=json"
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        response = await client.get(url, headers={"User-Agent": "Windeep/0.1"})
        response.raise_for_status()
        payload = response.json()
    names: list[str] = []
    seen: set[str] = set()
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        for name in str(item.get("name_value") or "").splitlines():
            normalized = name.strip().lower().lstrip("*.")
            if normalized and normalized not in seen:
                seen.add(normalized)
                names.append(normalized)
        if len(names) >= 500:
            break
    return [
        _finding("crtsh", target, name, description="Certificate Transparency hostname", evidence={"source": "crt.sh", "hostname": name}, endpoint=name)
        for name in names
    ]


async def _shodan(target: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    key = _env(environment, "SHODAN_API_KEY")
    try:
        ipaddress.ip_address(target)
        url = f"https://api.shodan.io/shodan/host/{quote(target)}"
        params = {"key": key}
    except ValueError:
        url = "https://api.shodan.io/shodan/host/search"
        params = {"key": key, "query": f"hostname:{target}"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        payload = response.json()
    matches = payload.get("matches") if isinstance(payload, dict) else None
    if isinstance(matches, list):
        rows = matches[:100]
    else:
        rows = [payload]
    output: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = str(row.get("ip_str") or target)
        ports = row.get("ports") or ([row.get("port")] if row.get("port") else [])
        output.append(_finding("shodan", target, f"Shodan host {host}", description="Shodan host intelligence", evidence={"ip": host, "ports": ports, "org": row.get("org"), "hostnames": row.get("hostnames")}, endpoint=host))
    return output


async def _censys(target: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    api_id = _env(environment, "CENSYS_API_ID")
    secret = _env(environment, "CENSYS_API_SECRET")
    async with httpx.AsyncClient(timeout=30.0, auth=(api_id, secret)) as client:
        response = await client.get("https://search.censys.io/api/v2/hosts/search", params={"q": target, "per_page": 50})
        response.raise_for_status()
        payload = response.json()
    result = payload.get("result", {}) if isinstance(payload, dict) else {}
    hits = result.get("hits", []) if isinstance(result, dict) else []
    output: list[dict[str, Any]] = []
    for row in hits[:50] if isinstance(hits, list) else []:
        if not isinstance(row, dict):
            continue
        host = str(row.get("ip") or target)
        output.append(_finding("censys", target, f"Censys host {host}", description="Censys host intelligence", evidence={"ip": host, "name": row.get("name"), "services": row.get("services", [])}, endpoint=host))
    return output


async def _etherscan(target: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    key = _env(environment, "ETHERSCAN_API_KEY")
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            "https://api.etherscan.io/api",
            params={"module": "contract", "action": "getsourcecode", "address": target, "apikey": key},
        )
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict) or str(payload.get("status")) not in {"1", "0"}:
        raise RuntimeError("unexpected Etherscan API response")
    result = payload.get("result")
    if not isinstance(result, list):
        raise RuntimeError(str(payload.get("message") or "Etherscan returned no contract result"))
    output: list[dict[str, Any]] = []
    for row in result[:20]:
        if not isinstance(row, dict):
            continue
        name = str(row.get("ContractName") or target)
        output.append(_finding("etherscan", target, f"Etherscan contract {name}", description="Verified-contract metadata from Etherscan", evidence={"contract_name": name, "compiler": row.get("CompilerVersion"), "optimization": row.get("OptimizationUsed"), "proxy": row.get("Proxy"), "implementation": row.get("Implementation")}, endpoint=target))
    return output


async def _corellium(target: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    base = _env(environment, "CORELLIUM_BASE_URL").rstrip("/")
    token = _env(environment, "CORELLIUM_API_TOKEN")
    async with httpx.AsyncClient(timeout=30.0, headers={"Authorization": f"Bearer {token}"}) as client:
        response = await client.get(f"{base}/api/v1/projects")
        response.raise_for_status()
        payload = response.json()
    rows = payload if isinstance(payload, list) else payload.get("projects", []) if isinstance(payload, dict) else []
    output: list[dict[str, Any]] = []
    for row in rows[:100] if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or row.get("id") or "Corellium project")
        output.append(_finding("corellium", target, f"Corellium project {name}", description="Authorized Corellium tenant project", evidence={"id": row.get("id"), "name": row.get("name")}, endpoint=base))
    return output


async def _mobsf(target: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    base = _env(environment, "MOBSF_URL").rstrip("/")
    key = _env(environment, "MOBSF_API_KEY")
    path = Path(target).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"MobSF target must be a local APK/IPA file: {path}")
    headers = {"Authorization": key}
    async with httpx.AsyncClient(timeout=180.0, headers=headers) as client:
        with path.open("rb") as handle:
            upload = await client.post(f"{base}/api/v1/upload", files={"file": (path.name, handle, "application/octet-stream")})
        upload.raise_for_status()
        meta = upload.json()
        if not isinstance(meta, dict) or not meta.get("hash"):
            raise RuntimeError("MobSF upload did not return a scan hash")
        scan = await client.post(
            f"{base}/api/v1/scan",
            data={"hash": meta["hash"], "scan_type": meta.get("scan_type", "apk"), "file_name": meta.get("file_name", path.name)},
        )
        scan.raise_for_status()
        payload = scan.json()
    evidence: dict[str, Any]
    if isinstance(payload, dict):
        evidence = {
            "hash": meta.get("hash"),
            "app_name": payload.get("app_name"),
            "package_name": payload.get("package_name"),
            "security_score": payload.get("security_score"),
            "high": payload.get("high"),
            "warning": payload.get("warning"),
            "info": payload.get("info"),
        }
    else:
        evidence = {"hash": meta.get("hash")}
    return [_finding("mobsf", target, f"MobSF analysis {path.name}", description="MobSF upload and scan completed", evidence=evidence, endpoint=base, confidence=0.9)]


async def _remix(target: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    del environment
    url = "https://remix.ethereum.org/"
    return [_finding("remix", target, "Remix IDE integration ready", description="Open the official Remix IDE and import the authorized contract/source.", evidence={"url": url, "target": target}, endpoint=url, confidence=1.0)]


async def _custom_regex(target: str, environment: Mapping[str, str]) -> list[dict[str, Any]]:
    del environment
    path = Path(target).expanduser()
    candidates: list[Path]
    if path.exists():
        resolved = path.resolve()
        if resolved.is_file():
            candidates = [resolved]
        else:
            candidates = [item for item in resolved.rglob("*") if item.is_file()][:500]
    else:
        candidates = []
    output: list[dict[str, Any]] = []
    if not candidates:
        candidates = []
        texts = [("<target>", target)]
    else:
        texts: list[tuple[str, str]] = []
        for item in candidates:
            try:
                if item.stat().st_size > 2 * 1024 * 1024:
                    continue
                raw = item.read_bytes()
                if b"\x00" in raw[:4096]:
                    continue
                texts.append((str(item), raw.decode("utf-8", errors="replace")))
            except OSError:
                continue
    for source, text in texts:
        for label, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                raw_value = match.group(1) if match.lastindex else match.group(0)
                output.append(_finding("custom_regex", target, f"Potential {label} in {Path(source).name}", description="Built-in secret-pattern match (value redacted).", evidence={"source": source, "pattern": label, "value": _redact(raw_value), "offset": match.start()}, endpoint=source, confidence=0.65))
                if len(output) >= 200:
                    return output
    return output


_HANDLERS = {
    "crtsh": _crtsh,
    "shodan": _shodan,
    "censys": _censys,
    "etherscan": _etherscan,
    "corellium": _corellium,
    "mobsf": _mobsf,
    "remix": _remix,
    "custom_regex": _custom_regex,
}


async def run(name: str, target: str, *, environment: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    try:
        handler = _HANDLERS[name]
    except KeyError as exc:
        raise KeyError(f"no built-in integration handler: {name}") from exc
    merged = {**os.environ, **dict(environment or {})}
    return await handler(target, merged)
