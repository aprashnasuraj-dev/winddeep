"""Authenticated bug-bounty program scope importers with encrypted policy snapshots."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urljoin

import httpx

from app.database import Database
from app.security.crypto import CryptoManager
from app.security.scope import ScopeEnforcer


class ScopeImportError(RuntimeError):
    """Raised when program scope cannot be imported or normalized safely."""


@dataclass(frozen=True, slots=True)
class ProgramAsset:
    """Normalized program asset used to build enforceable local scope."""

    identifier: str
    asset_type: str
    eligible: bool = True
    max_severity: str | None = None
    instructions: str = ""

    def __post_init__(self) -> None:
        if not self.identifier.strip():
            raise ValueError("asset identifier must not be empty")
        if not self.asset_type.strip():
            raise ValueError("asset_type must not be empty")


@dataclass(frozen=True, slots=True)
class ImportedProgramScope:
    """Result of one platform scope import."""

    platform: str
    program_handle: str
    assets: tuple[ProgramAsset, ...]
    snapshot_sha256: str
    snapshot_path: str
    source_url: str
    testing_requirements: dict[str, Any]


class ScopeSnapshotStore:
    """Store encrypted immutable program-policy snapshots for later consent evidence."""

    def __init__(self, crypto: CryptoManager, root: str | Path = "state/program_snapshots") -> None:
        self.crypto = crypto
        self.root = Path(root)

    @staticmethod
    def _slug(value: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
        return slug[:100] or "program"

    def save(self, platform: str, program_handle: str, payload: Mapping[str, Any]) -> tuple[str, str]:
        """Encrypt a canonical JSON snapshot and return plaintext SHA-256 plus path."""
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        directory = self.root / self._slug(platform) / self._slug(program_handle)
        directory.mkdir(parents=True, exist_ok=True)
        stamp = int(time.time() * 1000)
        path = directory / f"{stamp}-{digest[:12]}.json.enc"
        encrypted = self.crypto.encrypt_text(canonical, aad=b"windeep:program-snapshot")
        path.write_text(encrypted, encoding="utf-8")
        return digest, str(path)

    def load(self, path: str | Path) -> dict[str, Any]:
        """Decrypt and validate one stored policy snapshot."""
        encrypted = Path(path).read_text(encoding="utf-8")
        plaintext = self.crypto.decrypt_text(encrypted, aad=b"windeep:program-snapshot")
        value = json.loads(plaintext)
        if not isinstance(value, dict):
            raise ScopeImportError("program snapshot is not a JSON object")
        return value


class ProgramScopeRepository:
    """Persist normalized program scopes and replace stale assets atomically."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self._require_schema()

    def _require_schema(self) -> None:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = ? AND name = ?",
                ("table", "program_scopes"),
            ).fetchone()
        if row is None:
            raise ScopeImportError("program_scopes table is missing; apply migrations first")

    def replace(
        self,
        *,
        platform: str,
        program_handle: str,
        assets: Sequence[ProgramAsset],
        tos_url: str,
        snapshot_sha256: str,
    ) -> int:
        """Replace a program's locally cached scope in one transaction."""
        now = time.time()
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "DELETE FROM program_scopes WHERE platform = ? AND program_handle = ?",
                    (platform, program_handle),
                )
                for asset in assets:
                    conn.execute(
                        """
                        INSERT INTO program_scopes(
                            platform, program_handle, asset_identifier, asset_type,
                            eligible, max_severity, instructions, tos_url,
                            tos_snapshot_sha256, imported_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            platform,
                            program_handle,
                            asset.identifier,
                            asset.asset_type,
                            int(asset.eligible),
                            asset.max_severity,
                            asset.instructions,
                            tos_url,
                            snapshot_sha256,
                            now,
                        ),
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return len(assets)

    def list(self, platform: str, program_handle: str) -> list[ProgramAsset]:
        """Return normalized assets for one imported program."""
        with self.database._connect() as conn:
            rows = conn.execute(
                """
                SELECT asset_identifier, asset_type, eligible, max_severity, instructions
                FROM program_scopes
                WHERE platform = ? AND program_handle = ?
                ORDER BY asset_identifier
                """,
                (platform, program_handle),
            ).fetchall()
        return [
            ProgramAsset(
                identifier=str(row[0]),
                asset_type=str(row[1]),
                eligible=bool(row[2]),
                max_severity=str(row[3]) if row[3] is not None else None,
                instructions=str(row[4] or ""),
            )
            for row in rows
        ]

    def to_scope_enforcer(self, platform: str, program_handle: str) -> ScopeEnforcer:
        """Build a web-addressable ScopeEnforcer from the latest imported program scope."""
        assets = self.list(platform, program_handle)
        web_types = {
            "url",
            "domain",
            "wildcard",
            "cidr",
            "website",
            "web",
            "api",
            "ip",
            "ip address",
        }
        relevant = [asset for asset in assets if asset.asset_type.casefold() in web_types]
        allows = [asset.identifier for asset in relevant if asset.eligible]
        denies = [asset.identifier for asset in relevant if not asset.eligible]
        if not allows:
            raise ScopeImportError("imported program has no eligible web-addressable assets")
        return ScopeEnforcer(target=allows[0], allow=allows, deny=denies)


class ProgramScopeImporter:
    """Import HackerOne, Bugcrowd, and Intigriti scope using user-supplied API credentials."""

    HACKERONE_BASE = "https://api.hackerone.com/v1/"
    BUGCROWD_BASE = "https://api.bugcrowd.com/"
    INTIGRITI_BASE = "https://api.intigriti.com/external/researcher/"

    def __init__(
        self,
        repository: ProgramScopeRepository,
        snapshots: ScopeSnapshotStore,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.repository = repository
        self.snapshots = snapshots
        self.transport = transport
        self.timeout = timeout

    async def import_hackerone(self, handle: str, *, api_username: str, api_token: str) -> ImportedProgramScope:
        """Import HackerOne researcher structured scopes for one program handle."""
        if not handle.strip() or not api_username or not api_token:
            raise ValueError("handle, api_username, and api_token are required")
        try:
            async with httpx.AsyncClient(
                base_url=self.HACKERONE_BASE,
                auth=(api_username, api_token),
                headers={"Accept": "application/json"},
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                program_response = await client.get(f"hackers/programs/{handle}")
                program_response.raise_for_status()
                program = program_response.json()
                scopes = await self._hackerone_pages(client, f"hackers/programs/{handle}/structured_scopes")
                exclusions_response = await client.get(f"hackers/programs/{handle}/scope_exclusions")
                exclusions_response.raise_for_status()
                exclusions = exclusions_response.json()
            assets = self._parse_hackerone_scopes(scopes)
            snapshot_payload = {"program": program, "structured_scopes": scopes, "scope_exclusions": exclusions}
            digest, path = self.snapshots.save("hackerone", handle, snapshot_payload)
            source_url = f"https://hackerone.com/{handle}"
            self.repository.replace(
                platform="hackerone",
                program_handle=handle,
                assets=assets,
                tos_url=source_url,
                snapshot_sha256=digest,
            )
            return ImportedProgramScope(
                platform="hackerone",
                program_handle=handle,
                assets=tuple(assets),
                snapshot_sha256=digest,
                snapshot_path=path,
                source_url=source_url,
                testing_requirements={"scope_exclusions": exclusions},
            )
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ScopeImportError(f"HackerOne scope import failed: {exc}") from exc

    async def _hackerone_pages(self, client: httpx.AsyncClient, path: str) -> dict[str, Any]:
        data: list[Any] = []
        next_url: str | None = path
        pages = 0
        while next_url:
            pages += 1
            if pages > 100:
                raise ScopeImportError("HackerOne pagination exceeded 100 pages")
            response = await client.get(next_url, params={"page[size]": 100} if pages == 1 else None)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, Mapping):
                raise ScopeImportError("HackerOne returned a non-object page")
            page_data = payload.get("data", [])
            if not isinstance(page_data, list):
                raise ScopeImportError("HackerOne page data is not a list")
            data.extend(page_data)
            links = payload.get("links") or {}
            next_value = links.get("next") if isinstance(links, Mapping) else None
            next_url = str(next_value) if next_value else None
        return {"data": data}

    @staticmethod
    def _parse_hackerone_scopes(payload: Mapping[str, Any]) -> list[ProgramAsset]:
        assets: list[ProgramAsset] = []
        for item in payload.get("data", []):
            if not isinstance(item, Mapping):
                continue
            attributes = item.get("attributes") or {}
            if not isinstance(attributes, Mapping):
                continue
            identifier = str(attributes.get("asset_identifier") or "").strip()
            asset_type = str(attributes.get("asset_type") or "").strip()
            if not identifier or not asset_type:
                continue
            assets.append(
                ProgramAsset(
                    identifier=identifier,
                    asset_type=asset_type,
                    eligible=bool(attributes.get("eligible_for_submission", False)),
                    max_severity=str(attributes["max_severity"]) if attributes.get("max_severity") else None,
                    instructions=str(attributes.get("instruction") or ""),
                )
            )
        if not assets:
            raise ScopeImportError("HackerOne returned no structured scope assets")
        return assets

    async def import_intigriti(self, program_id: str, *, bearer_token: str) -> ImportedProgramScope:
        """Import Intigriti researcher program domains and rules of engagement."""
        if not program_id.strip() or not bearer_token:
            raise ValueError("program_id and bearer_token are required")
        headers = {"Authorization": f"Bearer {bearer_token}", "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(
                base_url=self.INTIGRITI_BASE,
                headers=headers,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = await client.get(f"v1/programs/{program_id}")
                response.raise_for_status()
                program = response.json()
            if not isinstance(program, Mapping):
                raise ScopeImportError("Intigriti returned a non-object program")
            handle = str(program.get("handle") or program_id)
            name = str(program.get("name") or handle)
            domains = program.get("domains") or {}
            content = domains.get("content") if isinstance(domains, Mapping) else []
            assets: list[ProgramAsset] = []
            for item in content or []:
                if not isinstance(item, Mapping):
                    continue
                endpoint = str(item.get("endpoint") or "").strip()
                type_value = item.get("type") or {}
                asset_type = str(type_value.get("value") if isinstance(type_value, Mapping) else type_value or "domain")
                if endpoint:
                    assets.append(
                        ProgramAsset(
                            identifier=endpoint,
                            asset_type=asset_type,
                            eligible=True,
                            instructions=str(item.get("description") or ""),
                        )
                    )
            if not assets:
                raise ScopeImportError("Intigriti returned no program domains")
            rules = program.get("rulesOfEngagement") or {}
            rule_content = rules.get("content") if isinstance(rules, Mapping) else {}
            testing_requirements = {}
            if isinstance(rule_content, Mapping):
                maybe_requirements = rule_content.get("testingRequirements")
                if isinstance(maybe_requirements, Mapping):
                    testing_requirements = dict(maybe_requirements)
            source_url = str(((program.get("webLinks") or {}).get("detail") if isinstance(program.get("webLinks"), Mapping) else "") or "https://app.intigriti.com/")
            digest, path = self.snapshots.save("intigriti", handle, {"program": program})
            self.repository.replace(
                platform="intigriti",
                program_handle=handle,
                assets=assets,
                tos_url=source_url,
                snapshot_sha256=digest,
            )
            return ImportedProgramScope(
                platform="intigriti",
                program_handle=handle,
                assets=tuple(assets),
                snapshot_sha256=digest,
                snapshot_path=path,
                source_url=source_url,
                testing_requirements=testing_requirements,
            )
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ScopeImportError(f"Intigriti scope import failed: {exc}") from exc

    async def import_bugcrowd(
        self,
        program_id: str,
        *,
        token_username: str,
        token_password: str,
    ) -> ImportedProgramScope:
        """Import Bugcrowd program targets using the documented JSON:API program includes."""
        if not program_id.strip() or not token_username or not token_password:
            raise ValueError("program_id and Bugcrowd token credentials are required")
        headers = {
            "Accept": "application/vnd.bugcrowd+json",
            "Authorization": f"Token {token_username}:{token_password}",
        }
        params = {
            "include": "current_brief.target_groups.targets,current_brief.target_groups.reward_range",
            "fields[program]": "code,current_brief",
            "fields[program_brief]": "target_groups",
            "fields[target_group]": "name,targets,reward_range",
            "fields[target]": "name,category",
        }
        try:
            async with httpx.AsyncClient(
                base_url=self.BUGCROWD_BASE,
                headers=headers,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = await client.get(f"programs/{program_id}", params=params)
                response.raise_for_status()
                program = response.json()
            if not isinstance(program, Mapping):
                raise ScopeImportError("Bugcrowd returned a non-object program")
            primary = program.get("data") or {}
            attributes = primary.get("attributes") if isinstance(primary, Mapping) else {}
            handle = str((attributes or {}).get("code") or program_id)
            assets: list[ProgramAsset] = []
            for item in program.get("included", []):
                if not isinstance(item, Mapping) or str(item.get("type") or "").casefold() != "target":
                    continue
                attrs = item.get("attributes") or {}
                if not isinstance(attrs, Mapping):
                    continue
                identifier = str(attrs.get("name") or "").strip()
                category = str(attrs.get("category") or "web").strip()
                if identifier:
                    assets.append(ProgramAsset(identifier=identifier, asset_type=category, eligible=True))
            if not assets:
                raise ScopeImportError("Bugcrowd returned no target assets")
            source_url = f"https://bugcrowd.com/engagements/{handle}"
            digest, path = self.snapshots.save("bugcrowd", handle, {"program": program})
            self.repository.replace(
                platform="bugcrowd",
                program_handle=handle,
                assets=assets,
                tos_url=source_url,
                snapshot_sha256=digest,
            )
            return ImportedProgramScope(
                platform="bugcrowd",
                program_handle=handle,
                assets=tuple(assets),
                snapshot_sha256=digest,
                snapshot_path=path,
                source_url=source_url,
                testing_requirements={},
            )
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ScopeImportError(f"Bugcrowd scope import failed: {exc}") from exc

    def import_manual(
        self,
        *,
        platform: str,
        program_handle: str,
        assets: Sequence[ProgramAsset],
        source_url: str,
        policy: Mapping[str, Any],
    ) -> ImportedProgramScope:
        """Import a manually supplied policy without weakening snapshot/audit semantics."""
        if not assets:
            raise ScopeImportError("manual import requires at least one asset")
        digest, path = self.snapshots.save(platform, program_handle, {"policy": dict(policy), "assets": [asset.__dict__ for asset in assets]})
        self.repository.replace(
            platform=platform,
            program_handle=program_handle,
            assets=assets,
            tos_url=source_url,
            snapshot_sha256=digest,
        )
        return ImportedProgramScope(
            platform=platform,
            program_handle=program_handle,
            assets=tuple(assets),
            snapshot_sha256=digest,
            snapshot_path=path,
            source_url=source_url,
            testing_requirements={},
        )
