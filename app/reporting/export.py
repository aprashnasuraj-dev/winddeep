"""Deterministic P3 export bundles for HackerOne, Jira, and GitHub."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.reporting.generator import ReportArtifact, ReportGenerator, ReportingError

_SUPPORTED_PLATFORMS = {"hackerone", "jira", "github"}


@dataclass(frozen=True, slots=True)
class ExportBundle:
    """Platform payload plus redacted, hash-manifested attachment files."""

    platform: str
    report_sha256: str
    files: dict[str, bytes]
    payload: dict[str, Any]


class ExportBundleBuilder:
    """Build submission-ready bundles without performing remote side effects."""

    def __init__(self, generator: ReportGenerator) -> None:
        self.generator = generator

    @staticmethod
    def _canonical_json(value: Any) -> bytes:
        return (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str) + "\n"
        ).encode("utf-8")

    @staticmethod
    def _flows(report: ReportArtifact) -> list[Mapping[str, Any]]:
        if report.model.get("kind") == "finding":
            values = list(report.model.get("flows") or [])
        else:
            values = [flow for hop in report.model.get("hops") or [] for flow in hop.get("flows") or []]
        values.sort(key=lambda flow: (str(flow.get("created_at") or ""), int(flow.get("id") or 0)))
        return values

    @staticmethod
    def _headers(mapping: Mapping[str, Any]) -> list[dict[str, str]]:
        return [
            {"name": str(key), "value": str(value)}
            for key, value in sorted(mapping.items(), key=lambda item: str(item[0]).casefold())
        ]

    def _har(self, report: ReportArtifact) -> bytes:
        entries: list[dict[str, Any]] = []
        for flow in self._flows(report):
            request_headers = flow.get("request_headers") or {}
            response_headers = flow.get("response_headers") or {}
            request_body = str(flow.get("request_body") or "")
            response_body = str(flow.get("response_body") or "")
            request: dict[str, Any] = {
                "method": str(flow.get("method") or "GET"),
                "url": str(flow.get("url") or ""),
                "httpVersion": "HTTP/1.1",
                "headers": self._headers(request_headers),
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(request_body.encode("utf-8")),
            }
            if request_body:
                request["postData"] = {"mimeType": "text/plain", "text": request_body}
            response = {
                "status": int(flow.get("status") or 0),
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": self._headers(response_headers),
                "cookies": [],
                "content": {"size": len(response_body.encode("utf-8")), "mimeType": "text/plain", "text": response_body},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(response_body.encode("utf-8")),
            }
            entries.append(
                {
                    "startedDateTime": str(flow.get("created_at") or "unknown"),
                    "time": float(flow.get("timing_ms") or 0.0),
                    "request": request,
                    "response": response,
                    "cache": {},
                    "timings": {"send": 0, "wait": float(flow.get("timing_ms") or 0.0), "receive": 0},
                    "_windeep_flow_id": int(flow["id"]),
                    "_windeep_flow_sha256": str(flow["sha256"]),
                    "_windeep_replay_handle": str(flow["replay_handle"]),
                }
            )
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Windeep", "version": "2.3.0"},
                "entries": entries,
            }
        }
        return self._canonical_json(har)

    @staticmethod
    def _images(report: ReportArtifact) -> list[Mapping[str, Any]]:
        if report.model.get("kind") == "finding":
            images = list(report.model.get("images") or [])
            browser_present = bool(report.model.get("browser_observation_present"))
            if browser_present and not images:
                raise ReportingError("export requires a redacted screenshot view; raw encrypted screenshot is not exportable")
            return images
        images: list[Mapping[str, Any]] = []
        for hop in report.model.get("hops") or []:
            hop_images = list(hop.get("images") or [])
            if hop.get("browser_observation_present") and not hop_images:
                raise ReportingError("export requires a redacted screenshot view for every browser-observed hop")
            images.extend(hop_images)
        return images

    @staticmethod
    def _image_extension(media_type: str) -> str:
        return {
            "image/png": "png",
            "image/jpeg": "jpg",
            "image/webp": "webp",
        }.get(media_type.casefold(), "bin")

    @staticmethod
    def _platform_payload(platform: str, report: ReportArtifact, attachments: Sequence[str]) -> dict[str, Any]:
        common = {
            "platform": platform,
            "title": report.title,
            "body": report.markdown,
            "severity": report.severity,
            "cvss_vector": report.cvss_vector,
            "cvss_score": report.cvss_score,
            "report_sha256": report.sha256,
            "attachments": list(attachments),
        }
        if platform == "hackerone":
            common["hackerone"] = {
                "vulnerability_information": report.markdown,
                "severity_rating": report.severity,
            }
        elif platform == "jira":
            common["jira"] = {
                "fields": {
                    "summary": report.title,
                    "description": report.markdown,
                    "labels": ["windeep", f"severity-{report.severity}"],
                }
            }
        elif platform == "github":
            common["github"] = {
                "issue": {
                    "title": report.title,
                    "body": report.markdown,
                    "labels": ["security", f"severity:{report.severity}"],
                }
            }
        return common

    def _build(self, report: ReportArtifact, *, platform: str) -> ExportBundle:
        normalized = platform.strip().casefold()
        if normalized not in _SUPPORTED_PLATFORMS:
            raise ReportingError(f"unsupported export platform: {platform}")
        files: dict[str, bytes] = {
            "report.md": report.markdown.encode("utf-8"),
            "report.html": report.html.encode("utf-8"),
            "evidence.har": self._har(report),
        }
        for index, image in enumerate(self._images(report), start=1):
            extension = self._image_extension(str(image.get("media_type") or ""))
            files[f"screenshot-{index:02d}.{extension}"] = bytes(image["content"])
        manifest = {
            "schema": "windeep.report-export.v1",
            "report_sha256": report.sha256,
            "finding_ids": list(report.finding_ids),
            "flow_ids": list(report.flow_ids),
            "files": [
                {"name": name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
                for name, content in sorted(files.items())
            ],
        }
        files["manifest.json"] = self._canonical_json(manifest)
        payload = self._platform_payload(normalized, report, sorted(files))
        return ExportBundle(platform=normalized, report_sha256=report.sha256, files=files, payload=payload)

    def build_finding(
        self,
        finding_id: int,
        *,
        platform: str,
        external_duplicates: Sequence[Mapping[str, Any]] | None = None,
    ) -> ExportBundle:
        """Build a redacted export bundle for one evidence-backed finding."""
        return self._build(
            self.generator.render_finding(finding_id, external_duplicates=external_duplicates),
            platform=platform,
        )

    def build_chain(
        self,
        finding_ids: Sequence[int],
        *,
        platform: str,
        external_duplicates: Mapping[int, Sequence[Mapping[str, Any]]] | None = None,
    ) -> ExportBundle:
        """Build a redacted export bundle for an ordered evidence chain."""
        return self._build(
            self.generator.render_chain(finding_ids, external_duplicates=external_duplicates),
            platform=platform,
        )
