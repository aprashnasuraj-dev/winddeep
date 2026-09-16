"""Deterministic P5 web3 report section generation."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def render_web3_markdown(context: Mapping[str, Any]) -> str:
    """Render deterministic static-analysis context without exploit instructions."""
    chain_id = int(context["chain_id"])
    block_number = int(context["block_number"])
    if chain_id <= 0 or block_number <= 0:
        raise ValueError("web3 report requires positive chain_id and block_number")
    verified = bool(context.get("verified"))
    resolver = _text(context.get("resolver") or ("verified" if verified else "bytecode-only"))
    lines = [
        "## Source Resolution",
        "",
        f"- Contract: `{_text(context.get('contract_address'))}`",
        f"- Chain id: `{chain_id}`",
        f"- Pinned block: `{block_number}`",
        f"- Resolution: `{'verified source' if verified else 'source not verified'}`",
        f"- Resolver: `{resolver}`",
        f"- Resolver response SHA-256: `{_text(context.get('resolver_response_hash')) or 'n/a'}`",
        f"- Verified solc: `{_text(context.get('solc_version')) or 'unknown'}`",
        f"- Project solc: `{_text(context.get('project_solc_version')) or 'unknown'}`",
        f"- Optimizer runs: `{_text(context.get('optimizer_runs')) or 'unknown'}`",
        f"- EVM version: `{_text(context.get('evm_version')) or 'unknown'}`",
        f"- Source artifact SHA-256: `{_text(context.get('source_artifact_sha256')) or 'n/a'}`",
        f"- Bytecode artifact SHA-256: `{_text(context.get('bytecode_artifact_sha256')) or 'n/a'}`",
        f"- Disassembly artifact SHA-256: `{_text(context.get('disassembly_artifact_sha256')) or 'n/a'}`",
    ]
    if context.get("project_solc_version") and context.get("solc_version") and context.get("project_solc_version") != context.get("solc_version"):
        lines.append("- Compiler divergence: `true` — analysis is pinned to verified deployed metadata, not the project configuration.")
    else:
        lines.append("- Compiler divergence: `false`")

    lines.extend(["", "## Detector Provenance", ""])
    observations = list(context.get("engine_observations") or [])
    observations.sort(key=lambda row: (_text(row.get("engine")), _text(row.get("detector_id")), _text(row.get("swc_id"))))
    lines.append("| Engine | Version | Detector | SWC | Upstream source |")
    lines.append("| --- | --- | --- | --- | --- |")
    for row in observations:
        lines.append(
            f"| {_text(row.get('engine'))} | {_text(row.get('version'))} | {_text(row.get('detector_id'))} | {_text(row.get('swc_id')) or 'n/a'} | {_text(row.get('upstream_source'))} |"
        )
    if not observations:
        lines.append("| n/a | n/a | n/a | n/a | no detector provenance supplied |")

    lines.extend(
        [
            "",
            "## Static Finding Context",
            "",
            f"- Corroborated: `{str(bool(context.get('corroborated'))).lower()}`",
            f"- Affected function: `{_text(context.get('affected_function')) or 'unknown'}`",
            f"- Exploitability: `{_text(context.get('exploitability')) or 'needs-human-review'}`",
        ]
    )
    source_file = _text(context.get("source_file"))
    if source_file:
        lines.append(
            f"- Source location: `{source_file}:{_text(context.get('line_start')) or '?'}-{_text(context.get('line_end')) or '?'}`"
        )
    if context.get("bytecode_offset_start") is not None:
        lines.append(
            f"- Bytecode/disassembly range: `{context.get('bytecode_offset_start')}-{context.get('bytecode_offset_end')}`"
        )

    lines.extend(["", "## Reproducibility", ""])
    reproduction = context.get("reproduction_plan") or []
    if isinstance(reproduction, Sequence) and not isinstance(reproduction, (str, bytes)):
        for index, step in enumerate(reproduction, start=1):
            lines.append(f"{index}. {_text(step)}")
    else:
        lines.append("1. Re-run the pinned static engine against the cached evidence artifact and inspect the recorded location.")
    lines.append("2. Stop at static inspection; no fork, deployment, signing, or state-changing validation is part of this report.")
    caveat = _text(context.get("nondeterminism_caveat"))
    if caveat:
        lines.extend(["", f"Reproducibility caveat: {caveat}"])
    return "\n".join(lines).replace("\r\n", "\n").replace("\r", "\n") + "\n"
