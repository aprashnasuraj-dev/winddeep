"""Tests for the dynamic Windeep tool-wrapper factory."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.engine.tool_wrapper import Finding, ToolExecutionError, ToolWrapperFactory


def _write_config(path: Path, *, parser: str = "lines", retries: int = 0) -> None:
    path.write_text(
        json.dumps(
            {
                "tools": {
                    "demo": {
                        "binary": "demo-bin",
                        "args": ["--target", "{target}", "--count", "{count}"],
                        "input_schema": {
                            "count": {"type": "int", "required": True}
                        },
                        "parser": parser,
                        "timeout": 1,
                        "retries": retries,
                        "rate_limit": 0,
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def test_factory_generates_typed_wrapper(tmp_path: Path) -> None:
    config = tmp_path / "tools.json"
    _write_config(config)
    wrapper_class = ToolWrapperFactory(config).get("demo")
    model = wrapper_class.input_schema.model_validate(
        {"target": "example.com", "count": 3}
    )
    assert model.count == 3
    assert wrapper_class.tool_name == "demo"


def test_unknown_input_field_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "tools.json"
    _write_config(config)
    wrapper_class = ToolWrapperFactory(config).get("demo")
    with pytest.raises(ValidationError):
        wrapper_class.input_schema.model_validate(
            {"target": "example.com", "count": 1, "extra": True}
        )


def test_validate_installed_prefers_tools_directory(tmp_path: Path) -> None:
    config = tmp_path / "tools.json"
    _write_config(config)
    binary = tmp_path / "demo-bin"
    binary.write_text("binary", encoding="utf-8")
    wrapper = ToolWrapperFactory(config).get("demo")(tools_dir=tmp_path)
    assert wrapper.validate_installed()
    assert wrapper.resolve_binary() == binary.resolve()


def test_line_parser_normalizes_findings(tmp_path: Path) -> None:
    config = tmp_path / "tools.json"
    _write_config(config)
    wrapper = ToolWrapperFactory(config).get("demo")(tools_dir=tmp_path)
    findings = wrapper.parse_output("one\ntwo\n", "https://example.com")
    assert [finding.title for finding in findings] == ["one", "two"]
    assert all(isinstance(finding, Finding) for finding in findings)


def test_jsonl_parser_maps_common_fields(tmp_path: Path) -> None:
    config = tmp_path / "tools.json"
    _write_config(config, parser="jsonl")
    wrapper = ToolWrapperFactory(config).get("demo")(tools_dir=tmp_path)
    raw = (
        '{"title":"Issue","severity":"high",'
        '"url":"https://example.com/a","confidence":0.9}'
    )
    finding = wrapper.parse_output(raw, "https://example.com")[0]
    assert finding.title == "Issue"
    assert finding.severity == "high"
    assert finding.endpoint == "https://example.com/a"
    assert finding.confidence == 0.9


@pytest.mark.asyncio
async def test_run_enforces_scope_before_execution(tmp_path: Path) -> None:
    config = tmp_path / "tools.json"
    _write_config(config)
    binary = tmp_path / "demo-bin"
    binary.write_text("binary", encoding="utf-8")
    wrapper = ToolWrapperFactory(config).get("demo")(
        tools_dir=tmp_path,
        scope_validator=lambda target: target == "allowed.example",
    )
    with pytest.raises(PermissionError):
        await wrapper.run("denied.example", {"count": 1})


@pytest.mark.asyncio
async def test_run_returns_parsed_output_without_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "tools.json"
    _write_config(config)
    binary = tmp_path / "demo-bin"
    binary.write_text("binary", encoding="utf-8")
    wrapper = ToolWrapperFactory(config).get("demo")(tools_dir=tmp_path)

    async def fake_process(argv: list[str]) -> tuple[str, str, int]:
        assert argv[0] == str(binary.resolve())
        assert argv[-1] == "2"
        return "normalized output\n", "", 0

    monkeypatch.setattr(wrapper, "_run_process", fake_process)
    findings = await wrapper.run("example.com", {"count": 2})
    assert findings[0].title == "normalized output"


@pytest.mark.asyncio
async def test_retry_exhaustion_raises_tool_execution_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "tools.json"
    _write_config(config, retries=1)
    binary = tmp_path / "demo-bin"
    binary.write_text("binary", encoding="utf-8")
    wrapper = ToolWrapperFactory(config).get("demo")(tools_dir=tmp_path)
    attempts = 0

    async def failing_process(argv: list[str]) -> tuple[str, str, int]:
        nonlocal attempts
        attempts += 1
        return "", "failure", 2

    async def no_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(wrapper, "_run_process", failing_process)
    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    with pytest.raises(ToolExecutionError):
        await wrapper.run("example.com", {"count": 1})
    assert attempts == 2
