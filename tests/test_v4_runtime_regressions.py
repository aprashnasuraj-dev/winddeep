from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.engine.tool_wrapper import ToolWrapperFactory, _failure_outcome, _jsonl_parser
from app.tools.backends import BackendUnavailableError
from app.tools.provisioning import _candidate_names


def _factory(tmp_path: Path, root: dict | None = None) -> ToolWrapperFactory:
    config = tmp_path / "tools_config.json"
    config.write_text(json.dumps(root if root is not None else {"tools": {}}), encoding="utf-8")
    return ToolWrapperFactory(config)


def test_windows_provisioning_prefers_only_native_launchers_over_posix_shims() -> None:
    assert _candidate_names("surya", windows=True) == ["surya.exe", "surya.cmd", "surya.bat"]
    assert _candidate_names("solcjs", windows=True)[0:2] == ["solcjs.exe", "solcjs.cmd"]
    assert "inql" not in _candidate_names("inql", windows=True)
    assert _candidate_names("tool", windows=False) == ["tool"]
    assert _candidate_names("already.exe", windows=True) == ["already.exe"]


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (BackendUnavailableError("missing"), "MISSING"),
        (FileNotFoundError("missing"), "MISSING"),
        (OSError(2, "missing"), "MISSING"),
        (OSError(5, "denied"), "REJECTED"),
        (RuntimeError("boom"), "REJECTED"),
    ],
)
def test_backend_failure_classification_is_stable(exc: BaseException, expected: str) -> None:
    assert _failure_outcome(exc) == expected


def test_jsonl_parser_handles_blank_text_scalar_and_invalid_confidence() -> None:
    raw = "\nnot-json\n42\n{\"name\":\"structured\",\"confidence\":\"bad\"}\n{\"url\":\"https://example.test\",\"confidence\":2}\n"
    rows = _jsonl_parser(raw, "demo", "example.test")
    assert len(rows) == 4
    assert rows[0].title == "not-json"
    assert rows[0].evidence["line_number"] == 2
    assert rows[1].title == "Tool finding"
    assert rows[1].evidence == {"value": 42}
    assert rows[2].title == "structured"
    assert rows[2].confidence == 0.5
    assert rows[3].title == "https://example.test"
    assert rows[3].confidence == 1.0


@pytest.mark.parametrize(
    ("definition", "message"),
    [
        ({"args": "not-a-list"}, "args must be a list"),
        ({"stdin": 7}, "stdin must be a string"),
        ({"parser": "does-not-exist"}, "unknown parser"),
        ({"required_env": "TOKEN"}, "required_env must be a list"),
        ({"target_types": "domain"}, "target_types must be a list"),
        ({"runtime_strategy": "telepathy"}, "invalid runtime_strategy"),
        ({"execution_preference": "local_binary"}, "execution_preference must be a list"),
        ({"provision": []}, "provision must be an object"),
        ({"probe": "--version"}, "probe must be a list"),
        ({"input_schema": []}, "input_schema must be an object"),
        ({"input_schema": {"threads": "bad"}}, "input field must be an object"),
        ({"input_schema": {"threads": {"type": "mystery"}}}, "unsupported input type"),
    ],
)
def test_wrapper_factory_rejects_invalid_runtime_contracts(tmp_path: Path, definition: dict, message: str) -> None:
    factory = _factory(tmp_path)
    with pytest.raises(ValueError, match=message):
        factory._create_wrapper("demo", definition)


def test_wrapper_factory_builds_required_and_optional_input_fields(tmp_path: Path) -> None:
    factory = _factory(tmp_path)
    wrapper = factory._create_wrapper(
        "demo",
        {
            "input_schema": {
                "required_count": {"type": "int", "required": True},
                "optional_flag": {"type": "bool", "default": False},
            }
        },
    )
    validated = wrapper.input_schema.model_validate(
        {"target": "example.test", "required_count": 3}
    ).model_dump()
    assert validated["required_count"] == 3
    assert validated["optional_flag"] is False


def test_load_definitions_rejects_non_object_root(tmp_path: Path) -> None:
    config = tmp_path / "tools_config.json"
    config.write_text("[]", encoding="utf-8")
    factory = ToolWrapperFactory(config)
    with pytest.raises(ValueError, match="tool config must be an object"):
        factory._load_definitions(config.resolve(), set())


@pytest.mark.parametrize(
    ("root", "message"),
    [
        ({"tools": []}, "'tools' must be an object"),
        ({"tools": {"demo": []}}, "tool definition must be an object"),
        ({"tools": {}, "includes": "child.json"}, "'includes' must be a list"),
        ({"tools": {}, "includes": ["../outside.json"]}, "include escapes registry root"),
    ],
)
def test_load_definitions_rejects_invalid_registry_shapes(tmp_path: Path, root: dict, message: str) -> None:
    factory = _factory(tmp_path, root)
    with pytest.raises(ValueError, match=message):
        factory._load_definitions(factory.config_path.resolve(), set())


def test_load_definitions_rejects_cycles_and_duplicates(tmp_path: Path) -> None:
    cyclic = _factory(tmp_path, {"tools": {}, "includes": ["tools_config.json"]})
    with pytest.raises(ValueError, match="cyclic tools_config include"):
        cyclic._load_definitions(cyclic.config_path.resolve(), set())

    child = tmp_path / "child.json"
    child.write_text(json.dumps({"tools": {"demo": {}}}), encoding="utf-8")
    duplicate = _factory(tmp_path, {"tools": {"demo": {}}, "includes": ["child.json"]})
    with pytest.raises(ValueError, match="duplicate tool definition"):
        duplicate._load_definitions(duplicate.config_path.resolve(), set())


def test_runtime_overlay_missing_file_uses_defaults_and_unknown_get_raises(tmp_path: Path) -> None:
    factory = _factory(tmp_path, {"tools": {"demo": {}}})
    defaults, tools, aliases = factory._load_runtime_overlays({"demo": {}})
    assert defaults == {"runtime_strategy": "auto"}
    assert tools == {}
    assert aliases == {}
    with pytest.raises(KeyError, match="unknown tool wrapper"):
        factory.get("missing")


def test_runtime_overlay_rejects_escape_and_invalid_shapes(tmp_path: Path) -> None:
    escaped = _factory(
        tmp_path,
        {"tools": {"demo": {}}, "runtime_overlays": "../outside.json"},
    )
    with pytest.raises(ValueError, match="runtime_overlays escapes registry root"):
        escaped._load_runtime_overlays({"demo": {}})

    overlay = tmp_path / "overlay.json"
    overlay.write_text("[]", encoding="utf-8")
    malformed = _factory(
        tmp_path,
        {"tools": {"demo": {}}, "runtime_overlays": "overlay.json"},
    )
    with pytest.raises(ValueError, match="runtime overlay must be an object"):
        malformed._load_runtime_overlays({"demo": {}})

    overlay.write_text(json.dumps({"defaults": [], "tools": {}, "aliases": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="requires object defaults/tools/aliases"):
        malformed._load_runtime_overlays({"demo": {}})


def test_runtime_overlay_filters_unknown_tools_and_non_object_entries(tmp_path: Path) -> None:
    overlay = tmp_path / "overlay.json"
    overlay.write_text(
        json.dumps(
            {
                "defaults": {"runtime_strategy": "auto"},
                "tools": {"demo": {"probe": ["--help"]}, "unknown": {}, "bad": []},
                "aliases": {"demo": "maintained", "unknown": "ignored"},
            }
        ),
        encoding="utf-8",
    )
    factory = _factory(
        tmp_path,
        {"tools": {"demo": {}}, "runtime_overlays": "overlay.json"},
    )
    defaults, tools, aliases = factory._load_runtime_overlays({"demo": {}})
    assert defaults["runtime_strategy"] == "auto"
    assert tools == {"demo": {"probe": ["--help"]}}
    assert aliases == {"demo": "maintained"}
