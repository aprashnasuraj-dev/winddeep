"""One-shot/idempotent migration for the operational 137-integration runtime.

This script is intentionally repository-local so the exact source tree can be
transformed and tested by GitHub Actions without relying on an external clone.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"expected migration anchor missing in {path}: {old[:120]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def migrate_registry() -> None:
    path = ROOT / "tools_config.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    catalog = list(data["catalog_includes"])
    data["active_tool_count"] = 137
    data["certified_windows_tool_count"] = 6
    data["includes"] = catalog
    data["release_policy"] = (
        "All 137 catalog integrations are runtime-addressable. Windows v0.1.x packaging certification "
        "remains a separate six-binary payload contract enforced by app/tools/release-policy.json and "
        "installer/tools-manifest.json."
    )
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def migrate_wrapper() -> None:
    path = ROOT / "app" / "engine" / "tool_wrapper.py"
    replace_once(
        path,
        "from pydantic import BaseModel, ConfigDict, Field, create_model\n",
        "from pydantic import BaseModel, ConfigDict, Field, create_model\n\nfrom app.tools import builtin_integrations\n",
    )
    replace_once(
        path,
        "    required_env: ClassVar[tuple[str, ...]] = ()\n\n    def __init__(\n        self,\n        *,\n        tools_dir: str | Path = \"tools\",\n        scope_validator: Callable[[str], bool] | None = None,\n    ) -> None:\n        self.tools_dir = Path(tools_dir)\n        self.scope_validator = scope_validator\n        self._rate_lock = asyncio.Lock()\n        self._last_started = 0.0\n",
        "    required_env: ClassVar[tuple[str, ...]] = ()\n    adapter_kind: ClassVar[str] = \"process\"\n    target_types: ClassVar[tuple[str, ...]] = ()\n    scan_default: ClassVar[bool] = True\n\n    def __init__(\n        self,\n        *,\n        tools_dir: str | Path = \"tools\",\n        scope_validator: Callable[[str], bool] | None = None,\n        environment: Mapping[str, str] | None = None,\n    ) -> None:\n        self.tools_dir = Path(tools_dir)\n        self.scope_validator = scope_validator\n        self.environment = {**os.environ, **dict(environment or {})}\n        self._rate_lock = asyncio.Lock()\n        self._last_started = 0.0\n",
    )
    replace_once(
        path,
        "        configured = Path(self.binary)\n",
        "        env_key = \"WINDEEP_TOOL_\" + \"\".join(ch if ch.isalnum() else \"_\" for ch in self.tool_name.upper()) + \"_BINARY\"\n        configured = Path(self.environment.get(env_key) or self.binary)\n",
    )
    replace_once(
        path,
        "    def validate_installed(self) -> bool:\n        \"\"\"Return whether the wrapper executable can be resolved.\"\"\"\n        return self.resolve_binary() is not None\n\n    def missing_environment(self) -> tuple[str, ...]:\n        \"\"\"Return required environment-variable names that are not configured.\"\"\"\n        return tuple(name for name in self.required_env if not os.getenv(name))\n",
        "    def validate_installed(self) -> bool:\n        \"\"\"Return whether this integration has a runnable local/built-in path.\"\"\"\n        if builtin_integrations.supports(self.tool_name):\n            return not self.missing_environment()\n        return self.resolve_binary() is not None\n\n    def missing_environment(self) -> tuple[str, ...]:\n        \"\"\"Return required environment-variable names that are not configured.\"\"\"\n        required = (*self.required_env, *builtin_integrations.required_env(self.tool_name))\n        return tuple(sorted({name for name in required if not self.environment.get(name)}))\n",
    )
    replace_once(
        path,
        "            binary = self.resolve_binary()\n            if binary is None:\n                raise FileNotFoundError(f\"tool binary not installed: {self.binary}\")\n\n            validated = self.input_schema.model_validate(\n                {\"target\": target, **dict(options or {})}\n            ).model_dump()\n            argv = [str(binary), *self._render_args(validated)]\n            stdin_data = self._render_stdin(validated)\n",
        "            validated = self.input_schema.model_validate(\n                {\"target\": target, **dict(options or {})}\n            ).model_dump()\n            if builtin_integrations.supports(self.tool_name):\n                rows = await builtin_integrations.run(self.tool_name, target, environment=self.environment)\n                return [Finding.model_validate(row) for row in rows]\n\n            rendered_args = self._render_args(validated)\n            binary = self.resolve_binary()\n            if binary is None:\n                wsl = shutil.which(\"wsl.exe\") if os.name == \"nt\" else None\n                if wsl:\n                    argv = [wsl, \"--\", self.binary, *rendered_args]\n                else:\n                    raise FileNotFoundError(\n                        f\"tool binary not installed: {self.binary}; install it on PATH/tools, set WINDEEP_TOOL_{self.tool_name.upper().replace('-', '_')}_BINARY, or install it in WSL\"\n                    )\n            else:\n                argv = [str(binary), *rendered_args]\n            stdin_data = self._render_stdin(validated)\n",
    )
    replace_once(
        path,
        "            stderr=asyncio.subprocess.PIPE,\n            creationflags=creationflags,\n        )\n",
        "            stderr=asyncio.subprocess.PIPE,\n            creationflags=creationflags,\n            env=self.environment,\n        )\n",
    )
    replace_once(
        path,
        "        input_model = self._build_input_model(name, definition.get(\"input_schema\", {}))\n        class_name = \"\".join(part.capitalize() for part in name.replace(\"-\", \"_\").split(\"_\")) + \"Wrapper\"\n",
        "        input_model = self._build_input_model(name, definition.get(\"input_schema\", {}))\n        target_types_raw = definition.get(\"target_types\", [])\n        if not isinstance(target_types_raw, list) or not all(isinstance(item, str) for item in target_types_raw):\n            raise ValueError(f\"target_types must be a list of strings: {name}\")\n        class_name = \"\".join(part.capitalize() for part in name.replace(\"-\", \"_\").split(\"_\")) + \"Wrapper\"\n",
    )
    replace_once(
        path,
        "                \"required_env\": tuple(required_env),\n                \"__module__\": __name__,\n",
        "                \"required_env\": tuple(required_env),\n                \"adapter_kind\": \"builtin\" if builtin_integrations.supports(name) else \"process\",\n                \"target_types\": tuple(target_types_raw),\n                \"scan_default\": bool(definition.get(\"scan_default\", True)),\n                \"__module__\": __name__,\n",
    )


def migrate_server() -> None:
    path = ROOT / "app" / "server.py"
    replace_once(
        path,
        "from app.modules.test_packs import PACK_COUNTS, TOTAL_TESTS, list_tests, run_selected\n",
        "from app.modules.test_packs import PACK_COUNTS, TOTAL_TESTS, list_tests, run_selected\nfrom app.tools.release_metadata import apply_release_metadata\n",
    )
    replace_once(
        path,
        "    wrapper_classes = factory.load()\n    scan_cancel: set[int] = set()\n",
        "    wrapper_classes = factory.load()\n    effective_tools = apply_release_metadata(wrapper_classes, registry_path)\n    scan_cancel: set[int] = set()\n",
    )
    replace_once(
        path,
        "            result.append({\"name\": name, \"category\": cls.category, \"description\": cls.description, \"installed\": wrapper.validate_installed(), \"configured\": not bool(wrapper.missing_environment()), \"required_env\": list(cls.required_env), \"timeout\": cls.timeout, \"retries\": cls.retries, \"rate_limit\": cls.rate_limit, \"requires_scope\": cls.requires_scope})\n",
        "            result.append({\"name\": name, \"category\": cls.category, \"description\": cls.description, \"adapter\": getattr(cls, \"adapter_kind\", \"process\"), \"installed\": wrapper.validate_installed(), \"configured\": not bool(wrapper.missing_environment()), \"required_env\": sorted(set((*cls.required_env, *wrapper.missing_environment()))), \"timeout\": cls.timeout, \"retries\": cls.retries, \"rate_limit\": cls.rate_limit, \"requires_scope\": cls.requires_scope, \"release_support\": getattr(cls, \"release_support\", \"unsupported\"), \"windows_certified\": getattr(cls, \"release_support\", \"\") == \"bundled\"})\n",
    )
    replace_once(path, "raise KeyError(f\"unknown release-certified tool: {tool_name}\")", "raise KeyError(f\"unknown tool integration: {tool_name}\")")
    replace_once(path, "raise ValueError(\"no release-certified tools matched the requested scan selection\")", "raise ValueError(\"no tool integrations matched the requested scan selection\")")
    replace_once(
        path,
        "\"release_certified_tools\": len(wrapper_classes), \"test_count\": TOTAL_TESTS",
        "\"integrations_total\": len(wrapper_classes), \"windows_certified_tools\": sum(1 for cls in wrapper_classes.values() if getattr(cls, \"release_support\", \"\") == \"bundled\"), \"test_count\": TOTAL_TESTS",
    )
    replace_once(
        path,
        "\"tools\": {\"active\": len(wrapper_classes), \"all_scope_bound\": all(cls.requires_scope for cls in wrapper_classes.values())}",
        "\"tools\": {\"active\": len(wrapper_classes), \"catalog\": len(effective_tools), \"windows_certified\": sum(1 for cls in wrapper_classes.values() if getattr(cls, \"release_support\", \"\") == \"bundled\"), \"all_scope_bound\": all(cls.requires_scope for cls in wrapper_classes.values())}",
    )


def migrate_audit() -> None:
    path = ROOT / "scripts" / "audit" / "release_audit.py"
    replace_once(path, "EXPECTED_ACTIVE_TOOL_COUNT = 6\n", "EXPECTED_ACTIVE_TOOL_COUNT = 137\nEXPECTED_CERTIFIED_TOOL_COUNT = 6\n")
    replace_once(
        path,
        "    checks.append(Check(\"runtime allowlist equals certified bundled set\", \"PASS\" if set(active) == bundled else \"FAIL\", f\"active={sorted(active)}, bundled={sorted(bundled)}\"))\n",
        "    checks.append(Check(\"operational runtime exposes complete catalog\", \"PASS\" if set(active) == set(catalog) and len(active) == EXPECTED_ACTIVE_TOOL_COUNT else \"FAIL\", f\"active={len(active)}, catalog={len(catalog)}, required={EXPECTED_ACTIVE_TOOL_COUNT}\"))\n    checks.append(Check(\"Windows-certified bundled subset\", \"PASS\" if len(bundled) == EXPECTED_CERTIFIED_TOOL_COUNT else \"FAIL\", f\"bundled={sorted(bundled)}, required_count={EXPECTED_CERTIFIED_TOOL_COUNT}\"))\n",
    )
    replace_once(
        path,
        "    checks.append(Check(\"certified runtime allowlist\", \"PASS\" if set(active) == bundled else \"FAIL\", f\"active={sorted(active)}, bundled={sorted(bundled)}\"))\n",
        "    checks.append(Check(\"operational runtime catalog\", \"PASS\" if set(active) == set(catalog) and len(active) == EXPECTED_ACTIVE_TOOL_COUNT else \"FAIL\", f\"active={len(active)}, catalog={len(catalog)}\"))\n    checks.append(Check(\"Windows-certified manifest subset count\", \"PASS\" if len(bundled) == EXPECTED_CERTIFIED_TOOL_COUNT else \"FAIL\", f\"bundled={sorted(bundled)}, required_count={EXPECTED_CERTIFIED_TOOL_COUNT}\"))\n",
    )
    replace_once(
        path,
        "                and body.get(\"release_certified_tools\") == EXPECTED_ACTIVE_TOOL_COUNT\n",
        "                and body.get(\"integrations_total\") == EXPECTED_ACTIVE_TOOL_COUNT\n                and body.get(\"windows_certified_tools\") == EXPECTED_CERTIFIED_TOOL_COUNT\n",
    )


def migrate_tests() -> None:
    path = ROOT / "tests" / "test_release_catalog_contract.py"
    replace_once(
        path,
        "def test_runtime_registry_is_exact_certified_subset() -> None:\n    classes = ToolWrapperFactory(ROOT / \"tools_config.json\").load()\n    assert set(classes) == CERTIFIED\n    assert all(wrapper.requires_scope is True for wrapper in classes.values())\n",
        "def test_runtime_registry_exposes_complete_catalog() -> None:\n    classes = ToolWrapperFactory(ROOT / \"tools_config.json\").load()\n    effective = effective_definitions(ROOT / \"tools_config.json\")\n    assert len(classes) == 137\n    assert set(classes) == set(effective)\n    assert all(wrapper.requires_scope is True for wrapper in classes.values())\n",
    )
    replace_once(
        path,
        "    assert len(effective) == 137\n    assert set(classes) == CERTIFIED\n    for name, wrapper in classes.items():\n        assert wrapper.release_support == \"bundled\"\n        assert wrapper.license == \"MIT\"\n        assert wrapper.homepage.startswith(\"https://github.com/projectdiscovery/\")\n        assert effective[name][\"release_support\"] == \"bundled\"\n",
        "    assert len(effective) == 137\n    assert set(classes) == set(effective)\n    assert {name for name, wrapper in classes.items() if wrapper.release_support == \"bundled\"} == CERTIFIED\n    for name in CERTIFIED:\n        wrapper = classes[name]\n        assert wrapper.license == \"MIT\"\n        assert wrapper.homepage.startswith(\"https://github.com/projectdiscovery/\")\n        assert effective[name][\"release_support\"] == \"bundled\"\n",
    )

    path = ROOT / "tests" / "test_release_surface.py"
    replace_once(
        path,
        "    classes = ToolWrapperFactory(ROOT / \"tools_config.json\").load()\n    assert set(classes) == CERTIFIED\n    assert all(cls.requires_scope for cls in classes.values())\n    manifest = json.loads((ROOT / \"installer\" / \"tools-manifest.json\").read_text(encoding=\"utf-8\"))\n    provided = {alias for entry in manifest[\"tools\"] for alias in entry[\"provides\"]}\n    assert provided == set(classes)\n",
        "    classes = ToolWrapperFactory(ROOT / \"tools_config.json\").load()\n    assert len(classes) == 137\n    assert CERTIFIED.issubset(classes)\n    assert all(cls.requires_scope for cls in classes.values())\n    manifest = json.loads((ROOT / \"installer\" / \"tools-manifest.json\").read_text(encoding=\"utf-8\"))\n    provided = {alias for entry in manifest[\"tools\"] for alias in entry[\"provides\"]}\n    assert provided == CERTIFIED\n",
    )

    path = ROOT / "tests" / "test_server_release.py"
    replace_once(path, "CERTIFIED = {\"subfinder\", \"dnsx\", \"httpx\", \"naabu\", \"katana\", \"nuclei\"}\n", "CERTIFIED = {\"subfinder\", \"dnsx\", \"httpx\", \"naabu\", \"katana\", \"nuclei\"}\nCATALOG_COUNT = 137\n")
    replace_once(path, "    assert health_json[\"release_certified_tools\"] == len(CERTIFIED)\n", "    assert health_json[\"integrations_total\"] == CATALOG_COUNT\n    assert health_json[\"windows_certified_tools\"] == len(CERTIFIED)\n")
    replace_once(path, "    assert integrations[\"tools\"][\"active\"] == len(CERTIFIED)\n", "    assert integrations[\"tools\"][\"active\"] == CATALOG_COUNT\n    assert integrations[\"tools\"][\"catalog\"] == CATALOG_COUNT\n    assert integrations[\"tools\"][\"windows_certified\"] == len(CERTIFIED)\n")
    replace_once(path, "    assert {entry[\"name\"] for entry in tools} == CERTIFIED\n", "    assert len(tools) == CATALOG_COUNT\n    assert CERTIFIED.issubset({entry[\"name\"] for entry in tools})\n")


def main() -> int:
    migrate_registry()
    migrate_wrapper()
    migrate_server()
    migrate_audit()
    migrate_tests()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
