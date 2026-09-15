"""Dynamic external-tool wrapper factory for Windeep.

Wrappers execute binaries without a shell, validate structured inputs with
Pydantic, support argv and stdin-oriented CLIs, enforce bounded retries/timeouts,
and normalize parser output into the unified :class:`Finding` model. Registry
configuration may be split into included JSON files for maintainability.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, create_model

from app.tools import builtin_integrations


class Finding(BaseModel):
    """Normalized external-tool result consumed by database, UI, and Brain."""

    model_config = ConfigDict(extra="allow")

    title: str
    severity: str = "info"
    vuln_type: str = "informational"
    tool: str
    endpoint: str | None = None
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


Parser = Callable[[str, str, str], list[Finding]]


def _line_parser(raw: str, tool: str, target: str) -> list[Finding]:
    return [
        Finding(
            title=line,
            severity="info",
            vuln_type="tool_output",
            tool=tool,
            endpoint=target,
            description="Normalized line emitted by external tool.",
            evidence={"raw": line},
            confidence=0.3,
        )
        for line in (item.strip() for item in raw.splitlines())
        if line
    ]


def _jsonl_parser(raw: str, tool: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            findings.append(
                Finding(
                    title=line.strip(),
                    severity="info",
                    vuln_type="tool_output",
                    tool=tool,
                    endpoint=target,
                    description="Non-JSON diagnostic line emitted alongside structured output.",
                    evidence={"raw": line, "line_number": line_number},
                    confidence=0.2,
                )
            )
            continue
        if not isinstance(item, dict):
            item = {"value": item}
        try:
            confidence = float(item.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        findings.append(
            Finding(
                title=str(
                    item.get("title")
                    or item.get("name")
                    or item.get("host")
                    or item.get("url")
                    or "Tool finding"
                ),
                severity=str(item.get("severity") or "info").lower(),
                vuln_type=str(item.get("vuln_type") or item.get("type") or "tool_output"),
                tool=tool,
                endpoint=str(item.get("endpoint") or item.get("url") or item.get("host") or target),
                description=str(item.get("description") or ""),
                evidence=item,
                confidence=max(0.0, min(1.0, confidence)),
            )
        )
    return findings


_BUILTIN_PARSERS: dict[str, Parser] = {"lines": _line_parser, "jsonl": _jsonl_parser}
_TYPE_MAP: dict[str, Any] = {
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "list[str]": list[str],
    "dict": dict[str, Any],
}


class ToolExecutionError(RuntimeError):
    """Raised when an external tool cannot complete successfully."""


class ToolWrapperBase:
    """Base implementation inherited by dynamically generated wrappers."""

    tool_name: ClassVar[str]
    binary: ClassVar[str]
    args_template: ClassVar[tuple[str, ...]]
    stdin_template: ClassVar[str | None] = None
    input_schema: ClassVar[type[BaseModel]]
    output_parser: ClassVar[Parser]
    timeout: ClassVar[float]
    retries: ClassVar[int]
    rate_limit: ClassVar[float]
    category: ClassVar[str] = "uncategorized"
    description: ClassVar[str] = ""
    requires_scope: ClassVar[bool] = False
    required_env: ClassVar[tuple[str, ...]] = ()
    adapter_kind: ClassVar[str] = "process"
    target_types: ClassVar[tuple[str, ...]] = ()
    scan_default: ClassVar[bool] = True

    def __init__(
        self,
        *,
        tools_dir: str | Path = "tools",
        scope_validator: Callable[[str], bool] | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.tools_dir = Path(tools_dir)
        self.scope_validator = scope_validator
        self.environment = {**os.environ, **dict(environment or {})}
        self._rate_lock = asyncio.Lock()
        self._last_started = 0.0

    def resolve_binary(self) -> Path | None:
        """Resolve a configured executable from ``tools/`` first, then ``PATH``."""
        env_key = "WINDEEP_TOOL_" + "".join(ch if ch.isalnum() else "_" for ch in self.tool_name.upper()) + "_BINARY"
        configured = Path(self.environment.get(env_key) or self.binary)
        if configured.is_absolute() and configured.is_file():
            return configured
        local = self.tools_dir / configured
        candidates = [local]
        if not local.suffix:
            candidates.extend(local.with_suffix(suffix) for suffix in (".exe", ".cmd", ".bat", ".ps1", ".py"))
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        found = shutil.which(self.binary)
        return Path(found).resolve() if found else None

    def validate_installed(self) -> bool:
        """Return whether this integration has a runnable local/built-in path."""
        if builtin_integrations.supports(self.tool_name):
            return not self.missing_environment()
        return self.resolve_binary() is not None

    def missing_environment(self) -> tuple[str, ...]:
        """Return required environment-variable names that are not configured."""
        required = (*self.required_env, *builtin_integrations.required_env(self.tool_name))
        return tuple(sorted({name for name in required if not self.environment.get(name)}))

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        """Normalize raw standard output through the configured parser."""
        return self.output_parser(raw, self.tool_name, target)

    async def run(
        self,
        target: str,
        options: Mapping[str, Any] | None = None,
    ) -> list[Finding]:
        """Validate scope/input, execute without a shell, and normalize output."""
        try:
            if self.requires_scope and self.scope_validator is None:
                raise PermissionError(f"{self.tool_name} requires an explicit scope validator before execution")
            if self.scope_validator is not None and not self.scope_validator(target):
                raise PermissionError(f"target is outside configured scope: {target}")
            missing_env = self.missing_environment()
            if missing_env:
                raise ToolExecutionError(
                    f"{self.tool_name} requires environment variable(s): {', '.join(missing_env)}"
                )
            validated = self.input_schema.model_validate(
                {"target": target, **dict(options or {})}
            ).model_dump()
            if builtin_integrations.supports(self.tool_name):
                rows = await builtin_integrations.run(self.tool_name, target, environment=self.environment)
                return [Finding.model_validate(row) for row in rows]

            rendered_args = self._render_args(validated)
            binary = self.resolve_binary()
            if binary is None:
                wsl = shutil.which("wsl.exe") if os.name == "nt" else None
                if wsl:
                    argv = [wsl, "--", self.binary, *rendered_args]
                else:
                    raise FileNotFoundError(
                        f"tool binary not installed: {self.binary}; install it on PATH/tools, set WINDEEP_TOOL_{self.tool_name.upper().replace('-', '_')}_BINARY, or install it in WSL"
                    )
            else:
                argv = [str(binary), *rendered_args]
            stdin_data = self._render_stdin(validated)
            last_error: BaseException | None = None
            for attempt in range(self.retries + 1):
                try:
                    await self._respect_rate_limit()
                    if stdin_data is None:
                        stdout, stderr, returncode = await self._run_process(argv)
                    else:
                        stdout, stderr, returncode = await self._run_process(argv, stdin_data)
                    if returncode != 0:
                        raise ToolExecutionError(
                            f"{self.tool_name} exited with code {returncode}: {stderr.strip()[:2000]}"
                        )
                    return self.parse_output(stdout, target)
                except asyncio.CancelledError:
                    raise
                except (ToolExecutionError, asyncio.TimeoutError, OSError) as exc:
                    last_error = exc
                    if attempt >= self.retries:
                        break
                    await asyncio.sleep(min(8.0, 0.5 * (2**attempt)))
            raise ToolExecutionError(
                f"{self.tool_name} failed after {self.retries + 1} attempt(s): {last_error}"
            )
        except asyncio.CancelledError:
            raise

    def _render_args(self, values: Mapping[str, Any]) -> list[str]:
        strings = self._string_values(values)
        return [token.format_map(strings) for token in self.args_template]

    def _render_stdin(self, values: Mapping[str, Any]) -> bytes | None:
        if self.stdin_template is None:
            return None
        return self.stdin_template.format_map(self._string_values(values)).encode("utf-8")

    @staticmethod
    def _string_values(values: Mapping[str, Any]) -> dict[str, str]:
        return {
            key: json.dumps(value, separators=(",", ":")) if isinstance(value, (dict, list)) else str(value)
            for key, value in values.items()
        }

    async def _respect_rate_limit(self) -> None:
        try:
            if self.rate_limit <= 0:
                return
            interval = 1.0 / self.rate_limit
            async with self._rate_lock:
                delay = interval - (time.monotonic() - self._last_started)
                if delay > 0:
                    await asyncio.sleep(delay)
                self._last_started = time.monotonic()
        except asyncio.CancelledError:
            raise

    async def _run_process(
        self,
        argv: Sequence[str],
        stdin_data: bytes | None = None,
    ) -> tuple[str, str, int]:
        """Run one process with bounded lifetime and cancellation cleanup."""
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0)
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=creationflags,
            env=self.environment,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(stdin_data), timeout=self.timeout)
        except asyncio.CancelledError:
            process.kill()
            await process.wait()
            raise
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            process.returncode,
        )


class ToolWrapperFactory:
    """Load one modular registry and generate concrete wrapper classes at runtime."""

    def __init__(
        self,
        config_path: str | Path,
        *,
        parsers: Mapping[str, Parser] | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.parsers = {**_BUILTIN_PARSERS, **dict(parsers or {})}
        self._classes: dict[str, type[ToolWrapperBase]] = {}

    def load(self) -> dict[str, type[ToolWrapperBase]]:
        """Read root/included JSON configuration and return generated classes."""
        definitions = self._load_definitions(self.config_path.resolve(), set())
        if not definitions:
            raise ValueError("tools_config.json does not define any tools")
        generated = {
            name: self._create_wrapper(name, definition)
            for name, definition in definitions.items()
        }
        self._classes = generated
        return dict(generated)

    def get(self, name: str) -> type[ToolWrapperBase]:
        """Return one generated class, loading configuration on first use."""
        if not self._classes:
            self.load()
        try:
            return self._classes[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool wrapper: {name}") from exc

    def _load_definitions(
        self,
        path: Path,
        visited: set[Path],
    ) -> dict[str, Mapping[str, Any]]:
        if path in visited:
            raise ValueError(f"cyclic tools_config include: {path}")
        visited.add(path)
        config = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError(f"tool config must be an object: {path}")
        combined: dict[str, Mapping[str, Any]] = {}
        tools = config.get("tools", {})
        if not isinstance(tools, dict):
            raise ValueError(f"'tools' must be an object: {path}")
        for name, definition in tools.items():
            if not isinstance(definition, dict):
                raise ValueError(f"tool definition must be an object: {name}")
            combined[str(name)] = definition

        includes = config.get("includes", [])
        if not isinstance(includes, list) or not all(isinstance(item, str) for item in includes):
            raise ValueError(f"'includes' must be a list of paths: {path}")
        root = self.config_path.resolve().parent
        for include in includes:
            include_path = (root / include).resolve()
            if not include_path.is_relative_to(root):
                raise ValueError(f"tool config include escapes registry root: {include}")
            for name, definition in self._load_definitions(include_path, visited).items():
                if name in combined:
                    raise ValueError(f"duplicate tool definition: {name}")
                combined[name] = definition
        visited.remove(path)
        return combined

    def _create_wrapper(
        self,
        name: str,
        definition: Mapping[str, Any],
    ) -> type[ToolWrapperBase]:
        binary = str(definition.get("binary") or name)
        args = definition.get("args", ["{target}"])
        if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
            raise ValueError(f"tool args must be a list of strings: {name}")
        stdin_template = definition.get("stdin")
        if stdin_template is not None and not isinstance(stdin_template, str):
            raise ValueError(f"tool stdin must be a string template: {name}")
        parser_name = str(definition.get("parser", "lines"))
        if parser_name not in self.parsers:
            raise ValueError(f"unknown parser '{parser_name}' for tool '{name}'")
        required_env = definition.get("required_env", [])
        if not isinstance(required_env, list) or not all(isinstance(item, str) for item in required_env):
            raise ValueError(f"required_env must be a list of strings: {name}")
        input_model = self._build_input_model(name, definition.get("input_schema", {}))
        target_types_raw = definition.get("target_types", [])
        if not isinstance(target_types_raw, list) or not all(isinstance(item, str) for item in target_types_raw):
            raise ValueError(f"target_types must be a list of strings: {name}")
        class_name = "".join(part.capitalize() for part in name.replace("-", "_").split("_")) + "Wrapper"
        return type(
            class_name,
            (ToolWrapperBase,),
            {
                "tool_name": name,
                "binary": binary,
                "args_template": tuple(args),
                "stdin_template": stdin_template,
                "input_schema": input_model,
                "output_parser": staticmethod(self.parsers[parser_name]),
                "timeout": float(definition.get("timeout", 120.0)),
                "retries": int(definition.get("retries", 1)),
                "rate_limit": float(definition.get("rate_limit", 0.0)),
                "category": str(definition.get("category") or "uncategorized"),
                "description": str(definition.get("description") or ""),
                "requires_scope": bool(definition.get("requires_scope", False)),
                "required_env": tuple(required_env),
                "adapter_kind": "builtin" if builtin_integrations.supports(name) else "process",
                "target_types": tuple(target_types_raw),
                "scan_default": bool(definition.get("scan_default", True)),
                "__module__": __name__,
            },
        )

    @staticmethod
    def _build_input_model(name: str, schema: Any) -> type[BaseModel]:
        if not isinstance(schema, dict):
            raise ValueError(f"input_schema must be an object: {name}")
        fields: dict[str, tuple[Any, Any]] = {"target": (str, ...)}
        for field_name, definition in schema.items():
            if not isinstance(definition, dict):
                raise ValueError(f"input field must be an object: {name}.{field_name}")
            type_name = str(definition.get("type", "str"))
            if type_name not in _TYPE_MAP:
                raise ValueError(f"unsupported input type '{type_name}' for {name}.{field_name}")
            field_type = _TYPE_MAP[type_name]
            if definition.get("required", False):
                default: Any = ...
            else:
                default = definition.get("default", None)
                field_type = field_type | None
            fields[field_name] = (field_type, default)
        return create_model(
            f"{name.title().replace('_', '')}Input",
            __config__=ConfigDict(extra="forbid"),
            **fields,
        )
