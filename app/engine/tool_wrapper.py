"""Dynamic external-tool wrapper factory for Windeep.

Wrappers execute binaries without a shell, validate structured inputs with
Pydantic, enforce bounded retries/timeouts, and normalize parser output into a
single Finding model.
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

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model


class Finding(BaseModel):
    """Normalized tool finding consumed by database, UI, and AI layers."""

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
    for line in raw.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        findings.append(
            Finding(
                title=str(item.get("title") or item.get("name") or "Tool finding"),
                severity=str(item.get("severity") or "info").lower(),
                vuln_type=str(
                    item.get("vuln_type") or item.get("type") or "tool_output"
                ),
                tool=tool,
                endpoint=str(item.get("endpoint") or item.get("url") or target),
                description=str(item.get("description") or ""),
                evidence=item if isinstance(item, dict) else {"value": item},
                confidence=float(item.get("confidence", 0.5)),
            )
        )
    return findings


_BUILTIN_PARSERS: dict[str, Parser] = {
    "lines": _line_parser,
    "jsonl": _jsonl_parser,
}
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
    input_schema: ClassVar[type[BaseModel]]
    output_parser: ClassVar[Parser]
    timeout: ClassVar[float]
    retries: ClassVar[int]
    rate_limit: ClassVar[float]

    def __init__(
        self,
        *,
        tools_dir: str | Path = "tools",
        scope_validator: Callable[[str], bool] | None = None,
    ) -> None:
        self.tools_dir = Path(tools_dir)
        self.scope_validator = scope_validator
        self._rate_lock = asyncio.Lock()
        self._last_started = 0.0

    def resolve_binary(self) -> Path | None:
        """Resolve the configured binary from tools/ first, then PATH."""
        configured = Path(self.binary)
        if configured.is_absolute() and configured.is_file():
            return configured
        local = self.tools_dir / configured
        if local.is_file():
            return local.resolve()
        found = shutil.which(self.binary)
        return Path(found).resolve() if found else None

    def validate_installed(self) -> bool:
        """Return whether the wrapper's executable can be resolved."""
        return self.resolve_binary() is not None

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        """Normalize raw standard output through the configured parser."""
        return self.output_parser(raw, self.tool_name, target)

    async def run(
        self,
        target: str,
        options: Mapping[str, Any] | None = None,
    ) -> list[Finding]:
        """Validate inputs, execute the tool, and return normalized findings."""
        if self.scope_validator is not None and not self.scope_validator(target):
            raise PermissionError(
                f"target is outside configured scope: {target}"
            )
        binary = self.resolve_binary()
        if binary is None:
            raise FileNotFoundError(f"tool binary not installed: {self.binary}")

        values = {"target": target, **dict(options or {})}
        try:
            validated = self.input_schema.model_validate(values).model_dump()
        except ValidationError:
            raise
        argv = [str(binary), *self._render_args(validated)]

        last_error: BaseException | None = None
        for attempt in range(self.retries + 1):
            try:
                await self._respect_rate_limit()
                stdout, stderr, returncode = await self._run_process(argv)
                if returncode != 0:
                    raise ToolExecutionError(
                        f"{self.tool_name} exited with code {returncode}: "
                        f"{stderr.strip()[:2000]}"
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
            f"{self.tool_name} failed after {self.retries + 1} attempt(s): "
            f"{last_error}"
        )

    def _render_args(self, values: Mapping[str, Any]) -> list[str]:
        rendered: list[str] = []
        string_values = {
            key: json.dumps(value, separators=(",", ":"))
            if isinstance(value, (dict, list))
            else str(value)
            for key, value in values.items()
        }
        for token in self.args_template:
            rendered.append(token.format_map(string_values))
        return rendered

    async def _respect_rate_limit(self) -> None:
        if self.rate_limit <= 0:
            return
        interval = 1.0 / self.rate_limit
        async with self._rate_lock:
            now = time.monotonic()
            delay = interval - (now - self._last_started)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_started = time.monotonic()

    async def _run_process(
        self,
        argv: Sequence[str],
    ) -> tuple[str, str, int]:
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0)
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=creationflags,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )
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
    """Load tool definitions and generate concrete wrapper classes at runtime."""

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
        """Read JSON configuration and return generated wrapper classes."""
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        tools = config.get("tools")
        if not isinstance(tools, dict):
            raise ValueError(
                "tools_config.json must contain an object named 'tools'"
            )
        generated: dict[str, type[ToolWrapperBase]] = {}
        for name, definition in tools.items():
            if not isinstance(definition, dict):
                raise ValueError(f"tool definition must be an object: {name}")
            generated[name] = self._create_wrapper(name, definition)
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

    def _create_wrapper(
        self,
        name: str,
        definition: Mapping[str, Any],
    ) -> type[ToolWrapperBase]:
        binary = str(definition.get("binary") or name)
        args = definition.get("args", ["{target}"])
        if not isinstance(args, list) or not all(
            isinstance(value, str) for value in args
        ):
            raise ValueError(f"tool args must be a list of strings: {name}")
        parser_name = str(definition.get("parser", "lines"))
        if parser_name not in self.parsers:
            raise ValueError(
                f"unknown parser '{parser_name}' for tool '{name}'"
            )
        input_model = self._build_input_model(
            name, definition.get("input_schema", {})
        )
        class_name = (
            "".join(
                part.capitalize()
                for part in name.replace("-", "_").split("_")
            )
            + "Wrapper"
        )
        return type(
            class_name,
            (ToolWrapperBase,),
            {
                "tool_name": name,
                "binary": binary,
                "args_template": tuple(args),
                "input_schema": input_model,
                "output_parser": staticmethod(self.parsers[parser_name]),
                "timeout": float(definition.get("timeout", 120.0)),
                "retries": int(definition.get("retries", 1)),
                "rate_limit": float(definition.get("rate_limit", 0.0)),
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
                raise ValueError(
                    f"input field must be an object: {name}.{field_name}"
                )
            type_name = str(definition.get("type", "str"))
            if type_name not in _TYPE_MAP:
                raise ValueError(
                    f"unsupported input type '{type_name}' for "
                    f"{name}.{field_name}"
                )
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
