"""Dynamic tool wrapper factory for Windeep v4.

Wrappers validate scope/input and normalize output, while execution is delegated
to an ordered backend resolver. A tool may be served natively, from Windeep's
provisioned cache, a container, WSL, an authenticated remote worker, or a
pure-Python builtin fallback without changing the public tool name.
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
from app.tools.backends import BackendUnavailableError, ExecutionResolver
from app.tools.provisioning import provisioned_candidates, restore_cached_binary


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
            description="Normalized line emitted by tool integration.",
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
                title=str(item.get("title") or item.get("name") or item.get("host") or item.get("url") or "Tool finding"),
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
_ALLOWED_RUNTIME_STRATEGIES = {"process", "builtin", "container", "wsl", "remote", "auto"}


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot complete successfully on any eligible backend."""


class ToolCancelledError(ToolExecutionError):
    """Raised when a user-requested scan stop terminates tool execution."""


class ToolWrapperBase:
    """Base implementation inherited by dynamically generated wrappers."""

    tool_name: ClassVar[str]
    execution_name: ClassVar[str]
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
    adapter_kind: ClassVar[str] = "auto"
    target_types: ClassVar[tuple[str, ...]] = ()
    scan_default: ClassVar[bool] = True
    runtime_strategy: ClassVar[str] = "auto"
    execution_preference: ClassVar[tuple[str, ...]] = ()
    provision: ClassVar[dict[str, Any]] = {}
    container_image: ClassVar[str] = ""
    container_command: ClassVar[str] = ""
    container_runtime: ClassVar[str] = ""
    requires_host: ClassVar[str] = ""
    builtin_fallback: ClassVar[str] = ""
    alias_to: ClassVar[str] = ""
    probe: ClassVar[tuple[str, ...]] = ()

    def __init__(
        self,
        *,
        tools_dir: str | Path = "tools",
        scope_validator: Callable[[str], bool] | None = None,
        environment: Mapping[str, str] | None = None,
        cancel_check: Callable[[], bool] | None = None,
        resolver: ExecutionResolver | None = None,
    ) -> None:
        self.tools_dir = Path(tools_dir)
        self.scope_validator = scope_validator
        self.environment = {**os.environ, **dict(environment or {})}
        self.cancel_check = cancel_check
        self.resolver = resolver or ExecutionResolver()
        self.current_target = ""
        self._rate_lock = asyncio.Lock()
        self._last_started = 0.0

    def _binary_env_key(self) -> str:
        return "WINDEEP_TOOL_" + "".join(ch if ch.isalnum() else "_" for ch in self.tool_name.upper()) + "_BINARY"

    def resolve_local_binary(self) -> Path | None:
        """Resolve only explicitly local/tool-dir/PATH executables."""
        execution_binary = str(self.environment.get(self._binary_env_key()) or self.binary or self.execution_name)
        configured = Path(execution_binary)
        if configured.is_absolute() and configured.is_file():
            return configured.resolve()
        local = self.tools_dir / configured
        candidates = [local]
        if not local.suffix:
            candidates.extend(local.with_suffix(suffix) for suffix in (".exe", ".cmd", ".bat", ".ps1", ".py"))
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        for name in (execution_binary, self.execution_name):
            found = shutil.which(name)
            if found:
                return Path(found).resolve()
        return None

    def resolve_provisioned_binary(self) -> Path | None:
        for candidate in provisioned_candidates(self):
            if candidate.is_file():
                return candidate.resolve()
        restored = restore_cached_binary(self)
        if restored is not None and restored.is_file():
            return restored
        return None

    def resolve_binary(self) -> Path | None:
        """Compatibility helper: local first, then Windeep-provisioned binary."""
        return self.resolve_local_binary() or self.resolve_provisioned_binary()

    def runtime_status(self) -> dict[str, Any]:
        status = self.resolver.status(self)
        status.update(
            {
                "execution_name": self.execution_name,
                "alias_to": self.alias_to or None,
                "requires_host": self.requires_host or None,
                "has_provision_recipe": bool(self.provision),
                "container_image": self.container_image or None,
                "builtin_fallback": self.builtin_fallback or None,
            }
        )
        return status

    def validate_installed(self) -> bool:
        """Return whether at least one backend currently resolves."""
        return self.runtime_status()["tier"] != "unavailable"

    def missing_environment(self) -> tuple[str, ...]:
        """Return credentials required by the tool or builtin fallback."""
        adapter = self.builtin_fallback or self.execution_name or self.tool_name
        required = (*self.required_env, *builtin_integrations.required_env(adapter))
        return tuple(sorted({name for name in required if not self.environment.get(name)}))

    def parse_output(self, raw: str, target: str, *, builtin: bool = False) -> list[Finding]:
        parser = _jsonl_parser if builtin else self.output_parser
        return parser(raw, self.tool_name, target)

    def _annotate_findings(self, findings: list[Finding], *, backend: Any, attempted: list[dict[str, str]]) -> list[Finding]:
        for finding in findings:
            evidence = dict(finding.evidence or {})
            evidence["backend"] = backend.key
            evidence["backend_tier"] = backend.tier
            if self.alias_to:
                evidence["served_by"] = self.execution_name
                evidence["deprecated_alias"] = True
            if attempted:
                evidence["backend_fallbacks"] = list(attempted)
            finding.evidence = evidence
            finding.tool = self.tool_name
        return findings

    async def run(self, target: str, options: Mapping[str, Any] | None = None) -> list[Finding]:
        """Validate, resolve an execution backend, execute, then normalize output."""
        if self._cancel_requested():
            raise ToolCancelledError(f"{self.tool_name} cancelled before execution")
        if self.requires_scope and self.scope_validator is None:
            raise PermissionError(f"{self.tool_name} requires an explicit scope validator before execution")
        if self.scope_validator is not None and not self.scope_validator(target):
            raise PermissionError(f"target is outside configured scope: {target}")

        validated = self.input_schema.model_validate({"target": target, **dict(options or {})}).model_dump()
        rendered_args = self._render_args(validated)
        stdin_data = self._render_stdin(validated)
        attempted: list[dict[str, str]] = []
        self.current_target = target
        try:
            available = []
            for key in self.resolver.ordered_keys(self):
                backend = self.resolver.backends[key]
                if backend.can_run(self):
                    available.append(backend)
            if not available:
                raise BackendUnavailableError(
                    f"no execution backend available for {self.tool_name}; doctor --heal can provision declared dependencies"
                )

            last_error: BaseException | None = None
            for backend in available:
                for attempt in range(self.retries + 1):
                    try:
                        if self._cancel_requested():
                            raise ToolCancelledError(f"{self.tool_name} cancelled by user")
                        await self._respect_rate_limit()
                        stdout, stderr, returncode = await self._await_with_cancel(
                            backend.exec(self, rendered_args, stdin_data, self.timeout),
                            timeout=self.timeout + 2.0,
                        )
                        if returncode != 0:
                            raise ToolExecutionError(
                                f"{self.tool_name} via {backend.key} exited with code {returncode}: {stderr.strip()[:2000]}"
                            )
                        findings = self.parse_output(stdout, target, builtin=backend.key == "builtin_fallback")
                        return self._annotate_findings(findings, backend=backend, attempted=attempted)
                    except (ToolCancelledError, asyncio.CancelledError):
                        raise
                    except (ToolExecutionError, BackendUnavailableError, asyncio.TimeoutError, OSError, httpx.HTTPError if False else OSError) as exc:  # type: ignore[misc]
                        last_error = exc
                        if attempt < self.retries:
                            await asyncio.sleep(min(8.0, 0.5 * (2**attempt)))
                            continue
                        attempted.append({"backend": backend.key, "error": str(exc)[:1000]})
                        break
            raise ToolExecutionError(
                f"{self.tool_name} failed across {len(available)} backend(s): {last_error}; "
                f"attempted={', '.join(item['backend'] for item in attempted)}"
            )
        finally:
            self.current_target = ""

    def _cancel_requested(self) -> bool:
        if self.cancel_check is None:
            return False
        try:
            return bool(self.cancel_check())
        except Exception:
            return False

    async def _await_with_cancel(self, awaitable: Any, *, timeout: float) -> Any:
        task = asyncio.create_task(awaitable)
        started = time.monotonic()
        try:
            while True:
                if self._cancel_requested():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise ToolCancelledError(f"{self.tool_name} cancelled by user")
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise asyncio.TimeoutError
                done, _pending = await asyncio.wait({task}, timeout=min(0.2, remaining))
                if task in done:
                    return await task
        except asyncio.CancelledError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
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
        if self.rate_limit <= 0:
            return
        interval = 1.0 / self.rate_limit
        async with self._rate_lock:
            delay = interval - (time.monotonic() - self._last_started)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_started = time.monotonic()

    async def _run_process(self, argv: Sequence[str], stdin_data: bytes | None = None) -> tuple[str, str, int]:
        """Legacy direct-process helper retained for compatibility tests."""
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.environment,
        )
        try:
            stdout, stderr = await self._await_with_cancel(process.communicate(stdin_data), timeout=self.timeout)
        except (ToolCancelledError, asyncio.CancelledError, asyncio.TimeoutError):
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        return stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"), int(process.returncode or 0)


class ToolWrapperFactory:
    """Load modular registries plus v4 runtime overlays into wrapper classes."""

    def __init__(self, config_path: str | Path, *, parsers: Mapping[str, Parser] | None = None) -> None:
        self.config_path = Path(config_path)
        self.parsers = {**_BUILTIN_PARSERS, **dict(parsers or {})}
        self._classes: dict[str, type[ToolWrapperBase]] = {}

    def load(self) -> dict[str, type[ToolWrapperBase]]:
        definitions = self._load_definitions(self.config_path.resolve(), set())
        if not definitions:
            raise ValueError("tools_config.json does not define any tools")
        defaults, overlays, aliases = self._load_runtime_overlays()
        merged: dict[str, Mapping[str, Any]] = {}
        for name, original in definitions.items():
            alias_to = str(aliases.get(name) or "")
            base = dict(definitions.get(alias_to, original)) if alias_to else dict(original)
            if alias_to:
                base["category"] = original.get("category", base.get("category"))
                base["description"] = original.get("description", base.get("description"))
                base["target_types"] = original.get("target_types", base.get("target_types", []))
                base["alias_to"] = alias_to
                base["execution_name"] = alias_to
            else:
                base["execution_name"] = name
            base = {**defaults, **base, **dict(overlays.get(name, {}))}
            if alias_to:
                base["alias_to"] = alias_to
                base["execution_name"] = alias_to
            merged[name] = base
        generated = {name: self._create_wrapper(name, definition) for name, definition in merged.items()}
        self._classes = generated
        return dict(generated)

    def get(self, name: str) -> type[ToolWrapperBase]:
        if not self._classes:
            self.load()
        try:
            return self._classes[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool wrapper: {name}") from exc

    def _load_runtime_overlays(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        root = self.config_path.resolve().parent
        root_config = json.loads(self.config_path.resolve().read_text(encoding="utf-8"))
        relative = str(root_config.get("runtime_overlays") or "app/tools/config/v4_runtime.json")
        path = (root / relative).resolve()
        if not path.is_relative_to(root):
            raise ValueError("runtime_overlays escapes registry root")
        if not path.exists():
            return {"runtime_strategy": "auto"}, {}, {}
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("v4 runtime overlay must be an object")
        defaults = raw.get("defaults", {})
        tools = raw.get("tools", {})
        aliases = raw.get("aliases", {})
        if not isinstance(defaults, dict) or not isinstance(tools, dict) or not isinstance(aliases, dict):
            raise ValueError("v4 runtime overlay requires object defaults/tools/aliases")
        unknown = sorted(set(tools).difference(self._load_definitions(self.config_path.resolve(), set())))
        if unknown:
            # Overlay can be prepared ahead of a catalog addition, but it must not
            # mutate the active registry until that tool exists.
            tools = {name: value for name, value in tools.items() if name not in unknown}
        return dict(defaults), dict(tools), {str(k): str(v) for k, v in aliases.items()}

    def _load_definitions(self, path: Path, visited: set[Path]) -> dict[str, Mapping[str, Any]]:
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

    def _create_wrapper(self, name: str, definition: Mapping[str, Any]) -> type[ToolWrapperBase]:
        binary = str(definition.get("binary") or definition.get("execution_name") or name)
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
        target_types_raw = definition.get("target_types", [])
        if not isinstance(target_types_raw, list) or not all(isinstance(item, str) for item in target_types_raw):
            raise ValueError(f"target_types must be a list of strings: {name}")
        runtime_strategy = str(definition.get("runtime_strategy") or "auto").lower()
        if runtime_strategy not in _ALLOWED_RUNTIME_STRATEGIES:
            raise ValueError(f"invalid runtime_strategy '{runtime_strategy}' for {name}")
        preference = definition.get("execution_preference", [])
        if not isinstance(preference, list) or not all(isinstance(item, str) for item in preference):
            raise ValueError(f"execution_preference must be a list of strings: {name}")
        provision = definition.get("provision", {})
        if not isinstance(provision, dict):
            raise ValueError(f"provision must be an object: {name}")
        probe = definition.get("probe", [])
        if not isinstance(probe, list) or not all(isinstance(item, str) for item in probe):
            raise ValueError(f"probe must be a list of strings: {name}")
        input_model = self._build_input_model(name, definition.get("input_schema", {}))
        execution_name = str(definition.get("execution_name") or name)
        class_name = "".join(part.capitalize() for part in name.replace("-", "_").split("_")) + "Wrapper"
        return type(
            class_name,
            (ToolWrapperBase,),
            {
                "tool_name": name,
                "execution_name": execution_name,
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
                "adapter_kind": runtime_strategy,
                "target_types": tuple(target_types_raw),
                "scan_default": bool(definition.get("scan_default", True)),
                "runtime_strategy": runtime_strategy,
                "execution_preference": tuple(preference),
                "provision": dict(provision),
                "container_image": str(definition.get("container_image") or ""),
                "container_command": str(definition.get("container_command") or ""),
                "container_runtime": str(definition.get("container_runtime") or ""),
                "requires_host": str(definition.get("requires_host") or ""),
                "builtin_fallback": str(definition.get("builtin_fallback") or ""),
                "alias_to": str(definition.get("alias_to") or ""),
                "probe": tuple(probe),
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
