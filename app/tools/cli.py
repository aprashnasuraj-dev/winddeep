"""Command-line entry points for Windeep v4 runtime management."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from app.tools.backends import backend_capabilities
from app.tools.bundle import export_bundle, import_bundle
from app.tools.doctor import doctor, render_text
from app.tools.remote_worker import run_worker


def _root() -> Path:
    configured = os.getenv("WINDEEP_APP_ROOT", "").strip()
    return Path(configured).resolve() if configured else Path(__file__).resolve().parents[2]


def _confirm(message: str, *, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        return False
    answer = input(f"{message} [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="winddeep", description="Windeep v4 runtime management")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor_parser = sub.add_parser("doctor", help="detect runtime tiers and optionally heal missing integrations")
    doctor_parser.add_argument("--heal", action="store_true", help="provision declared dependencies and build the tools container")
    doctor_parser.add_argument("--yes", action="store_true", help="approve provisioning without an interactive prompt")
    doctor_parser.add_argument("--backends", action="store_true", help="show backend/toolchain availability and exit")
    doctor_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    doctor_parser.add_argument("--no-probe", action="store_true", help="skip non-invasive liveness probes")

    bundle = sub.add_parser("bundle", help="export/import an offline provisioned runtime")
    bundle_sub = bundle.add_subparsers(dest="bundle_command", required=True)
    export = bundle_sub.add_parser("export", help="export tools, cache and optional OCI image")
    export.add_argument("output")
    export.add_argument("--image", default="winddeep/tools:v3")
    imp = bundle_sub.add_parser("import", help="import and verify an offline bundle")
    imp.add_argument("bundle")
    imp.add_argument("--no-container", action="store_true")

    worker = sub.add_parser("remote-worker", help="run the authenticated host-specific execution agent")
    worker.add_argument("--host", default="127.0.0.1")
    worker.add_argument("--port", type=int, default=7441)
    worker.add_argument("--token", default=os.getenv("WINDEEP_REMOTE_WORKER_TOKEN", ""))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    root = _root()
    registry = root / "tools_config.json"
    tools_dir = root / "tools"

    if args.command == "doctor":
        if args.backends:
            payload = backend_capabilities()
            print(json.dumps(payload, indent=2, sort_keys=True) if args.json else "\n".join(f"{key}: {'available' if value else 'missing'}" for key, value in payload.items()))
            return 0
        consent = False
        if args.heal:
            consent = _confirm(
                "Doctor --heal may invoke go/pipx/cargo/npm/OS package managers and build the declared OCI tools image. Continue?",
                yes=args.yes,
            )
            if not consent:
                print("Healing cancelled: explicit provisioning consent was not granted.", file=sys.stderr)
                return 2
        report = doctor(registry, tools_dir=tools_dir, heal=args.heal, consent=consent, probe=not args.no_probe)
        print(json.dumps(report, indent=2, sort_keys=True, default=str) if args.json else render_text(report))
        return 0 if report["unavailable"] == 0 else 3

    if args.command == "bundle":
        if args.bundle_command == "export":
            result = export_bundle(tools_dir, args.output, container_image=args.image)
        else:
            result = import_bundle(args.bundle, tools_dir, load_container=not args.no_container)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "remote-worker":
        if not args.token:
            print("remote-worker requires --token or WINDEEP_REMOTE_WORKER_TOKEN", file=sys.stderr)
            return 2
        run_worker(registry, tools_dir, token=args.token, host=args.host, port=args.port)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
