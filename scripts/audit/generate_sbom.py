"""Generate the release CycloneDX SBOM for Python and bundled tool assets."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="dist/SBOM.json")
    args = parser.parse_args()
    output = (ROOT / args.output).resolve() if not Path(args.output).is_absolute() else Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="windeep-sbom-") as tmp:
        base = Path(tmp) / "python-sbom.json"
        cmd = [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "environment",
            "--output-format",
            "JSON",
            "--output-file",
            str(base),
        ]
        completed = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if completed.returncode != 0:
            print(completed.stdout, file=sys.stderr)
            print(completed.stderr, file=sys.stderr)
            return completed.returncode
        bom = json.loads(base.read_text(encoding="utf-8"))

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    metadata = bom.setdefault("metadata", {})
    metadata["component"] = {
        "type": "application",
        "bom-ref": f"pkg:github/aprashnasuraj-dev/winddeep@{version}",
        "name": "Windeep",
        "version": version,
        "purl": f"pkg:github/aprashnasuraj-dev/winddeep@{version}",
    }

    manifest_path = ROOT / "installer" / "tools-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    components = bom.setdefault("components", [])
    for entry in manifest.get("tools", []):
        name = str(entry.get("name", "")).strip()
        tool_version = str(entry.get("version", "unknown")).strip() or "unknown"
        component = {
            "type": "application",
            "bom-ref": f"windeep-tool:{name}@{tool_version}",
            "name": name,
            "version": tool_version,
            "hashes": [{"alg": "SHA-256", "content": str(entry.get("sha256", "")).lower()}],
            "externalReferences": [{"type": "distribution", "url": str(entry.get("url", ""))}],
            "properties": [
                {"name": "windeep:destination", "value": str(entry.get("destination", ""))},
                {"name": "windeep:provides", "value": ",".join(entry.get("provides", [name]))},
            ],
        }
        components.append(component)

    output.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"SBOM written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
