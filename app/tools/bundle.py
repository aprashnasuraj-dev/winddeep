"""Portable offline bundle export/import for provisioned Windeep runtimes."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

import zstandard as zstd


class BundleError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _container_runtime() -> str | None:
    return shutil.which("docker") or shutil.which("podman")


def _safe_extract(tar: tarfile.TarFile, destination: Path) -> None:
    """Extract regular files/directories only after canonical path validation."""
    root = destination.resolve()
    members = tar.getmembers()
    for member in members:
        target = (root / member.name).resolve()
        if not target.is_relative_to(root):
            raise BundleError(f"unsafe archive path: {member.name}")
        if member.issym() or member.islnk():
            raise BundleError(f"links are not allowed in Windeep bundles: {member.name}")
        if not (member.isdir() or member.isfile()):
            raise BundleError(f"unsupported archive member type: {member.name}")
    for member in members:
        target = (root / member.name).resolve()
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        source = tar.extractfile(member)
        if source is None:
            raise BundleError(f"archive member has no file payload: {member.name}")
        with source, target.open("wb") as output:
            shutil.copyfileobj(source, output)


def export_bundle(tools_dir: str | Path, output: str | Path, *, container_image: str = "winddeep/tools:v3") -> dict[str, Any]:
    source = Path(tools_dir).resolve()
    destination = Path(output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not source.exists():
        raise BundleError(f"tools directory does not exist: {source}")

    with tempfile.TemporaryDirectory(prefix="windeep-bundle-") as temp_raw:
        temp = Path(temp_raw)
        staged_tools = temp / "tools"
        shutil.copytree(source, staged_tools, dirs_exist_ok=True)
        runtime = _container_runtime()
        image_file: Path | None = None
        if runtime:
            inspect = subprocess.run([runtime, "image", "inspect", container_image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if inspect.returncode == 0:
                image_file = temp / "container-image.tar"
                saved = subprocess.run([runtime, "save", "-o", str(image_file), container_image], check=False)
                if saved.returncode != 0:
                    raise BundleError(f"failed to export container image {container_image}")

        files: dict[str, str] = {}
        for path in sorted(item for item in temp.rglob("*") if item.is_file() and item.name != "bundle-manifest.json"):
            files[str(path.relative_to(temp)).replace("\\", "/")] = _sha256(path)
        manifest = {"schema": "windeep.bundle.v4", "container_image": container_image if image_file else None, "files": files}
        (temp / "bundle-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        tar_path = temp / "bundle.tar"
        with tarfile.open(tar_path, "w") as tar:
            tar.add(temp / "bundle-manifest.json", arcname="bundle-manifest.json")
            tar.add(staged_tools, arcname="tools", recursive=True)
            if image_file:
                tar.add(image_file, arcname="container-image.tar")
        compressor = zstd.ZstdCompressor(level=10, threads=-1)
        with tar_path.open("rb") as src, destination.open("wb") as dst:
            compressor.copy_stream(src, dst)
    return {"output": str(destination), "sha256": _sha256(destination), "files": len(files), "container_image": manifest["container_image"]}


def import_bundle(bundle: str | Path, tools_dir: str | Path, *, load_container: bool = True) -> dict[str, Any]:
    archive = Path(bundle).resolve()
    destination = Path(tools_dir).resolve()
    if not archive.is_file():
        raise BundleError(f"bundle not found: {archive}")
    destination.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="windeep-bundle-import-") as temp_raw:
        temp = Path(temp_raw)
        tar_path = temp / "bundle.tar"
        decompressor = zstd.ZstdDecompressor()
        with archive.open("rb") as src, tar_path.open("wb") as dst:
            decompressor.copy_stream(src, dst)
        extract_root = temp / "extract"
        extract_root.mkdir()
        with tarfile.open(tar_path, "r") as tar:
            _safe_extract(tar, extract_root)
        manifest_path = extract_root / "bundle-manifest.json"
        if not manifest_path.is_file():
            raise BundleError("bundle manifest is missing")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema") != "windeep.bundle.v4" or not isinstance(manifest.get("files"), dict):
            raise BundleError("unsupported bundle manifest")
        verified_files = 0
        for relative, expected in manifest["files"].items():
            path = (extract_root / str(relative)).resolve()
            if not path.is_relative_to(extract_root.resolve()) or not path.is_file():
                raise BundleError(f"bundle file missing: {relative}")
            actual = _sha256(path)
            if actual != str(expected):
                raise BundleError(f"bundle checksum mismatch: {relative}")
            verified_files += 1
        staged_tools = extract_root / "tools"
        if staged_tools.exists():
            shutil.copytree(staged_tools, destination, dirs_exist_ok=True)

        container_loaded = False
        image_tar = extract_root / "container-image.tar"
        runtime = _container_runtime()
        if load_container and image_tar.is_file() and runtime:
            loaded = subprocess.run([runtime, "load", "-i", str(image_tar)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
            if loaded.returncode != 0:
                raise BundleError(f"container image import failed: {(loaded.stdout or '')[-2000:]}")
            container_loaded = True
    return {
        "bundle": str(archive),
        "sha256": _sha256(archive),
        "imported_to": str(destination),
        "verified": True,
        "verified_files": verified_files,
        "container_loaded": container_loaded,
    }
