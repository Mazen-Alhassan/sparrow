"""Fetch and unpack package sources from PyPI.

Wheels are unpacked directly rather than installed. Installing 127 pinned packages from 2021 under
a 2026 interpreter fails on the first C extension, and the analysis only needs the `.py` files.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import tarfile
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .net import context

PYPI = "https://pypi.org/pypi/{name}/{version}/json"
USER_AGENT = "sparrow/0.1 (+https://github.com/)"
DEFAULT_CACHE = Path.home() / ".cache" / "sparrow" / "pkgs"


@dataclass
class Unpacked:
    name: str
    version: str
    root: Path
    kind: str            # wheel | sdist
    top_level: list[str]  # importable top-level names found on disk
    native: list[str]     # compiled extension files, the opaque boundary
    error: str = ""


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout, context=context()) as resp:
        return resp.read()


def _pick_artifact(files: list[dict]) -> dict | None:
    """Prefer a pure-python wheel, then any wheel, then an sdist.

    Platform wheels carry the same `.py` files as the pure ones, so a manylinux wheel on a mac is
    fine here. Only the compiled objects inside differ, and those are opaque either way.
    """
    if not any(not f.get("yanked") for f in files):
        # Every file was yanked, as happened to requests 2.32.0. A yanked release is still the
        # release the advisory names, so it is used rather than failing the verification.
        files = list(files)
    else:
        files = [f for f in files if not f.get("yanked")]
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    pure = [f for f in wheels if "-py3-none-any" in f["filename"] or "-py2.py3-none-any" in f["filename"]]
    if pure:
        return pure[0]
    if wheels:
        wheels.sort(key=lambda f: ("macosx" not in f["filename"], "arm64" not in f["filename"]))
        return wheels[0]
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    return sdists[0] if sdists else None


def _safe_extract_zip(blob: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for member in zf.namelist():
            target = (dest / member).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue  # path traversal in an archive; skip the member, keep the package
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def _safe_extract_tar(blob: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for member in tf.getmembers():
            if not (member.isfile() or member.isdir()):
                continue
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def _source_roots(root: Path, kind: str) -> list[Path]:
    """Directories under which top-level importable names live."""
    if kind == "wheel":
        return [root]
    inner = [d for d in root.iterdir() if d.is_dir()]
    base = inner[0] if len(inner) == 1 else root
    src = base / "src"
    return [src] if src.is_dir() else [base]


def _scan(root: Path, kind: str) -> tuple[list[str], list[str]]:
    top: set[str] = set()
    native: list[str] = []
    for base in _source_roots(root, kind):
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            if entry.name.endswith((".dist-info", ".data", ".egg-info")):
                continue
            if entry.is_dir() and (entry / "__init__.py").exists():
                top.add(entry.name)
            elif entry.is_dir() and any(entry.rglob("*.py")):
                top.add(entry.name)  # namespace package
            elif entry.suffix == ".py" and entry.stem != "setup":
                top.add(entry.stem)
    for ext in ("*.so", "*.pyd", "*.dylib"):
        native.extend(str(p.relative_to(root)) for p in root.rglob(ext))
    return sorted(top), sorted(native)


def fetch_one(name: str, version: str, cache: Path = DEFAULT_CACHE, force: bool = False) -> Unpacked:
    dest = cache / name / version
    marker = dest / ".sparrow-ok.json"
    if marker.exists() and not force:
        meta = json.loads(marker.read_text())
        return Unpacked(name, version, dest / "src", meta["kind"], meta["top_level"], meta["native"])
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        meta = json.loads(_get(PYPI.format(name=name, version=version)))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        return Unpacked(name, version, dest / "src", "", [], [], error=f"pypi metadata: {exc}")
    artifact = _pick_artifact(meta.get("urls", []))
    if artifact is None:
        return Unpacked(name, version, dest / "src", "", [], [], error="no wheel or sdist on pypi")
    try:
        blob = _get(artifact["url"], timeout=180)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        return Unpacked(name, version, dest / "src", "", [], [], error=f"download: {exc}")
    digest = artifact.get("digests", {}).get("sha256")
    if digest and hashlib.sha256(blob).hexdigest() != digest:
        return Unpacked(name, version, dest / "src", "", [], [], error="sha256 mismatch")
    src = dest / "src"
    src.mkdir(parents=True, exist_ok=True)
    kind = "wheel" if artifact["packagetype"] == "bdist_wheel" else "sdist"
    try:
        if artifact["filename"].endswith((".whl", ".zip")):
            _safe_extract_zip(blob, src)
        else:
            _safe_extract_tar(blob, src)
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        return Unpacked(name, version, src, kind, [], [], error=f"unpack: {exc}")
    top, native = _scan(src, kind)
    marker.write_text(json.dumps({"kind": kind, "top_level": top, "native": native, "file": artifact["filename"]}))
    return Unpacked(name, version, src, kind, top, native)


def fetch_all(packages, cache: Path = DEFAULT_CACHE, workers: int = 12, progress=None) -> list[Unpacked]:
    out: list[Unpacked] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_one, p.name, p.version, cache): p for p in packages}
        for done in as_completed(futures):
            result = done.result()
            out.append(result)
            if progress:
                progress(result)
    return sorted(out, key=lambda u: u.name)


def source_dirs(unpacked: Unpacked) -> list[Path]:
    """Roots to hand to the AST index for this package."""
    if unpacked.error:
        return []
    return [p for p in _source_roots(unpacked.root, unpacked.kind) if p.is_dir()]
