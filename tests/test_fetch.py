"""fetch.py has no dedicated tests: the artifact picker, the zip/tar extraction path-traversal
guard, and every error branch in fetch_one were only ever exercised by accident, through a real
network call in a full scan run.
"""

from __future__ import annotations

import io
import json
import tarfile
import urllib.error
import zipfile

from src.sparrow import fetch


def test_pick_artifact_prefers_a_pure_python_wheel():
    files = [
        {"packagetype": "sdist", "filename": "pkg-1.0.tar.gz"},
        {"packagetype": "bdist_wheel", "filename": "pkg-1.0-cp311-cp311-manylinux1_x86_64.whl"},
        {"packagetype": "bdist_wheel", "filename": "pkg-1.0-py3-none-any.whl"},
    ]
    artifact = fetch._pick_artifact(files)
    assert artifact["filename"] == "pkg-1.0-py3-none-any.whl"


def test_pick_artifact_falls_back_to_any_wheel_then_sdist():
    only_sdist = [{"packagetype": "sdist", "filename": "pkg-1.0.tar.gz"}]
    assert fetch._pick_artifact(only_sdist)["filename"] == "pkg-1.0.tar.gz"

    only_platform_wheel = [
        {"packagetype": "bdist_wheel", "filename": "pkg-1.0-cp311-cp311-manylinux1_x86_64.whl"}
    ]
    assert fetch._pick_artifact(only_platform_wheel)["filename"].endswith(".whl")

    assert fetch._pick_artifact([]) is None


def test_pick_artifact_uses_a_yanked_release_when_nothing_else_exists():
    files = [{"packagetype": "sdist", "filename": "pkg-1.0.tar.gz", "yanked": True}]
    assert fetch._pick_artifact(files)["filename"] == "pkg-1.0.tar.gz"


def test_safe_extract_zip_skips_path_traversal_members(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.py", "pwned")
        zf.writestr("good/mod.py", "ok")
    dest = tmp_path / "dest"
    dest.mkdir()
    fetch._safe_extract_zip(buf.getvalue(), dest)
    assert not (tmp_path / "evil.py").exists()
    assert (dest / "good" / "mod.py").read_text() == "ok"


def test_safe_extract_tar_skips_path_traversal_members(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in (("../evil.py", b"pwned"), ("good/mod.py", b"ok")):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    dest = tmp_path / "dest"
    dest.mkdir()
    fetch._safe_extract_tar(buf.getvalue(), dest)
    assert not (tmp_path / "evil.py").exists()
    assert (dest / "good" / "mod.py").read_text() == "ok"


def test_scan_finds_top_level_package_and_native_extension(tmp_path):
    root = tmp_path / "src"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("")
    (root / "pkg" / "_native.cpython-311-x86_64-linux-gnu.so").write_bytes(b"\x00")
    (root / "pkg.dist-info").mkdir()
    top, native = fetch._scan(root, "wheel")
    assert top == ["pkg"]
    assert native == ["pkg/_native.cpython-311-x86_64-linux-gnu.so"]


def test_fetch_one_uses_the_cached_marker_without_a_network_call(tmp_path, monkeypatch):
    dest = tmp_path / "flask" / "1.0"
    (dest / "src").mkdir(parents=True)
    (dest / ".sparrow-ok.json").write_text(
        json.dumps({"kind": "wheel", "top_level": ["flask"], "native": []}))

    def boom(*args, **kwargs):
        raise AssertionError("a cached fetch should not touch the network")

    monkeypatch.setattr(fetch, "_get", boom)
    result = fetch.fetch_one("flask", "1.0", cache=tmp_path)
    assert result.error == ""
    assert result.top_level == ["flask"]


def test_fetch_one_reports_a_clear_error_when_pypi_metadata_is_unreachable(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "_get", lambda url, timeout=60: (_ for _ in ()).throw(
        urllib.error.URLError("Name or service not known")))
    result = fetch.fetch_one("flask", "1.0", cache=tmp_path)
    assert result.error.startswith("pypi metadata:")


def test_fetch_one_reports_a_clear_error_when_the_download_fails(tmp_path, monkeypatch):
    meta = json.dumps({"urls": [{"packagetype": "sdist", "filename": "flask-1.0.tar.gz",
                                 "url": "https://example.invalid/flask-1.0.tar.gz", "digests": {}}]})

    def fake_get(url, timeout=60):
        if url.endswith(".tar.gz"):
            raise urllib.error.HTTPError(url, 404, "not found", {}, None)
        return meta.encode()

    monkeypatch.setattr(fetch, "_get", fake_get)
    result = fetch.fetch_one("flask", "1.0", cache=tmp_path)
    assert result.error.startswith("download:")


def test_fetch_one_reports_a_sha256_mismatch(tmp_path, monkeypatch):
    meta = json.dumps({"urls": [{"packagetype": "sdist", "filename": "flask-1.0.tar.gz",
                                 "url": "https://example.invalid/flask-1.0.tar.gz",
                                 "digests": {"sha256": "0" * 64}}]})

    def fake_get(url, timeout=60):
        return meta.encode() if url.endswith("json") else b"not the right bytes"

    monkeypatch.setattr(fetch, "_get", fake_get)
    result = fetch.fetch_one("flask", "1.0", cache=tmp_path)
    assert result.error == "sha256 mismatch"


def test_fetch_one_reports_when_pypi_has_no_usable_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "_get", lambda url, timeout=60: json.dumps({"urls": []}).encode())
    result = fetch.fetch_one("flask", "1.0", cache=tmp_path)
    assert result.error == "no wheel or sdist on pypi"


def test_source_dirs_is_empty_for_a_failed_fetch(tmp_path):
    unpacked = fetch.Unpacked("flask", "1.0", tmp_path, "", [], [], error="boom")
    assert fetch.source_dirs(unpacked) == []
