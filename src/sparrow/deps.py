"""Lockfile parsing. Exact versions only, no network, no resolution.

An unpinned requirement is dropped with a warning rather than guessed at, because an advisory
match against the wrong version is worse than a missing row.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._!+-]*)\s*$")
_NAME_ONLY = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def canonical(name: str) -> str:
    """PEP 503 normalisation. `Flask_AppBuilder` and `flask-appbuilder` are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Package:
    name: str
    version: str
    direct: bool = False
    source: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "direct": self.direct, "source": self.source}


@dataclass
class Lockfile:
    packages: list[Package] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def by_name(self) -> dict[str, Package]:
        return {p.name: p for p in self.packages}


def _strip_comment(line: str) -> str:
    # A comment marker inside a URL fragment or an environment marker is not a comment start,
    # but pip-compile output never puts one there, and requirement lines that do are already
    # unpinned by construction.
    return line.split(" #")[0].split("\t#")[0].strip() if " #" in line or "\t#" in line else (
        "" if line.lstrip().startswith("#") else line.strip()
    )


def parse_requirements(path: Path, direct_names: set[str] | None = None) -> Lockfile:
    """Parse a pip requirements file. Follows `-r` includes relative to the file."""
    lock = Lockfile()
    seen: set[str] = set()
    _parse_requirements_into(path, lock, seen, direct_names or set())
    return lock


def _parse_requirements_into(path: Path, lock: Lockfile, seen: set[str], direct: set[str]) -> None:
    if not path.exists():
        raise FileNotFoundError(path)
    buffer = ""
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buffer += line[:-1]
            continue
        line, buffer = buffer + line, ""
        line = _strip_comment(line)
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            _parse_requirements_into(path.parent / line.split(None, 1)[1].strip(), lock, seen, direct)
            continue
        if line.startswith("-"):
            continue
        # Environment markers: keep the requirement, the marker only narrows platforms.
        line = line.split(";")[0].strip()
        m = _PIN.match(line)
        if not m:
            name = _NAME_ONLY.match(line)
            if name:
                lock.skipped.append(line)
            continue
        name = canonical(m.group(1))
        if name in seen:
            continue
        seen.add(name)
        lock.packages.append(
            Package(name=name, version=m.group(2), direct=name in direct, source=str(path.name))
        )


def parse_poetry_lock(path: Path) -> Lockfile:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    lock = Lockfile()
    for pkg in data.get("package", []):
        if pkg.get("category") == "dev":
            continue
        lock.packages.append(
            Package(name=canonical(pkg["name"]), version=pkg["version"], source=path.name)
        )
    return lock


def parse_pipfile_lock(path: Path) -> Lockfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    lock = Lockfile()
    for section, direct in (("default", True), ("develop", False)):
        for name, spec in data.get(section, {}).items():
            version = str(spec.get("version", "")).lstrip("=")
            if not version:
                lock.skipped.append(name)
                continue
            lock.packages.append(
                Package(name=canonical(name), version=version, direct=direct, source=path.name)
            )
    return lock


def parse_uv_lock(path: Path) -> Lockfile:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    lock = Lockfile()
    for pkg in data.get("package", []):
        if "version" not in pkg:
            lock.skipped.append(pkg.get("name", "?"))
            continue
        lock.packages.append(
            Package(name=canonical(pkg["name"]), version=pkg["version"], source=path.name)
        )
    return lock


_LOCKFILES = (
    ("uv.lock", parse_uv_lock),
    ("poetry.lock", parse_poetry_lock),
    ("Pipfile.lock", parse_pipfile_lock),
    ("requirements.txt", parse_requirements),
    ("requirements/base.txt", parse_requirements),
)


def discover(root: Path, explicit: Path | None = None) -> Lockfile:
    """Find and parse the lockfile for a target directory."""
    if explicit is not None:
        return parse_any(explicit)
    for rel, _ in _LOCKFILES:
        candidate = root / rel
        if candidate.exists():
            return parse_any(candidate)
    raise FileNotFoundError(f"no lockfile found under {root}")


def parse_any(path: Path) -> Lockfile:
    if path.name == "poetry.lock":
        return parse_poetry_lock(path)
    if path.name == "Pipfile.lock":
        return parse_pipfile_lock(path)
    if path.name == "uv.lock":
        return parse_uv_lock(path)
    direct = _direct_names(path.parent)
    return parse_requirements(path, direct)


def _direct_names(root: Path) -> set[str]:
    """Direct dependencies, read from pyproject or a `.in` file next to the lock.

    Used only to label a row direct or transitive. A wrong label changes no verdict.
    """
    names: set[str] = set()
    for candidate in (root / "pyproject.toml", root.parent / "pyproject.toml"):
        if not candidate.exists():
            continue
        try:
            data = tomllib.loads(candidate.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            continue
        deps = data.get("project", {}).get("dependencies", []) or []
        for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
            deps.extend(group)
        poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
        deps.extend(poetry.keys())
        for dep in deps:
            m = _NAME_ONLY.match(str(dep).strip())
            if m:
                names.add(canonical(m.group(1)))
        break
    for inc in root.glob("*.in"):
        for line in inc.read_text(encoding="utf-8", errors="replace").splitlines():
            line = _strip_comment(line)
            if line and not line.startswith("-"):
                m = _NAME_ONLY.match(line)
                if m:
                    names.add(canonical(m.group(1)))
    return names
