"""Deterministic verification of an extracted sink against the real patch.

A sink is accepted only when the named function exists in the vulnerable version and is absent or
textually different in the fixed version. This is the step that separates a tool from a model demo:
the model's answer is a hypothesis, and this is the experiment.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from ..fetch import DEFAULT_CACHE, Unpacked, fetch_one, source_dirs
from ..index import module_name_for

VERIFIED = "verified"
ABSENT = "absent_in_vulnerable"
UNCHANGED = "unchanged_in_fixed"
MISSING = "package_missing"
NO_FIX = "no_fixed_version"


@dataclass
class FunctionShape:
    module: str
    qualname: str
    file: str
    line: int
    digest: str


def _walk(tree: ast.AST, module: str, file: str) -> dict[str, FunctionShape]:
    out: dict[str, FunctionShape] = {}

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}.{child.name}" if prefix else child.name
                out[qual] = FunctionShape(module, qual, file, child.lineno,
                                          ast.dump(child, include_attributes=False))
                visit(child, f"{qual}.<locals>")
            elif isinstance(child, ast.ClassDef):
                qual = f"{prefix}.{child.name}" if prefix else child.name
                out[qual] = FunctionShape(module, qual, file, child.lineno,
                                          ast.dump(child, include_attributes=False))
                visit(child, qual)

    visit(tree, "")
    return out


def shapes_for(unpacked: Unpacked) -> dict[str, FunctionShape]:
    """`module.qualname` to a body digest for every function and class in a package version."""
    out: dict[str, FunctionShape] = {}
    for root in source_dirs(unpacked):
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts or "site-packages" in path.parts:
                continue
            module = module_name_for(path, root)
            if module is None:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
            except (SyntaxError, ValueError, RecursionError):
                continue
            for qual, shape in _walk(tree, module, str(path)).items():
                out.setdefault(f"{module}.{qual}", shape)
    return out


def _lookup(shapes: dict[str, FunctionShape], sink: str) -> FunctionShape | None:
    if sink in shapes:
        return shapes[sink]
    # `pkg.module.Class.method` where the model guessed a shallower or deeper module path
    tail = sink.split(".")[-2:]
    suffix = ".".join(tail)
    matches = [v for k, v in shapes.items() if k.endswith("." + suffix) or k == suffix]
    if len(matches) == 1:
        return matches[0]
    exact_tail = [v for k, v in shapes.items() if k.split(".")[-1] == sink.split(".")[-1]]
    return exact_tail[0] if len(exact_tail) == 1 else None


def verify_sink(package: str, sink: str, vulnerable_version: str, fixed_version: str | None,
                cache: Path = DEFAULT_CACHE) -> dict:
    result = {
        "status": MISSING, "present_in_vulnerable": False, "changed_in_fixed": False,
        "vulnerable_version": vulnerable_version, "fixed_version": fixed_version or "",
        "note": "",
    }
    if not fixed_version:
        result["status"] = NO_FIX
        result["note"] = "advisory lists no fixed version"
        return result
    vulnerable = fetch_one(package, vulnerable_version, cache)
    fixed = fetch_one(package, fixed_version, cache)
    if vulnerable.error or fixed.error:
        result["note"] = vulnerable.error or fixed.error
        return result
    vulnerable_shapes = shapes_for(vulnerable)
    fixed_shapes = shapes_for(fixed)
    before = _lookup(vulnerable_shapes, sink)
    if before is None:
        result["status"] = ABSENT
        result["note"] = f"{sink} does not exist in {package} {vulnerable_version}"
        return result
    result["present_in_vulnerable"] = True
    result["location"] = f"{before.module}:{before.qualname}"
    after = _lookup(fixed_shapes, sink)
    if after is None:
        result["status"] = VERIFIED
        result["changed_in_fixed"] = True
        result["note"] = f"removed in {fixed_version}"
        return result
    if after.digest != before.digest:
        result["status"] = VERIFIED
        result["changed_in_fixed"] = True
        result["note"] = f"body differs between {vulnerable_version} and {fixed_version}"
        return result
    result["status"] = UNCHANGED
    result["note"] = f"identical body in {vulnerable_version} and {fixed_version}"
    return result


def verify_record(record, advisory, cache: Path = DEFAULT_CACHE) -> dict:
    """Try each listed fixed version. Advisories sometimes name a release that was later yanked."""
    out = {}
    for sink in record.sinks:
        result = {"status": NO_FIX, "note": "advisory lists no fixed version"}
        for fixed in advisory.fixed_versions or [None]:
            result = verify_sink(advisory.package, sink, advisory.version, fixed, cache)
            if result["status"] != MISSING:
                break
        out[sink] = result
    return out
