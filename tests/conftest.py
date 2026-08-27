"""Fixture helpers: build a small package on disk, index it, and build a call graph."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.sparrow.callgraph import CallGraph          # noqa: E402
from src.sparrow.entrypoints import discover          # noqa: E402
from src.sparrow.index import Index                   # noqa: E402
from src.sparrow.reach import Analyzer                # noqa: E402


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body.lstrip("\n"))
    return root


def build(root: Path, extra_roots: dict[str, Path] | None = None):
    index = Index()
    index.add_root(root, is_app=True)
    for package, path in (extra_roots or {}).items():
        index.add_root(path, package=package)
    graph = CallGraph(index)
    graph.build()
    return index, graph


def analyse(root: Path, extra_roots: dict[str, Path] | None = None):
    index, graph = build(root, extra_roots)
    entries = discover(index, graph, root)
    return index, graph, entries, Analyzer(index, graph, entries)


@pytest.fixture
def tree(tmp_path):
    def _tree(files: dict[str, str]) -> Path:
        return write_tree(tmp_path, files)
    return _tree
