"""Regression tests for the adversary's cases.

Each directory under `tests/adversarial/` holds a tiny application whose `vuln.bad()` provably runs
when the app is executed. The tool is allowed to call any of them `reachable` or `undetermined`. It
is never allowed to call them `unreachable`, because that is the verdict a human acts on by not
looking. The adversary's original report is in `tests/adversarial/RESULTS.md`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from conftest import analyse

CASES = sorted(p for p in (Path(__file__).parent / "adversarial").iterdir() if p.is_dir())


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_sink_actually_executes(case):
    """A case that does not run the sink is not evidence of anything."""
    result = subprocess.run([sys.executable, "app.py"], cwd=case, capture_output=True, text=True)
    assert "SINK EXECUTED" in result.stdout, result.stderr


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_never_reported_unreachable(case):
    _, _, _, analyzer = analyse(case.resolve())
    verdict = analyzer.classify(["vuln.bad"], "verified", "vuln")
    assert verdict.bucket != "unreachable", f"{case.name}: {verdict.reason} {verdict.evidence}"
