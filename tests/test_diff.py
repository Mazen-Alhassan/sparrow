"""diff.py has no coverage: it is the one command whose whole job is to notice a change,
so a bug here means a regression slips through silently instead of loudly.
"""

from __future__ import annotations

import json

from src.cli import main
from src.sparrow.diff import compare, render


def _finding(advisory, package, bucket):
    return {"advisory": advisory, "package": package, "bucket": bucket}


def test_bucket_getting_worse_is_flagged_as_regressed():
    old = {"findings": [_finding("GHSA-1", "flask", "unreachable")]}
    new = {"findings": [_finding("GHSA-1", "flask", "reachable")]}
    rows = compare(old, new)
    assert rows == [{"advisory": "GHSA-1", "package": "flask", "change": "regressed",
                     "old_bucket": "unreachable", "new_bucket": "reachable"}]


def test_bucket_getting_better_is_flagged_as_improved():
    old = {"findings": [_finding("GHSA-1", "flask", "reachable")]}
    new = {"findings": [_finding("GHSA-1", "flask", "undetermined")]}
    rows = compare(old, new)
    assert rows[0]["change"] == "improved"


def test_advisory_only_in_new_run_is_added():
    old = {"findings": []}
    new = {"findings": [_finding("GHSA-2", "click", "undetermined")]}
    rows = compare(old, new)
    assert rows == [{"advisory": "GHSA-2", "package": "click", "change": "added",
                     "old_bucket": None, "new_bucket": "undetermined"}]


def test_advisory_only_in_old_run_is_removed():
    old = {"findings": [_finding("GHSA-3", "requests", "reachable")]}
    new = {"findings": []}
    rows = compare(old, new)
    assert rows == [{"advisory": "GHSA-3", "package": "requests", "change": "removed",
                     "old_bucket": "reachable", "new_bucket": None}]


def test_unchanged_advisories_produce_no_row():
    old = {"findings": [_finding("GHSA-4", "flask", "unreachable")]}
    new = {"findings": [_finding("GHSA-4", "flask", "unreachable")]}
    assert compare(old, new) == []


def test_render_reports_no_changes_plainly():
    assert render([]) == "no bucket changes"


def test_render_marks_a_regression_and_an_improvement_differently():
    rows = [
        {"advisory": "GHSA-1", "package": "flask", "change": "regressed",
         "old_bucket": "unreachable", "new_bucket": "reachable"},
        {"advisory": "GHSA-2", "package": "click", "change": "improved",
         "old_bucket": "reachable", "new_bucket": "undetermined"},
    ]
    text = render(rows)
    assert text.splitlines()[0].startswith("!")
    assert text.splitlines()[1].startswith("*")


def test_cli_diff_exits_nonzero_on_a_regression(tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"findings": [_finding("GHSA-1", "flask", "unreachable")]}))
    new.write_text(json.dumps({"findings": [_finding("GHSA-1", "flask", "reachable")]}))
    code = main(["diff", str(old), str(new)])
    assert code == 1
    assert "GHSA-1" in capsys.readouterr().out


def test_cli_diff_exits_zero_with_no_regression(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"findings": []}))
    new.write_text(json.dumps({"findings": []}))
    assert main(["diff", str(old), str(new)]) == 0
