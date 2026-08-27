"""The exit code is the only part of this tool a CI job reads."""

import pytest

from src.cli import _exit_code, main


def counts(reachable=0, undetermined=0):
    return {"reachable": reachable, "undetermined": undetermined, "unreachable": 17}


def test_never_passes_even_with_findings():
    assert _exit_code("never", counts(reachable=4, undetermined=55)) == 0


def test_reachable_fails_only_on_a_call_path():
    assert _exit_code("reachable", counts(reachable=1)) == 1
    assert _exit_code("reachable", counts(undetermined=55)) == 0


def test_undetermined_also_covers_reachable():
    assert _exit_code("undetermined", counts(undetermined=1)) == 1
    assert _exit_code("undetermined", counts(reachable=1)) == 1
    assert _exit_code("undetermined", counts()) == 0


def test_a_clean_run_passes_at_every_level():
    assert all(_exit_code(level, counts()) == 0 for level in ("never", "reachable", "undetermined"))


def test_unknown_level_is_rejected_before_anything_runs():
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "--target", ".", "--fail-on", "sometimes"])
    assert exit_info.value.code == 2
