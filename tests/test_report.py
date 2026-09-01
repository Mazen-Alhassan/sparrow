"""The bits of report.py with no coverage: colour detection and path shortening.

Both are easy to get quietly wrong (colour codes leaking into piped output, a frame path
that no longer matches any root) and neither needs a real scan to exercise.
"""

from __future__ import annotations

import io
import json

from src.sparrow.report import Renderer, _colour_enabled, write_json


def test_no_color_env_wins_even_on_a_tty(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert _colour_enabled(io.StringIO()) is False


def test_force_color_env_wins_on_a_non_tty_stream(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert _colour_enabled(io.StringIO()) is True


def test_piped_output_is_plain_by_default(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert _colour_enabled(io.StringIO()) is False


def test_shorten_strips_a_matching_root():
    renderer = Renderer(io.StringIO())
    path = renderer._shorten("/app/src/pkg/mod.py", ["/app"])
    assert path == "src/pkg/mod.py"


def test_shorten_falls_back_to_the_last_parts_when_no_root_matches():
    renderer = Renderer(io.StringIO())
    path = renderer._shorten("/site-packages/deep/nested/pkg/mod.py", ["/app"])
    assert path == "nested/pkg/mod.py"


def test_shorten_leaves_a_short_path_alone():
    renderer = Renderer(io.StringIO())
    assert renderer._shorten("mod.py", ["/app"]) == "mod.py"


def test_write_json_round_trips_and_creates_parent_dirs(tmp_path):
    out = tmp_path / "nested" / "results.json"
    results = {"target": {"name": "demo"}, "counts": {"reachable": 1}}
    write_json(results, out)
    assert json.loads(out.read_text()) == results
