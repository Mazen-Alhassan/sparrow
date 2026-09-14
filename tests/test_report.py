"""The bits of report.py with no coverage: colour detection, path shortening, and the
section renderers (header/funnel/findings/breakdown/timings) that turn a results dict into
the text a human reads. A `Renderer` on an `io.StringIO` never hits `isatty()` true, so
colour stays off and the assertions below can match on plain text.
"""

from __future__ import annotations

import io
import json

from src.sparrow.report import Renderer, _colour_enabled, render, write_json


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


def _finding(bucket="reachable", reason="call_path", **overrides):
    finding = {
        "advisory": "GHSA-1", "cve": "CVE-2024-1", "package": "flask", "version": "1.0",
        "direct": True, "severity": "high", "bucket": bucket, "reason": reason,
        "evidence": "", "sinks": ["flask.templating:render_template"], "taint": None, "paths": [],
    }
    finding.update(overrides)
    return finding


def test_header_prints_target_name_and_stats():
    stream = io.StringIO()
    results = {
        "target": {"name": "demo", "lockfile": "requirements.txt"},
        "stats": {"packages": 3, "modules": 12, "scopes": 40, "entry_points": 2, "edges": 88},
    }
    Renderer(stream).header(results)
    out = stream.getvalue()
    assert "demo" in out and "requirements.txt" in out
    assert "3 packages, 12 modules, 40 functions, 2 entry points, 88 call edges" in out


def test_funnel_reports_raw_and_unique_counts_plus_direct_breakdown():
    stream = io.StringIO()
    results = {
        "counts": {"advisories_raw": 5, "advisories_unique": 4, "reachable": 1,
                   "undetermined": 2, "unreachable": 1, "reachable_direct": 1},
    }
    Renderer(stream).funnel(results)
    out = stream.getvalue()
    assert "5 advisories reported by OSV, 4 unique after merging GHSA and PYSEC duplicates" in out
    assert "reachable" in out and "undetermined" in out and "not reachable" in out
    assert "1 reachable (1 in a direct dependency), 2 undetermined" in out


def test_findings_only_renders_the_requested_bucket():
    stream = io.StringIO()
    results = {"target": {"roots": []},
               "findings": [_finding("reachable"), _finding("undetermined", reason="dynamic_dispatch")]}
    Renderer(stream).findings(results, bucket="reachable")
    out = stream.getvalue()
    assert "CVE-2024-1" in out
    assert "dynamic_dispatch" not in out


def test_finding_renders_call_path_with_vulnerable_marker_and_guessed_hop():
    stream = io.StringIO()
    finding = _finding(paths=[{
        "frames": [
            {"file": "/app/svc/views.py", "line": 10, "node": "svc.views:handler", "edge": "call"},
            {"file": "/app/svc/util.py", "line": 20, "node": "svc.util:dispatch", "edge": "dynamic"},
            {"file": "/app/.cache/sparrow/pkgs/flask/templating.py", "line": 30,
             "node": "flask.templating:render_template", "edge": "call"},
        ],
        "entrypoint": {"node": "svc.views:handler", "detail": "GET /x", "kind": "http_route"},
    }])
    results = {"target": {"roots": ["/app"]}, "findings": [finding]}
    Renderer(stream).findings(results, bucket="reachable")
    out = stream.getvalue()
    assert "svc/views.py:10" in out and "handler()" in out
    assert "guessed, name match at a dynamic call site" in out
    assert "<-- vulnerable" in out
    assert "reachable from: GET /x  (http_route)" in out


def test_finding_shows_taint_status_and_source():
    stream = io.StringIO()
    finding = _finding(paths=[{
        "frames": [{"file": "/app/svc/views.py", "line": 1, "node": "svc.views:handler", "edge": "call"}],
        "entrypoint": {"node": "svc.views:handler", "detail": "", "kind": "http_route"},
    }], taint={"status": "tainted", "source": "request.args"})
    results = {"target": {"roots": ["/app"]}, "findings": [finding]}
    Renderer(stream).findings(results, bucket="reachable")
    assert "request data reaches the arguments, source request.args" in stream.getvalue()


def test_non_reachable_finding_shows_reason_and_evidence():
    stream = io.StringIO()
    finding = _finding("undetermined", reason="dynamic_dispatch", evidence="unresolved call .run()")
    results = {"target": {"roots": []}, "findings": [finding]}
    Renderer(stream).findings(results, bucket="undetermined")
    out = stream.getvalue()
    assert "blocked by dynamic dispatch: unresolved call .run()" in out


def test_breakdown_groups_by_reason_most_common_first():
    stream = io.StringIO()
    results = {"findings": [
        _finding("reachable"),
        _finding("undetermined", reason="dynamic_dispatch"),
        _finding("undetermined", reason="dynamic_dispatch"),
        _finding("unreachable", reason="module_never_imported"),
    ]}
    Renderer(stream).breakdown(results)
    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    assert any("2  dynamic_dispatch" in line for line in lines)
    dispatch_idx = next(i for i, line in enumerate(lines) if "dynamic_dispatch" in line)
    imported_idx = next(i for i, line in enumerate(lines) if "module_never_imported" in line)
    assert dispatch_idx < imported_idx


def test_timings_joins_marks_in_order():
    stream = io.StringIO()
    Renderer(stream).timings({"index": 1.234, "reachability": 0.5})
    assert "index 1.2s, reachability 0.5s" in stream.getvalue()


def test_render_wires_every_section_together():
    stream = io.StringIO()
    results = {
        "target": {"name": "demo", "lockfile": "requirements.txt", "roots": []},
        "stats": {"packages": 1, "modules": 1, "scopes": 1, "entry_points": 1, "edges": 1},
        "counts": {"advisories_raw": 1, "advisories_unique": 1, "reachable": 1,
                   "undetermined": 0, "unreachable": 0, "reachable_direct": 1},
        "findings": [_finding("reachable")],
        "timings": {"total": 0.1},
    }
    render(results, stream=stream, show="all")
    out = stream.getvalue()
    assert "demo" in out
    assert "CVE-2024-1" in out
    assert "why the rest are not reachable" in out
    assert "total 0.1s" in out
