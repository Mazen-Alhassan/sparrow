from src.sparrow.osv import Advisory
from src.sparrow.sinks.extract import SinkRecord, build_prompt
from src.sparrow.sinks.patches import patch_urls, python_hunks

ADVISORY = Advisory(
    id="GHSA-test", package="bleach", version="3.0.0", aliases=["CVE-2024-0001"],
    severity="high", summary="Sanitiser flaw", details="A flaw in the css sanitiser.",
    fixed_versions=["3.0.1"],
    references=[{"type": "FIX", "url": "https://github.com/mozilla/bleach/commit/abc1234"},
                {"type": "WEB", "url": "https://example.invalid/notes"}],
)


def test_prompt_states_the_mode_rule():
    advisory_only = build_prompt(ADVISORY, "advisory-only")
    with_patch = build_prompt(ADVISORY, "advisory+patch", patch="diff --git a/x.py b/x.py")
    assert "No diff, no source, no lookups." in advisory_only
    assert "diff --git" not in advisory_only
    assert "diff --git" in with_patch


def test_patch_urls_are_github_only():
    assert patch_urls(ADVISORY) == ["https://github.com/mozilla/bleach/commit/abc1234.patch"]


def test_python_hunks_drops_other_languages():
    patch = (
        "diff --git a/src/x.js b/src/x.js\n@@ -1 +1 @@\n-a\n+b\n"
        "diff --git a/src/y.py b/src/y.py\n@@ -1 +1 @@\n-def old():\n+def new():\n"
    )
    hunks = python_hunks(patch)
    assert "src/y.py" in hunks and "src/x.js" not in hunks


def test_record_status_requires_a_verified_sink():
    record = SinkRecord(advisory="A", package="p", sinks=["p.m.f"])
    assert record.status == "unverified"
    record.verification = {"p.m.f": {"status": "unchanged_in_fixed"}}
    assert record.status == "unchanged_in_fixed"
    assert record.verified_sinks == []
    record.verification = {"p.m.f": {"status": "verified"}}
    assert record.status == "verified"
    assert record.verified_sinks == ["p.m.f"]


def test_empty_sinks_is_no_sink():
    assert SinkRecord(advisory="A", package="p").status == "no_sink"
