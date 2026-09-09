"""osv.py has no coverage: query_batch is the first network call every run makes, and until now
it was the only one of the three OSV/PyPI call sites with no error handling around it at all.
"""

from __future__ import annotations

import json
import urllib.error

import pytest

from src.sparrow import osv
from src.sparrow.deps import Package
from src.sparrow.osv import Advisory


def test_deduplicate_prefers_ghsa_and_merges_aliases_across_the_same_cve():
    ghsa = Advisory(id="GHSA-aaaa", package="flask", version="1.0",
                    aliases=["CVE-2026-1"], severity="unknown", details="a full writeup")
    pysec = Advisory(id="PYSEC-2026-1", package="flask", version="1.0",
                     aliases=["CVE-2026-1"], severity="high", details="")
    kept, merged = osv.deduplicate([ghsa, pysec])
    assert [a.id for a in kept] == ["GHSA-aaaa"]
    assert kept[0].severity == "high"          # backfilled from the dropped record
    assert kept[0].aliases == ["CVE-2026-1", "PYSEC-2026-1"]
    assert merged == {"GHSA-aaaa": ["PYSEC-2026-1"]}


def test_deduplicate_leaves_unrelated_advisories_alone():
    a = Advisory(id="GHSA-aaaa", package="flask", version="1.0", severity="high")
    b = Advisory(id="GHSA-bbbb", package="requests", version="2.0", severity="low")
    kept, merged = osv.deduplicate([a, b])
    assert {x.id for x in kept} == {"GHSA-aaaa", "GHSA-bbbb"}
    assert merged == {"GHSA-aaaa": [], "GHSA-bbbb": []}


def test_severity_of_prefers_database_specific_field():
    assert osv._severity_of({"database_specific": {"severity": "HIGH"}}) == "high"
    assert osv._severity_of({}) == "unknown"


def test_fixed_versions_matches_the_named_package_case_insensitively():
    record = {"affected": [
        {"package": {"name": "Flask"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.3.2"}]}]},
        {"package": {"name": "other"}, "ranges": [{"events": [{"fixed": "9.9.9"}]}]},
    ]}
    assert osv._fixed_versions(record, "flask") == ["2.3.2"]


def test_fetch_advisory_uses_the_cache_without_a_network_call(tmp_path, monkeypatch):
    vulns = tmp_path / "vulns"
    vulns.mkdir()
    (vulns / "GHSA-aaaa.json").write_text(json.dumps({"id": "GHSA-aaaa", "summary": "cached"}))

    def boom(url, timeout=60):
        raise AssertionError("a cache hit should not reach the network")

    monkeypatch.setattr(osv, "_get", boom)
    advisory = osv.fetch_advisory("GHSA-aaaa", "flask", "1.0", cache=tmp_path)
    assert advisory.summary == "cached"


def test_fetch_advisory_offline_without_cache_returns_none(tmp_path):
    assert osv.fetch_advisory("GHSA-aaaa", "flask", "1.0", cache=tmp_path, offline=True) is None


def test_fetch_advisory_returns_none_on_a_network_error(tmp_path, monkeypatch):
    monkeypatch.setattr(osv, "_get", lambda url, timeout=60: (_ for _ in ()).throw(
        urllib.error.URLError("boom")))
    assert osv.fetch_advisory("GHSA-aaaa", "flask", "1.0", cache=tmp_path) is None


def test_query_batch_reports_unreachable_osv_clearly(monkeypatch, tmp_path):
    def fake_post(url, payload, timeout=90):
        raise urllib.error.URLError("Name or service not known")

    monkeypatch.setattr(osv, "_post", fake_post)
    packages = [Package(name="flask", version="1.0")]

    with pytest.raises(RuntimeError, match="could not reach OSV.dev"):
        osv.query_batch(packages, cache=tmp_path)


def test_query_batch_offline_without_cache_is_also_clear(tmp_path):
    with pytest.raises(RuntimeError, match="offline run with no cached OSV query"):
        osv.query_batch([], cache=tmp_path, offline=True)
