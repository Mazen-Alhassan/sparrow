"""osv.py has no coverage: query_batch is the first network call every run makes, and until now
it was the only one of the three OSV/PyPI call sites with no error handling around it at all.
"""

from __future__ import annotations

import urllib.error

import pytest

from src.sparrow import osv
from src.sparrow.deps import Package


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
