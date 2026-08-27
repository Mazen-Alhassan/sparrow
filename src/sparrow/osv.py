"""OSV.dev client and advisory normalisation.

OSV returns a GHSA record and a PYSEC record for the same underlying CVE. Both are real rows in a
scanner's output, so both are counted in the raw total, and they are merged by CVE alias before
analysis so one flaw is not triaged twice.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from .net import context

QUERYBATCH = "https://api.osv.dev/v1/querybatch"
VULN = "https://api.osv.dev/v1/vulns/{id}"
DEFAULT_CACHE = Path.home() / ".cache" / "sparrow" / "osv"

_SEVERITY_ORDER = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1, "unknown": 0}


@dataclass
class Advisory:
    id: str
    package: str
    version: str
    aliases: list[str] = field(default_factory=list)
    severity: str = "unknown"
    summary: str = ""
    details: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    withdrawn: bool = False

    @property
    def cve(self) -> str:
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.id if self.id.startswith("CVE-") else ""

    @property
    def key(self) -> str:
        """Identity used for de-duplication: the CVE if there is one, else the advisory id."""
        return self.cve or self.id

    def fix_commits(self) -> list[str]:
        out = []
        for ref in self.references:
            url = ref.get("url", "")
            if ref.get("type") in ("FIX", "ADVISORY", "WEB", "PACKAGE") and "/commit/" in url:
                out.append(url)
        return out

    def to_dict(self) -> dict:
        return {
            "id": self.id, "package": self.package, "version": self.version, "aliases": self.aliases,
            "severity": self.severity, "summary": self.summary, "details": self.details,
            "fixed_versions": self.fixed_versions, "references": self.references,
        }


def _post(url: str, payload: dict, timeout: int = 90) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout, context=context()) as resp:
        return json.loads(resp.read())


def _get(url: str, timeout: int = 60) -> dict:
    with urllib.request.urlopen(url, timeout=timeout, context=context()) as resp:
        return json.loads(resp.read())


def query_batch(packages, cache: Path = DEFAULT_CACHE, offline: bool = False) -> dict[str, list[str]]:
    """Map package name to the advisory ids affecting its pinned version."""
    cache.mkdir(parents=True, exist_ok=True)
    key = cache / "querybatch.json"
    if offline:
        if not key.exists():
            raise RuntimeError("offline run with no cached OSV query; run once online first")
        return json.loads(key.read_text())
    queries = [{"package": {"name": p.name, "ecosystem": "PyPI"}, "version": p.version} for p in packages]
    hits: dict[str, list[str]] = {}
    for start in range(0, len(queries), 100):
        chunk = queries[start : start + 100]
        result = _post(QUERYBATCH, {"queries": chunk})
        for query, row in zip(chunk, result.get("results", [])):
            ids = [v["id"] for v in row.get("vulns", [])]
            if ids:
                hits[query["package"]["name"]] = ids
    key.write_text(json.dumps(hits, indent=1, sort_keys=True))
    return hits


def _severity_of(record: dict) -> str:
    db = (record.get("database_specific") or {}).get("severity")
    if db:
        return db.lower()
    for sev in record.get("severity", []):
        score = sev.get("score", "")
        if score.startswith("CVSS:"):
            return "unknown"
    return "unknown"


def _fixed_versions(record: dict, package: str) -> list[str]:
    out: list[str] = []
    for affected in record.get("affected", []):
        if (affected.get("package") or {}).get("name", "").lower() != package.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    out.append(event["fixed"])
    return sorted(set(out))


def fetch_advisory(advisory_id: str, package: str, version: str, cache: Path = DEFAULT_CACHE,
                   offline: bool = False) -> Advisory | None:
    path = cache / "vulns" / f"{advisory_id}.json"
    if path.exists():
        record = json.loads(path.read_text())
    elif offline:
        return None
    else:
        try:
            record = _get(VULN.format(id=advisory_id))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record))
    return Advisory(
        id=record["id"],
        package=package,
        version=version,
        aliases=record.get("aliases", []),
        severity=_severity_of(record),
        summary=record.get("summary", ""),
        details=record.get("details", ""),
        fixed_versions=_fixed_versions(record, package),
        references=record.get("references", []),
        withdrawn=bool(record.get("withdrawn")),
    )


def fetch_all(hits: dict[str, list[str]], packages: dict, cache: Path = DEFAULT_CACHE,
              offline: bool = False, workers: int = 12) -> list[Advisory]:
    jobs = [(aid, name) for name, ids in hits.items() for aid in ids]
    out: list[Advisory] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(fetch_advisory, aid, name, packages[name].version, cache, offline)
            for aid, name in jobs
        ]
        for done in as_completed(futures):
            advisory = done.result()
            if advisory and not advisory.withdrawn:
                out.append(advisory)
    return sorted(out, key=lambda a: (a.package, a.id))


def deduplicate(advisories: list[Advisory]) -> tuple[list[Advisory], dict[str, list[str]]]:
    """Merge advisories that describe the same CVE for the same package.

    Keeps the record with the most prose, which is GHSA in nearly every case. The dropped ids are
    returned so the report can show both the raw scanner count and the merged count.
    """
    groups: dict[tuple[str, str], list[Advisory]] = {}
    for advisory in advisories:
        groups.setdefault((advisory.package, advisory.key), []).append(advisory)
    kept: list[Advisory] = []
    merged: dict[str, list[str]] = {}
    for group in groups.values():
        group.sort(key=lambda a: (a.id.startswith("GHSA-"), len(a.details)), reverse=True)
        winner = group[0]
        for other in group[1:]:
            winner.aliases = sorted(set(winner.aliases) | set(other.aliases) | {other.id})
            if not winner.fixed_versions:
                winner.fixed_versions = other.fixed_versions
            if winner.severity == "unknown":
                winner.severity = other.severity
        kept.append(winner)
        merged[winner.id] = [o.id for o in group[1:]]
    return sorted(kept, key=lambda a: (-_SEVERITY_ORDER.get(a.severity, 0), a.package, a.id)), merged


def severity_rank(name: str) -> int:
    return _SEVERITY_ORDER.get(name, 0)
