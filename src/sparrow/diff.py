"""Diff two scan results by advisory bucket.

A single run's numbers are a snapshot. The number that matters day to day is whether an advisory
moved buckets between two runs -- a dependency bump that closed a reachable path, or a new import
that opened one. `sparrow diff` reads two `scan --out` files and reports exactly that, nothing else.
"""

from __future__ import annotations

from .reach import REACHABLE, UNDETERMINED, UNREACHABLE

# Worst to best, so a bucket change can be judged as a regression or an improvement rather than
# just "different".
SEVERITY = {REACHABLE: 0, UNDETERMINED: 1, UNREACHABLE: 2}


def _by_advisory(results: dict) -> dict[str, dict]:
    return {finding["advisory"]: finding for finding in results.get("findings", [])}


def compare(old: dict, new: dict) -> list[dict]:
    """One row per advisory that changed bucket, or that only appears in one of the two runs."""
    before, after = _by_advisory(old), _by_advisory(new)
    rows = []
    for advisory_id in sorted(set(before) | set(after)):
        old_finding, new_finding = before.get(advisory_id), after.get(advisory_id)
        if old_finding is None:
            rows.append({"advisory": advisory_id, "package": new_finding["package"], "change": "added",
                         "old_bucket": None, "new_bucket": new_finding["bucket"]})
        elif new_finding is None:
            rows.append({"advisory": advisory_id, "package": old_finding["package"], "change": "removed",
                         "old_bucket": old_finding["bucket"], "new_bucket": None})
        elif old_finding["bucket"] != new_finding["bucket"]:
            worse = SEVERITY[new_finding["bucket"]] < SEVERITY[old_finding["bucket"]]
            rows.append({"advisory": advisory_id, "package": new_finding["package"],
                         "change": "regressed" if worse else "improved",
                         "old_bucket": old_finding["bucket"], "new_bucket": new_finding["bucket"]})
    return rows


def render(rows: list[dict]) -> str:
    if not rows:
        return "no bucket changes"
    lines = []
    for row in rows:
        if row["change"] == "added":
            lines.append(f"+ {row['advisory']:<24} {row['package']:<20} new, {row['new_bucket']}")
        elif row["change"] == "removed":
            lines.append(f"- {row['advisory']:<24} {row['package']:<20} gone, was {row['old_bucket']}")
        else:
            marker = "!" if row["change"] == "regressed" else "*"
            lines.append(f"{marker} {row['advisory']:<24} {row['package']:<20} "
                         f"{row['old_bucket']} -> {row['new_bucket']}")
    return "\n".join(lines)
