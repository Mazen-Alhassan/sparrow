"""Score sink extraction against the hand-reviewed answer key.

    python tools/score.py --sinks data/sinks --mode advisory+patch
    python tools/score.py --sinks data/sinks-advisory-only --mode advisory-only

A prediction is a hit when any extracted sink string is in the answer key exactly. Naming the right
module but the wrong function is counted separately, because that failure mode is the one that
matters: it produces a sink that verifies against nothing and quietly becomes undetermined.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.sparrow.sinks.extract import load_cache   # noqa: E402


def load_labels(directory: Path) -> dict[str, dict]:
    labels = {row["advisory"]: row for row in json.loads((directory / "labels.json").read_text())}
    corrections = json.loads((directory / "corrections.json").read_text())
    for advisory, fix in corrections.items():
        if advisory.startswith("_") or advisory not in labels:
            continue
        labels[advisory]["truth"] = fix["truth"]
        labels[advisory]["corrected"] = fix["reason"]
    return labels


def classify(sinks: list[str], truth: list[str]) -> str:
    if not truth:
        return "hit" if not sinks else "false_sink"
    if not sinks:
        return "empty"
    if any(sink in truth for sink in sinks):
        return "hit"
    truth_modules = {t.rsplit(".", 1)[0] for t in truth}
    truth_names = {t.split(".")[-1] for t in truth}
    if any(sink.split(".")[-1] in truth_names for sink in sinks):
        return "right_function_wrong_path"
    if any(sink.rsplit(".", 1)[0] in truth_modules for sink in sinks):
        return "right_module_wrong_function"
    return "miss"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sinks", default="data/sinks")
    parser.add_argument("--labels", default="docs/labels")
    parser.add_argument("--mode", default="advisory+patch")
    parser.add_argument("--json", help="write the per-advisory table here")
    args = parser.parse_args()

    labels = load_labels(Path(args.labels))
    cache = load_cache(Path(args.sinks))
    rows = []
    for advisory, label in sorted(labels.items()):
        record = cache.get(advisory)
        sinks = record.sinks if record else []
        outcome = classify(sinks, label["truth"])
        rows.append({
            "advisory": advisory, "package": label["package"], "outcome": outcome,
            "predicted": sinks, "truth": label["truth"],
            "confidence": record.confidence if record else "", "mode": args.mode,
            "verified": record.status if record else "no_record",
        })

    tally: dict[str, int] = {}
    for row in rows:
        tally[row["outcome"]] = tally.get(row["outcome"], 0) + 1
    total = len(rows)
    hits = tally.get("hit", 0)

    width = max(len(r["advisory"]) for r in rows) + 2
    for row in rows:
        mark = {"hit": "ok", "miss": "MISS", "empty": "none",
                "right_module_wrong_function": "near", "right_function_wrong_path": "near",
                "false_sink": "FALSE"}[row["outcome"]]
        print(f"{row['advisory']:<{width}} {mark:<6} {row['confidence']:<7} "
              f"{', '.join(row['predicted'])[:70] or '(no sink)'}")
    print()
    for outcome, count in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>3}  {outcome}")
    print(f"\n  {hits}/{total} exact = {hits / total * 100:.0f}% in {args.mode} mode")
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"mode": args.mode, "total": total, "hits": hits, "tally": tally, "rows": rows},
            indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
