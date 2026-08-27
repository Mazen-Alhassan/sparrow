"""Command line entry point.

    python -m src.cli scan    --target data/sample --out data/results.json
    python -m src.cli prompts --target data/sample --out data/prompts --mode advisory-only
    python -m src.cli verify  --target data/sample
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .sparrow import deps, fetch, osv, report
from .sparrow.callgraph import CallGraph
from .sparrow.entrypoints import discover as discover_entrypoints
from .sparrow.index import Index
from .sparrow.reach import REACHABLE, UNDETERMINED, UNREACHABLE, Analyzer
from .sparrow.sinks import extract, verify
from .sparrow.taint import trace

SEVERITY_ORDER = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3, "unknown": 4}


class Timer:
    def __init__(self) -> None:
        self.marks: dict[str, float] = {}
        self._start = time.time()

    def mark(self, name: str) -> None:
        now = time.time()
        self.marks[name] = now - self._start
        self._start = now


def _load_target(args) -> tuple[Path, deps.Lockfile]:
    root = Path(args.target).resolve()
    lockfile = deps.discover(root, Path(args.lockfile).resolve() if args.lockfile else None)
    return root, lockfile


def _relative(path: Path) -> str:
    """Absolute home paths are noise in a terminal. Show the path as typed where possible."""
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _log(args, message: str) -> None:
    if not args.quiet:
        print(message, file=sys.stderr, flush=True)


def scan(args) -> int:
    timer = Timer()
    root, lockfile = _load_target(args)
    packages = lockfile.packages
    _log(args, f"[1/7] lockfile: {len(packages)} pinned packages, {len(lockfile.skipped)} unpinned skipped")
    timer.mark("lockfile")

    hits = osv.query_batch(packages, offline=args.offline)
    advisories = osv.fetch_all(hits, {p.name: p for p in packages}, offline=args.offline)
    unique, merged = osv.deduplicate(advisories)
    _log(args, f"[2/7] osv: {len(advisories)} advisories on {len(hits)} packages, {len(unique)} unique")
    timer.mark("osv")

    unpacked = fetch.fetch_all(packages, workers=args.workers)
    failed = [u for u in unpacked if u.error]
    _log(args, f"[3/7] sources: {len(unpacked) - len(failed)} packages unpacked, {len(failed)} failed")
    timer.mark("fetch")

    index = Index()
    roots = [root] + ([root / "src"] if (root / "src").is_dir() else [])
    for app_root in roots:
        index.add_root(app_root, is_app=True)
    for package in unpacked:
        for source in fetch.source_dirs(package):
            index.add_root(source, package=package.name)
    _log(args, f"[4/7] index: {index.stats()['modules']} modules, {index.stats()['scopes']} functions, "
               f"{index.stats()['parse_errors']} parse errors")
    timer.mark("index")

    graph = CallGraph(index)
    graph.build()
    _log(args, f"[5/7] graph: {graph.stats['call']} call, {graph.stats['ctor']} ctor, "
               f"{graph.stats['import']} import, {graph.stats['ref']} ref, "
               f"{graph.stats['virtual']} virtual edges, {graph.stats['unresolved']} unresolved sites")
    timer.mark("graph")

    entries = discover_entrypoints(index, graph, root, include_tests=False)
    test_entries = discover_entrypoints(index, graph, root, include_tests=True)
    test_only = [e for e in test_entries if e.node not in {x.node for x in entries}]
    kinds: dict[str, int] = {}
    for entry in entries:
        kinds[entry.kind] = kinds.get(entry.kind, 0) + 1
    _log(args, f"[6/7] entry points: {len(entries)} "
               f"({', '.join(f'{k} {v}' for k, v in sorted(kinds.items()))})")
    timer.mark("entrypoints")

    sink_dir = Path(args.sinks).resolve()
    cache = extract.load_cache(sink_dir)
    analyzer = Analyzer(index, graph, entries, test_only)

    findings = []
    by_package = {p.name: p for p in packages}
    for advisory in unique:
        record = cache.get(advisory.id)
        if record is None and args.llm:
            record = extract.extract_with_api(advisory, mode=args.mode)
            if record is not None:
                record.verification = verify.verify_record(record, advisory)
                extract.save(record, sink_dir)
        if record is not None and not record.verification and record.sinks:
            record.verification = verify.verify_record(record, advisory)
            extract.save(record, sink_dir)
        sinks = record.verified_sinks if record else []
        status = record.status if record else "no_record"
        verdict = analyzer.classify(sinks, "verified" if sinks else status, advisory.package)
        taint = None
        if verdict.bucket == REACHABLE and verdict.paths:
            best = verdict.paths[0]
            taint = trace([f.to_dict() for f in best.frames], index, best.entrypoint.kind).to_dict()
        package = by_package[advisory.package]
        findings.append({
            "advisory": advisory.id,
            "cve": advisory.cve,
            "merged_ids": merged.get(advisory.id, []),
            "package": advisory.package,
            "version": advisory.version,
            "direct": package.direct,
            "severity": advisory.severity,
            "summary": advisory.summary,
            "bucket": verdict.bucket,
            "reason": verdict.reason,
            "sinks": sinks or (record.sinks if record else []),
            "sink_status": status,
            "sink_confidence": record.confidence if record else "",
            "sink_mode": record.mode if record else "",
            "assumptions": record.assumptions if record else [],
            "evidence": verdict.evidence,
            "taint": taint,
            "paths": [p.to_dict() for p in verdict.paths],
        })
    timer.mark("reachability")

    findings.sort(key=lambda f: (
        {REACHABLE: 0, UNDETERMINED: 1, UNREACHABLE: 2}[f["bucket"]],
        SEVERITY_ORDER.get(f["severity"], 5), f["package"], f["advisory"]))

    counts = {
        "advisories_raw": len(advisories),
        "advisories_unique": len(unique),
        REACHABLE: sum(1 for f in findings if f["bucket"] == REACHABLE),
        UNDETERMINED: sum(1 for f in findings if f["bucket"] == UNDETERMINED),
        UNREACHABLE: sum(1 for f in findings if f["bucket"] == UNREACHABLE),
        "reachable_direct": sum(1 for f in findings if f["bucket"] == REACHABLE and f["direct"]),
        "reachable_tainted": sum(1 for f in findings
                                 if (f.get("taint") or {}).get("status") == "tainted"),
        "packages_with_advisories": len(hits),
    }
    results = {
        "tool": "sparrow",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": {
            "name": args.name or root.name,
            "root": str(root),
            "roots": [str(r) for r in roots] + [str(Path.home() / ".cache" / "sparrow" / "pkgs")],
            "lockfile": lockfile.packages[0].source if lockfile.packages else "",
        },
        "stats": {
            "packages": len(packages),
            "packages_failed": [f"{u.name}=={u.version}: {u.error}" for u in failed],
            "modules": index.stats()["modules"],
            "files": index.stats()["files"],
            "scopes": index.stats()["scopes"],
            "parse_errors": index.stats()["parse_errors"],
            "native_modules": index.stats()["native_modules"],
            "edges": sum(graph.stats[k] for k in ("call", "ctor", "import", "ref", "virtual")),
            "edge_kinds": dict(graph.stats),
            "entry_points": len(entries),
            "entry_point_kinds": kinds,
            **analyzer.summary(),
        },
        "counts": counts,
        "entry_points": [e.to_dict() for e in entries],
        "findings": findings,
        "timings": timer.marks,
    }
    out = Path(args.out).resolve()
    report.write_json(results, out)
    _log(args, f"[7/7] wrote {_relative(out)}")
    report.render(results, show=args.show, limit=args.limit)
    return 0


def prompts(args) -> int:
    root, lockfile = _load_target(args)
    hits = osv.query_batch(lockfile.packages, offline=args.offline)
    advisories = osv.fetch_all(hits, {p.name: p for p in lockfile.packages}, offline=args.offline)
    unique, _ = osv.deduplicate(advisories)
    out = Path(args.out).resolve()
    have = set(extract.load_cache(Path(args.sinks).resolve()))
    todo = [a for a in unique if a.id not in have] if args.missing_only else unique
    count = extract.emit_prompts(todo, out, mode=args.mode)
    manifest = {a.id: {"package": a.package, "version": a.version, "cve": a.cve,
                       "fixed": a.fixed_versions, "severity": a.severity} for a in todo}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"{count} prompts in {out} (mode {args.mode})")
    return 0


def verify_cmd(args) -> int:
    root, lockfile = _load_target(args)
    hits = osv.query_batch(lockfile.packages, offline=args.offline)
    advisories = osv.fetch_all(hits, {p.name: p for p in lockfile.packages}, offline=args.offline)
    unique, _ = osv.deduplicate(advisories)
    by_id = {a.id: a for a in unique}
    sink_dir = Path(args.sinks).resolve()
    cache = extract.load_cache(sink_dir)
    tally: dict[str, int] = {}
    for advisory_id, record in sorted(cache.items()):
        advisory = by_id.get(advisory_id)
        if advisory is None:
            continue
        if record.verification and not args.force:
            tally[record.status] = tally.get(record.status, 0) + 1
            continue
        record.verification = verify.verify_record(record, advisory)
        extract.save(record, sink_dir)
        tally[record.status] = tally.get(record.status, 0) + 1
        print(f"{advisory_id:<24} {record.status:<22} {', '.join(record.sinks) or '(no sink)'}")
    print()
    for status, count in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>4}  {status}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sparrow", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--target", required=True, help="application directory to analyse")
        p.add_argument("--lockfile", help="explicit lockfile path")
        p.add_argument("--sinks", default="data/sinks", help="directory of extracted sink records")
        p.add_argument("--offline", action="store_true", help="use cached OSV data only")
        p.add_argument("--quiet", action="store_true")

    scan_parser = sub.add_parser("scan", help="run the full analysis")
    common(scan_parser)
    scan_parser.add_argument("--out", default="data/results.json")
    scan_parser.add_argument("--name", help="display name for the target")
    scan_parser.add_argument("--show", default="reachable", choices=["reachable", "undetermined", "all"])
    scan_parser.add_argument("--limit", type=int, default=0)
    scan_parser.add_argument("--workers", type=int, default=12)
    scan_parser.add_argument("--llm", action="store_true", help="extract missing sinks via the API")
    scan_parser.add_argument("--mode", default="advisory+patch", choices=list(extract.MODES))
    scan_parser.set_defaults(func=scan)

    prompts_parser = sub.add_parser("prompts", help="write extraction prompts for the agent")
    common(prompts_parser)
    prompts_parser.add_argument("--out", default="data/prompts")
    prompts_parser.add_argument("--mode", default="advisory-only", choices=list(extract.MODES))
    prompts_parser.add_argument("--missing-only", action="store_true")
    prompts_parser.set_defaults(func=prompts)

    verify_parser = sub.add_parser("verify", help="verify cached sinks against patch diffs")
    common(verify_parser)
    verify_parser.add_argument("--force", action="store_true")
    verify_parser.set_defaults(func=verify_cmd)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
