"""Rank what defeats the call graph, on a real dependency tree.

Every static analyser for Python has a failure surface. This prints it: how many call sites resolved,
which resolution rule ran out of road on the rest, and which attribute names are most often called on
a receiver whose type is unknown.

    python tools/graph_report.py --target targets/superset --lockfile targets/superset/requirements/base.txt
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.sparrow import deps, fetch                      # noqa: E402
from src.sparrow.callgraph import CallGraph              # noqa: E402
from src.sparrow.entrypoints import discover             # noqa: E402
from src.sparrow.index import Index                      # noqa: E402
from src.sparrow.reach import Analyzer                   # noqa: E402

EXPLANATION = {
    "attribute_on_self_not_a_method": "`self.x.y()` where x is an instance attribute the resolver never typed",
    "parameter_without_annotation": "`def f(conn)` then `conn.execute()`, no annotation to type it",
    "parameter_annotation_unresolved": "annotated, but the annotation is a generic, a string, or outside the tree",
    "local_bound_to_unknown_return": "`x = f()` then `x.y()`, and f has no return annotation",
    "attribute_on_imported_object": "attribute of an imported object that is not a module, class, or function",
    "attribute_on_local_definition": "attribute of a local class or function that is not one of its members",
    "indirect_call_subscript": "`handlers[key]()`, the callee comes out of a container",
    "indirect_call_expression": "`f()()` or `(a or b)()`, the callee is a computed value",
    "unknown_receiver": "the receiving name was never bound anywhere the resolver looked",
    "outside_analysed_tree": "stdlib or a package not in the lockfile",
    "compiled_extension": "the call crosses into a .so or .pyd",
    "builtin": "a builtin, deliberately not an edge",
    "builtin_or_unbound_name": "a bare name that resolved to nothing at all",
    "super_call_unresolved": "`super().m()` where the parent class is outside the tree",
}


DEV = re.compile(r"(^|\.)(tests?|testing|conftest|scripts?|tools|docs?|examples?|benchmarks?|"
                 r"RELEASING|docker|ci|dev)(\.|$)")


def _best_example(examples):
    """Prefer an example from code that ships, not from a release script or a test."""
    for node, target, line in examples:
        if not DEV.search(node.split(":", 1)[0]):
            return node, target, line
    return examples[0] if examples else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--lockfile")
    parser.add_argument("--json", help="write the table here")
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--skip-tests", action="store_true",
                        help="drop test suites, in the target and in every dependency")
    args = parser.parse_args()

    root = Path(args.target).resolve()
    lock = deps.discover(root, Path(args.lockfile).resolve() if args.lockfile else None)
    unpacked = fetch.fetch_all(lock.packages)

    index = Index()
    index.add_root(root, is_app=True, skip_tests=args.skip_tests)
    for package in unpacked:
        for source in fetch.source_dirs(package):
            index.add_root(source, package=package.name, skip_tests=args.skip_tests)
    graph = CallGraph(index)
    graph.build()
    entries = discover(index, graph, root)
    analyzer = Analyzer(index, graph, entries)

    total = graph.call_sites
    resolved = graph.stats["call"] + graph.stats["ctor"]
    builtins = graph.failures.get("builtin", 0)
    print(f"call sites            {total:>10,}")
    print(f"resolved to an edge   {resolved:>10,}  {resolved / total * 100:.1f}%")
    print(f"builtins, skipped     {builtins:>10,}  {builtins / total * 100:.1f}%")
    unresolved = total - resolved - builtins
    print(f"unresolved            {unresolved:>10,}  {unresolved / total * 100:.1f}%")
    print()
    print(f"{'rank':<5} {'count':>10}  {'share':>6}  cause")
    rows = []
    ranked = [(k, v) for k, v in graph.failures.most_common() if k != "builtin"]
    for position, (kind, count) in enumerate(ranked, 1):
        share = count / total * 100
        rows.append({"rank": position, "cause": kind, "count": count, "share": round(share, 2),
                     "explanation": EXPLANATION.get(kind, ""),
                     "example": _best_example(graph.failure_examples.get(kind, []))})
        print(f"{position:<5} {count:>10,}  {share:>5.1f}%  {kind}")
        print(f"{'':<5} {'':>10}          {EXPLANATION.get(kind, '')}")
        example = _best_example(graph.failure_examples.get(kind, []))
        if example:
            print(f"{'':<5} {'':>10}          e.g. {example[1]}() in {example[0]} line {example[2]}")

    names = Counter()
    for sites in graph.unresolved.values():
        for attr, _ in sites:
            if not attr.startswith("native:"):
                names[attr] += 1
    print(f"\nmost frequent unresolved attribute names")
    for name, count in names.most_common(args.top):
        print(f"  {count:>7,}  .{name}()")

    reach = len(analyzer.high.nodes)
    print(f"\nnodes reachable at high confidence  {reach:,} of {sum(len(m.scopes) for m in index.modules.values()):,}")
    if args.json:
        Path(args.json).write_text(json.dumps({
            "call_sites": total, "resolved": resolved, "builtins": builtins,
            "unresolved": unresolved, "causes": rows,
            "top_unresolved_names": names.most_common(args.top),
        }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
