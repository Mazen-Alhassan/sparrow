"""Build ground truth for sink extraction accuracy.

For each advisory with a linked fix commit, this fetches the changed Python files at the fixed
commit, parses them, and records which functions and classes contain the changed lines. That set is
the answer key: it is derived from the patch alone and never sees the extractor's output.

It is a proxy, not an oracle. A fix commit can touch functions that are not the flaw, and the answer
key is reviewed by hand afterwards. Reviewed corrections live in docs/labels/corrections.json.

    python tools/label.py --target data/sample --out docs/labels
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.sparrow import deps, osv                       # noqa: E402
from src.sparrow.net import context                     # noqa: E402
from src.sparrow.sinks.patches import COMMIT, fetch_patch  # noqa: E402

FILE_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
TEST_PATH = re.compile(r"(^|/)(tests?|testing|benchmarks?|docs?|examples?|dummyserver)(/|$)|"
                       r"(^|/)(test_[^/]+|[^/]+_test|conftest|noxfile|setup)\.py$")


def module_for(path: str) -> str | None:
    if not path.endswith(".py") or TEST_PATH.search(path):
        return None
    parts = path[:-3].split("/")
    if parts and parts[0] in ("src", "lib"):
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or any(not p.isidentifier() for p in parts):
        return None
    return ".".join(parts)


def changed_lines(patch: str) -> dict[str, set[int]]:
    """New-side line numbers touched by the patch, per file."""
    out: dict[str, set[int]] = {}
    current: str | None = None
    line_no = 0
    for line in patch.splitlines():
        header = FILE_HEADER.match(line)
        if header:
            current = header.group(2)
            continue
        hunk = HUNK.match(line)
        if hunk:
            line_no = int(hunk.group(1))
            continue
        if current is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            out.setdefault(current, set()).add(line_no)
            line_no += 1
        elif line.startswith("-") and not line.startswith("---"):
            out.setdefault(current, set()).add(line_no)   # deletion anchors at the next kept line
        elif line.startswith(" "):
            line_no += 1
    return out


def enclosing(source: str, lines: set[int]) -> set[str]:
    """Qualnames of the functions and classes whose bodies contain any of these lines."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()
    found: set[str] = set()

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = f"{prefix}.{child.name}" if prefix else child.name
                start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                end = getattr(child, "end_lineno", start)
                if any(start <= line <= end for line in lines):
                    found.add(qual)
                walk(child, f"{qual}.<locals>" if not isinstance(child, ast.ClassDef) else qual)

    walk(tree, "")
    # Keep only the innermost match per branch: a method beats the class that holds it.
    return {q for q in found if not any(other != q and other.startswith(q + ".") for other in found)}


def raw_url(commit_url: str, path: str) -> str:
    owner, repo, sha = COMMIT.search(commit_url).groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"


def fetch_raw(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "sparrow/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=60, context=context()) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return ""


def label(advisory) -> dict:
    record = {"advisory": advisory.id, "package": advisory.package, "cve": advisory.cve,
              "commits": [], "truth": [], "files": [], "note": ""}
    commits = [r["url"] for r in advisory.references if COMMIT.search(r.get("url", ""))]
    if not commits:
        record["note"] = "no fix commit linked"
        return record
    truth: set[str] = set()
    for commit in commits[:2]:
        owner, repo, _ = COMMIT.search(commit).groups()
        record["commits"].append(f"{owner}/{repo}")
        patch = fetch_patch(commit + ".patch")
        if patch.startswith("__ERROR__"):
            continue
        for path, lines in changed_lines(patch).items():
            module = module_for(path)
            if module is None:
                continue
            source = fetch_raw(raw_url(commit, path))
            if not source:
                continue
            record["files"].append(path)
            for qual in enclosing(source, lines):
                truth.add(f"{module}.{qual}")
    record["truth"] = sorted(truth)
    if not record["truth"] and not record["note"]:
        record["note"] = "fix touches no python function"
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--lockfile")
    parser.add_argument("--out", default="docs/labels")
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    root = Path(args.target).resolve()
    lock = deps.discover(root, Path(args.lockfile).resolve() if args.lockfile else None)
    hits = osv.query_batch(lock.packages)
    advisories = osv.fetch_all(hits, {p.name: p for p in lock.packages})
    unique, _ = osv.deduplicate(advisories)
    unique.sort(key=lambda a: a.id)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    labels = []
    for advisory in unique:
        record = label(advisory)
        if not record["truth"]:
            continue
        labels.append(record)
        print(f"{record['advisory']:<24} {len(record['truth']):>2} functions  "
              f"{', '.join(record['truth'][:2])}")
        if len(labels) >= args.limit:
            break
    (out / "labels.json").write_text(json.dumps(labels, indent=2) + "\n")
    print(f"\n{len(labels)} labelled advisories written to {out / 'labels.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
