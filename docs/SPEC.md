# SPEC

## What it does

`sparrow` takes a Python application with a pinned lockfile and answers, per advisory:
**can execution reach the vulnerable function from an entry point in this application?**

It does not ask whether a vulnerable version is present in the tree. `pip-audit`, `safety` and
Snyk already answer that, and the answer is a number nobody acts on.

## Input

| Input | Form |
|---|---|
| Target application | A directory containing Python source and a pinned dependency file |
| Lockfile | `requirements*.txt` with `==` pins, `poetry.lock`, `Pipfile.lock`, or `uv.lock` |
| Advisory data | OSV.dev, queried live by package and exact version |
| Sink map | `data/sinks/*.json`, one file per advisory, produced by the extractor and committed |
| Package sources | Wheels or sdists fetched from PyPI into a local cache, never committed |

## Output

`data/results.json` and a terminal report. Every advisory lands in exactly one bucket.

| Bucket | Meaning |
|---|---|
| `reachable` | A concrete call path exists from an entry point to the vulnerable function. The path is in the output. |
| `unreachable` | No path in the static graph. Carries a machine-readable reason code. |
| `undetermined` | A path may exist but static analysis cannot decide: dynamic dispatch, a callback register, a C extension boundary, or no verified function-level sink for the advisory. |

The three-bucket split is the contract. A binary reachable/not-reachable output would be a lie by
omission, because the interesting cases are exactly the ones a static graph cannot settle.

## Guarantees

1. Every reachable finding ships a full call path, file and line for every frame.
2. Every sink used for a reachable or unreachable verdict has been verified against the real patch
   diff: the function exists in the vulnerable version and is absent or changed in the fixed version.
3. An advisory with no verified sink never lands in `unreachable`. It goes to `undetermined`.
4. Unreachable verdicts carry a reason code, not a bare boolean.

## What it explicitly does not do

- **Other languages.** Python only. No Java, no JavaScript, no native code.
- **Exploitability.** Reachable means callable. It does not mean an attacker controls the arguments.
  A reachable finding is a candidate for triage, not a confirmed exploit.
- **Full data flow.** Taint tracking is partial: flow-sensitive inside a function, positional across
  a call, no sanitiser model, no object state, no containers. It answers `tainted`, `clean`, or
  `unknown`, and it prefers `unknown` to a `clean` it cannot justify.
- **Reflection.** `getattr`, `eval`, `importlib`, and plugin loaders are undetermined by construction.
  They are detected and counted, never silently resolved.
- **C extensions.** A call that crosses into a compiled module is opaque. The boundary is recorded.
- **Runtime configuration.** Feature flags, installed plugins, and deployment settings change the real
  entry point set. The tool analyses the source as committed.
- **Patching.** It produces no fix, no PR, no version bump recommendation.

## Success criteria

| Phase | Criterion | Status |
|---|---|---|
| 1 | Answers "does `main` reach `helper.dangerous`" on a three-module app | met, `tests/test_callgraph.py` |
| 2 | Finds Flask, Django, Celery, click, and console_script entry points | met, `tests/test_entrypoints.py` |
| 3 | Sink extraction accuracy measured against a hand-labeled set of 30 advisories | met, `docs/labels/` and FINDINGS.md |
| 4 | Three buckets with reason codes, undetermined reported loudly | met, `src/sparrow/reach.py` |
| 5 | Real run on Apache Superset 3.1.0 with committed results | met, `data/results.json` |
| stretch | Taint from a request parameter to the sink on reachable paths | partial, `src/sparrow/taint.py` |

## Non-goals that were tempting

- A web UI. The output is a call path. A terminal prints call paths well.
- Resolving every dynamic call. The undetermined count is the honest answer and it is the point.
- Supporting unpinned requirements. Without exact versions the advisory match is guesswork.
