# ARCHITECTURE

Six modules, one direction of data flow, one schema locked before any of it was written.

```
  lockfile ────▶ deps.py ────▶ [Package]  ────────────────┐
                                  │                       │
                                  ▼                       ▼
                              fetch.py               osv.py ──▶ [Advisory]
                          (PyPI wheel cache)              │
                                  │                       ▼
                                  │                  sinks/extract.py   (LLM, offline cache)
                                  │                       │
                                  │                       ▼
                                  │                  sinks/verify.py    (deterministic, patch diff)
                                  │                       │
                                  ▼                       ▼
                          index.py ──▶ callgraph.py ──▶ [Sink]
                          (AST module    (nodes, edges,
                           index)         dynamic markers)
                                  │
                                  ▼
                          entrypoints.py ──▶ [EntryPoint]
                                  │
                                  ▼
                              reach.py   BFS, three buckets
                                  │
                                  ▼
                              report.py  ──▶ results.json, terminal, FINDINGS.md
```

## Module boundaries

| Module | Owns | Never does |
|---|---|---|
| `deps.py` | Lockfile parsing, direct vs transitive | Network |
| `fetch.py` | PyPI download, unpack, cache | Parsing Python |
| `osv.py` | OSV query and advisory normalisation | Deciding what is vulnerable |
| `sinks/extract.py` | Advisory prose to candidate function ids | Trusting its own output |
| `sinks/verify.py` | Proving a sink exists and changed in the patch | Calling an LLM |
| `index.py` | File to module mapping, AST defs, imports, class bases | Resolving calls |
| `callgraph.py` | Call resolution, edges, dynamic markers | Knowing what an entry point is |
| `entrypoints.py` | Entry point discovery | Traversal |
| `reach.py` | BFS, bucket assignment, reason codes | Formatting |
| `taint.py` | Request sources to sink arguments, on reachable paths only | Deciding reachability |
| `report.py` | Terminal, JSON, FINDINGS | Analysis |

The rule that matters: `callgraph.py` does not know what a vulnerability is, and `reach.py` does not
know what an AST is. Sinks are strings in the same namespace the index produces, and that is the only
coupling between the vulnerability half and the program-analysis half.

## The data schema

Locked before implementation. Everything downstream depends on it.

### Node id

```
"<module>:<qualname>"        superset.views.core:Superset.explore
"<module>:<module>"          jinja2.sandbox:<module>      module-level scope
```

The module part is the importable dotted name. The qualname part is Python's own `__qualname__`, so
`Class.method`, `Class.method.<locals>.inner` for closures. A sink string like
`jinja2.sandbox.SandboxedEnvironment.call` is resolved to a node id by taking the longest prefix that
is a known module.

### Package

```json
{"name": "jinja2", "version": "3.1.2", "direct": true, "source": "requirements/base.txt"}
```

### Advisory

```json
{
  "id": "GHSA-h5c8-rqwp-cp95",
  "aliases": ["CVE-2024-22195"],
  "package": "jinja2",
  "version": "3.1.2",
  "severity": "moderate",
  "summary": "Jinja2 vulnerable to HTML attribute injection",
  "details": "...",
  "fixed_versions": ["3.1.3"],
  "references": [{"type": "FIX", "url": "https://github.com/pallets/jinja/commit/..."}]
}
```

### Sink

```json
{
  "advisory": "GHSA-h5c8-rqwp-cp95",
  "package": "jinja2",
  "sinks": ["jinja2.filters.do_xmlattr"],
  "confidence": "high",
  "evidence": "fix commit 716795349a41d4983a9a4771f7d883c96ea17be7 modifies do_xmlattr",
  "assumptions": ["assumes the vulnerability is in the modified function, not in a caller"],
  "mode": "advisory+patch",
  "verification": {
    "jinja2.filters.do_xmlattr": {
      "status": "verified",
      "present_in_vulnerable": true,
      "changed_in_fixed": true,
      "vulnerable_version": "3.1.2",
      "fixed_version": "3.1.3"
    }
  }
}
```

`status` is one of `verified`, `absent_in_vulnerable`, `unchanged_in_fixed`, `package_missing`.
Only `verified` sinks are allowed to produce an `unreachable` verdict.

### Finding

```json
{
  "advisory": "GHSA-h5c8-rqwp-cp95",
  "cve": "CVE-2024-22195",
  "package": "jinja2",
  "version": "3.1.2",
  "direct": true,
  "severity": "moderate",
  "bucket": "reachable",
  "reason": "call_path",
  "sinks": ["jinja2.filters.do_xmlattr"],
  "sink_status": "verified",
  "paths": [
    {
      "sink": "jinja2.filters.do_xmlattr",
      "entrypoint": {"kind": "flask_route", "node": "app.views:index", "detail": "GET /"},
      "frames": [
        {"node": "app.views:index", "file": "app/views.py", "line": 12, "edge": "call"},
        {"node": "jinja2.filters:do_xmlattr", "file": ".../jinja2/filters.py", "line": 250, "edge": "call"}
      ]
    }
  ]
}
```

### Reason codes

| Bucket | `reason` | Meaning |
|---|---|---|
| reachable | `call_path` | High confidence edges only: direct call, constructor, import side effect |
| unreachable | `module_never_imported` | The sink's module is not in the import closure of any entry point |
| unreachable | `no_call_path` | Module is imported, function is never called on any static path |
| unreachable | `dev_or_test_only` | Only reachable from test or dev tooling entry points |
| undetermined | `dynamic_dispatch` | Reachable code performs `getattr`/`eval`/`importlib` and the sink module is in the import closure |
| undetermined | `callback_reference` | The sink or a caller of it is referenced as a value, never called directly |
| undetermined | `native_boundary` | The path crosses into a compiled extension |
| undetermined | `no_verified_sink` | Extraction failed or verification failed; only package-level reachability is known |
| undetermined | `virtual_dispatch` | Path exists only through a subclass override of a called method |

## Edge kinds and confidence

| Kind | Meaning | Confidence | Counts toward reachable |
|---|---|---|---|
| `call` | Resolved direct call | high | yes |
| `ctor` | `C()` to `C.__init__` | high | yes |
| `import` | Import statement to the imported module's top-level scope | high | yes |
| `ref` | Function object referenced without being called | medium | no, undetermined only |
| `virtual` | Call on a base method, edge to a subclass override | medium | no, undetermined only |

The high set is deliberately narrow. Widening it inflates the reachable count, which is the number a
reader will check by hand, and one wrong path costs more than ten honest undetermined entries.

`import` is a high-confidence edge because module top-level code runs on import. A vulnerable function
called at import time is reachable, and tools that only walk call edges miss it.

## Call resolution

Flow-insensitive, intra-procedural type tracking, per scope:

1. `Name(f)` — enclosing scopes, then module-level defs, then module import aliases.
2. `Attribute(Name(a), f)` — `a` as an import alias resolves to a module; `a` as a local bound to
   `C()` or annotated `a: C` resolves through the MRO; `a` as `self` or `cls` resolves through the
   enclosing class MRO.
3. `Attribute` chains resolve the longest module prefix first.
4. Constructor calls add a `ctor` edge and bind the target name's type for later attribute calls.
5. Anything else is an unresolved call site, recorded on the node with the attribute name. Unresolved
   call sites are the raw material of the undetermined bucket, not something to be hidden.

Parameter annotations are used for type binding. They are free precision in any codebase written
after 2018 and they are the single highest-yield resolution rule after import aliases.

## Undetermined logic

For a sink not in the high-confidence reachable set:

1. Sink module not in the import closure of entry points, and not reachable by `ref`/`virtual`
   edges, and no dynamic marker in reachable code can reach it: `unreachable`.
2. Sink reachable when `ref` or `virtual` edges are added: `undetermined`, with the medium-confidence
   path attached so a human can check it.
3. Sink module in the import closure and some reachable node has a dynamic marker whose module can
   import the sink module: `undetermined / dynamic_dispatch`.
4. Sink is in, or behind, a compiled extension: `undetermined / native_boundary`.
5. No verified sink at all: `undetermined / no_verified_sink`, always, regardless of the graph.

## Decisions and their costs

**AST, not PyCG.** PyCG is unmaintained and fails on modern syntax. Writing the resolver means owning
the failure modes, which is the part of this problem worth understanding. The cost is that the
resolver is less precise than a full points-to analysis, and everything it cannot resolve had to
become a bucket rather than a guess.

**Wheels, not an installed venv.** Installing 127 pinned packages under a modern interpreter fails on
old C extensions. Wheels are downloaded and unpacked directly, so the analysis works on versions that
will not build. The cost is that the wheel layout has to be mapped to module names by hand.

**Import edges are high confidence.** This finds import-time sinks that call-edge-only tools miss. The
cost is that a module imported for one unrelated function marks the whole module's top-level as
reachable, which is true but coarse.

**Sinks are verified against the patch, not trusted.** An unverified sink cannot clear an advisory.
The cost is that packages whose fix commit is not linked stay in undetermined forever.

**Undetermined is a first-class bucket, not an error state.** The cost is a bigger number in the
middle column and a longer README section.

## Changes the adversary forced

The design above is what the architect specified. These are the parts that only exist because the
adversary agent broke the original resolver on ten sample applications, all of which were reported
`unreachable` while provably executing their sink. The full report is `tests/adversarial/RESULTS.md`.

| Construct | Mechanism added |
|---|---|
| `getattr(mod, computed)()` | `getattr_any` marker keeps the receiver. Every function in the receiving module or class becomes a closure candidate. |
| `handlers[k]()`, `getattr(...)()` | A call whose callee is an expression is now recorded as an unresolved site instead of vanishing. |
| `exec` / `eval` of a literal | The string is parsed and its imports and calls are folded into the enclosing scope. A literal bound to a local name is followed. |
| computed module name, unparseable source | `opaque` marker. Every application module becomes a dynamic import seed rather than staying unreachable. |
| metaclass `__call__` | Resolved at every construction site through the metaclass, not the class. |
| `__init_subclass__` | Linked from the module scope of each subclass, because the subclass statement is the call site. |
| module level `__getattr__` | Answers attribute lookups the module does not define. |
| descriptors in a class body | `__get__`, `__set__` and `__set_name__` linked as `ref` edges from the module scope. |
| `Service.handle = other` | The right hand side is recorded as a callback reference. |

Two frame kinds were added to the output so a guessed hop is visible in a printed path: `dynamic`
for a name based dispatch and `property` for a property read. `dynamic_import` marks a module that
entered the graph only because its name appeared as a string.

One correction came from reading the output rather than from the adversary. `C()` used to add a high
confidence `call` edge to `C.__call__`, which is wrong: constructing a callable object does not call
it. It is now a `ref` edge, which moved two findings out of `reachable` and into `undetermined`.

## The taint pass

Added last, after the three buckets were stable, and deliberately kept outside the reachability
decision. It runs only on paths that are already `reachable`, so it can never move a finding into or
out of a bucket. Its only job is to add one field.

```json
{"status": "tainted|clean|unknown", "reason": "...", "source": "request.json",
 "broke_at": "module:qualname", "hops": ["caller -> callee carrying request.json"]}
```

Sources are the Flask and Django request accessors (`request.args`, `.form`, `.json`, `.headers`,
`.cookies`, `.files`, `.get_json()`, and the Django spellings) plus the parameters of an
`http_route` entry point, which is how URL path converters arrive.

Propagation is flow-sensitive within a function and positional across a call. Any function call is
treated as passing taint through, which over-approximates in the direction of `tainted`. The one
place it deliberately refuses to answer is when the tainted value reaches the receiver of a call
rather than its arguments: `Command(client_id=tainted).run()` puts the value on object state, which
is not tracked, so the verdict is `unknown` and not `clean`. A wrong `clean` costs the same as a
wrong `unreachable` and the rule exists to avoid it.
