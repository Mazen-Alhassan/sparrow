# Adversarial pass on `sparrow`

Goal: get the tool to say `unreachable` for a `bad()` sink that provably executes when the
application is run directly (`python3 app.py`). A verdict of `undetermined` is not a win — the
tool was honest there. Only `unreachable` counts.

Every case below is a two-file application (`app.py` entry point + `vuln.py` sink module) in its
own `case_N_*` directory. Each was run with plain `python3 app.py` and printed `SINK EXECUTED`
before the tool was pointed at it via `conftest.analyse(...)` + `Analyzer.classify(["vuln.bad"],
"verified", "x")`. Both `app.py` entry points the tool discovers on every case
(`app_factory` from the `main` name, and `main_guard` from `if __name__ == "__main__":`) are
legitimate, generous entry points — the failures below are all in the call-resolution step, not in
entry point discovery.

## Results

| # | Case | Construct | Sink executes? | Bucket | Reason | Verdict |
|---|------|-----------|-----------------|--------|--------|---------|
| 1 | `case_1_getattr_chained_call` | `getattr(vuln, name)()` — call result of a nested `Call` is itself called | yes | unreachable | no_call_path | **hit** |
| 2 | `case_2_dict_handler_getattr_comp` | dict comprehension `{n: getattr(vuln, n) for n in NAMES}` dispatched via `HANDLERS[key]()` | yes | unreachable | no_call_path | **hit** |
| 3 | `case_3_importlib_computed_name` | `importlib.import_module(prefix + suffix)` (concatenated, non-literal module name) then `mod.bad()` | yes | unreachable | module_never_imported | **hit** |
| 4 | `case_4_exec_generated_source` | `exec("from vuln import bad\nbad()\n")` | yes | unreachable | module_never_imported | **hit** |
| 5 | `case_5_metaclass_call` | metaclass `__call__` runs `bad()` before delegating to `Service()`'s real `__init__` | yes | unreachable | no_call_path | **hit** |
| 6 | `case_6_init_subclass_hook` | `Base.__init_subclass__` calls `bad()`; fires automatically when `class Child(Base): pass` is defined | yes | unreachable | no_call_path | **hit** |
| 7 | `case_7_module_getattr_pep562` | module-level `def __getattr__(name)` (PEP 562) calls `bad()` on `vuln.trigger` access | yes | unreachable | no_call_path | **hit** |
| 8 | `case_8_partial_in_list` | `functools.partial(getattr(vuln, name))` stored in a list, invoked via `tasks[i]()` | yes | unreachable | no_call_path | **hit** |
| 9 | `case_9_monkeypatch_rebind` | `Service.handle = bad` at module import time, shadowing the real (inert) `def handle(self)` in the class body | yes | unreachable | no_call_path | **hit** |
| 10 | `case_10_descriptor_get` | data descriptor `Trigger.__get__` calls `bad()`; fires on plain attribute read `s.thing`, no call syntax at all | yes | unreachable | no_call_path | **hit** |

**10 / 10 hits.**

## Why each one slips through

**Case 1 — `getattr(vuln, name)()`.** `visit_Call` in `index.py` only recognizes a call target
as a dotted `Name`/`Attribute` chain (`dotted(node.func)`). When `node.func` is itself a `Call`
(the result of `getattr(...)`), neither branch fires; the outer call is recorded with
`target=None, attr=None` and produces no edge and no entry in `unresolved`. The inner
`getattr(vuln, name)` call *is* recorded as a `getattr` marker, but since `name` is a variable, no
string literal is captured, so `Marker.detail` stays as the generic word `"getattr"` instead of
`"bad"` — the one piece of information (`BUILTIN_ATTRS`/name-based closure) that would have
recovered it is exactly the thing that got thrown away.

**Case 2 — dict-comprehension of `getattr`-built handlers.** Same non-literal-getattr blindness as
case 1, plus `HANDLERS[key]()` is a `Subscript` call, which — like case 1 — hits the `else`
branch of `visit_Call` with `attr=None`. Two independent resolver gaps stack, and neither the
dict values nor the dispatch call ever reference the literal name `"bad"` anywhere the
name-based closure (`nodes_by_name`) can see.

**Case 3 — `importlib.import_module(prefix + suffix)`.** `_dynamic_import_seeds` only seeds a
module from `_app_strings`, which `visit_Constant` populates from string *literals* — a
`BinOp` (string concatenation) is never a `Constant`, so `"vuln"` never enters `_app_strings`.
The module is also never a static `import` anywhere. Result: `vuln` never enters
`imported_modules` at all, so even the fallback name-based dispatch for `mod.bad()` (which does
correctly resolve to `unresolved("bad")`) is gated out by `candidate.split(":",1)[0] not in
imported`. The entire module is invisible, hence `module_never_imported` — the tool's most
confident-sounding reason code, applied to code that unconditionally runs on every invocation.

**Case 4 — `exec(code_string)`.** `exec`/`eval` are recorded as `DYNAMIC_KINDS` markers purely for
statistics (`dynamic_sites_in_reachable_code`); unlike `getattr`/`import`/`entry_points`, their
marker kind is never consulted in `_dynamic_closure`. The tool never parses the string argument,
so a call graph built entirely inside a string literal is 100% opaque to it — no edge, no
unresolved entry, nothing.

**Case 5 — metaclass `__call__`.** `_emit`'s class-construction handling does
`find_in_mro(*value.split(":",1), "__call__")` against the *instantiated class's own* MRO
(`Service`), never against its metaclass (`Meta`). Python's actual dispatch — the metaclass's
`__call__` runs first and decides whether/how to build the instance — has no analogue in the
resolver, so `Meta.__call__` (and the `bad()` call inside it) is never linked to the `Service()`
call site anywhere.

**Case 6 — `__init_subclass__`.** This hook is invoked implicitly by the interpreter the moment a
subclass statement executes (`class Child(Base): pass`), with no source-level call anywhere. The
resolver has no notion of implicit class-creation hooks, so `Base.__init_subclass__` is a scope
with zero inbound edges — permanently outside every traversal frontier, even though it runs before
any of `main()`'s own code.

**Case 7 — module-level `__getattr__` (PEP 562).** `vuln.trigger` resolves through
`_resolve_member`, finds no scope/class/alias named `"trigger"`, and returns
`("unresolved", "trigger")`. But this happens inside the *ref* handling path
(`_build_scope`'s `for ref in set(scope.refs)` loop), which only turns `("func", …)` /
`("class", …)` results into edges and silently drops anything else — unlike the *call* path, it
does not even register the miss in `self.unresolved`. So this construct leaves no trace at all,
not even a marker; `DYNAMIC_CALLS` has no entry for a *definition* named `__getattr__`, only for
calls to the builtin `getattr`.

**Case 8 — `functools.partial(getattr(vuln, name))` in a list.** `functools.partial` isn't in
`DYNAMIC_CALLS` and isn't a known module, so it resolves as `("external", …)` with no edge — that
part is expected. The interesting failure is that the *argument* to `functools.partial`,
`getattr(vuln, name)`, is a `Call` rather than a bare `Name`, so it never goes through the
`_visit_value` fast path that would otherwise capture a literal callable reference as a `ref`
edge (that fast path is exactly why the parallel construction `functools.partial(bad)` — passing
the name directly — *would* have been caught as `callback_reference`). Wrapping the real callable
in one more layer of indirection (`getattr` with a non-literal name) is enough to fall outside
every edge-producing code path, and the subsequent `tasks[i]()` dispatch is a `Subscript` call
(same blind spot as cases 1 and 2).

**Case 9 — monkeypatch / class attribute rebinding (`Service.handle = bad`).** `visit_Assign`'s
`_bind` helper only tracks two shapes: `self.x = …`/`cls.x = …` inside a method, and a plain
`Name` target. `Service.handle = bad` is neither (its target is `Attribute` with a *class* name,
not `self`/`cls`) — `_bind` returns immediately without recording anything, and because the
right-hand side is a bare `Name` visited only through `self.visit(node.value)` (not
`_visit_value`), it isn't captured as a ref either. This is the most dangerous shape of the ten:
the class body still contains a normal `def handle(self): return "original"`, so `s.handle()`
resolves cleanly to a real, high-confidence call edge — the tool reports a *confident, correct
looking* path to a function that is dead code at runtime, while the function that actually runs
(`bad`, installed by the rebind one line later) has no inbound edge from anywhere and is filed as
unreachable.

**Case 10 — descriptor `__get__`.** `thing = Trigger()` sits in the class body, which is indexed
with the *enclosing* scope (there is no dedicated `Scope` object for a class body) — so the
binding lands in the module's `bindings` dict rather than `ClassInfo.attrs`, which is populated
only by the `self.x = …` convention. `s.thing` therefore resolves through neither
`find_in_mro` nor `_class_attr` and falls out as `("unresolved", "thing")` — again through the
*ref* path, which drops unresolved results without a trace, exactly as in case 7. Nothing about
this construct even involves call syntax; a plain attribute read is enough to run `bad()`, and the
resolver's property-closure mechanism only fires for `@property`-decorated methods whose name
matches the accessed attribute — a raw descriptor's `__get__` (a differently-named method) never
matches.

## Pattern across all ten

Two structural gaps account for essentially everything above:

1. **`visit_Call`'s target detection is purely syntactic** (`dotted(node.func)` on
   `Name`/`Attribute` chains only). Any call whose callee is itself the result of an expression —
   `getattr(...)()`, `HANDLERS[key]()`, `tasks[i]()` — degrades to `target=None, attr=None`,
   which produces *no* edge and *no* `unresolved` entry, i.e. it is not merely low-confidence, it
   is completely absent from every bucket's math.
2. **Implicit-dispatch protocols have no model at all**: metaclass `__call__`,
   `__init_subclass__`, module `__getattr__`, and descriptor `__get__` are all cases where CPython
   invokes user code without any corresponding `Call` node in the source the reader is looking at.
   The resolver's entire worldview is "an edge exists only where an AST `Call` node points at a
   resolvable name," so any of Python's several implicit-invocation hooks are categorically
   invisible, not just imprecisely modeled.

Case 3/4 additionally show that the *module-import* gate (`imported_modules`) is only as strong as
the literal-string capture (`visit_Constant`) and the static `import`/`from import` statements —
one string concatenation or one `exec` is enough to remove a whole module from consideration, at
which point the `unreachable` reason code most likely to be trusted at a glance
(`module_never_imported`) gets attached to code that runs unconditionally.
