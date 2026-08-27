# FINDINGS

Target: **Apache Superset 3.1.0**, `requirements/base.txt`, 129 pinned packages.
Run on 2026-08-18. 23 seconds wall clock with a warm package cache.
Raw output: [`data/results.json`](data/results.json).

OSV returns 137 advisories against 27 of the 129 pinned packages. Merging the GHSA and PYSEC records
that describe the same CVE leaves 76 distinct vulnerabilities. That merge is worth doing before
anything else: a third of the scanner's number is the same flaw counted twice.

| | |
|---|---|
| Advisories reported | 137 |
| Distinct vulnerabilities | 76 |
| Reachable with a call path | 4 |
| Undetermined | 55 |
| Not reachable | 17 |

Four is the number a team acts on. Fifty five is the number that decides whether this tool is honest.

---

## 1. The reachable findings, in full

### CVE-2026-54284  (GHSA-pwgv-4x5q-6m9f)

`sqlparse 0.4.4`, severity high, transitive dependency  
sqlparse: TokenList.__init__ materializes O(subtree) value per group, causing CPU DoS before depth/token caps trigger

Sink: `sqlparse.sql.TokenList.__init__`, `sqlparse.sql.TokenList.group_tokens`  (extraction confidence high, verified against the patch)

```
superset/sqllab/api.py:246                                   SqlLabRestApi.export_csv()
superset/commands/sql_lab/export.py:275                      SqlResultExportCommand.run()
superset/sql_parse.py:118                                    ParsedQuery.__init__()
sqlparse/0.4.4/src/sqlparse/__init__.py:202                  parse()
sqlparse/0.4.4/src/sqlparse/__init__.py:30                   parsestream()
sqlparse/0.4.4/src/sqlparse/engine/filter_stack.py:42        FilterStack.run()
sqlparse/0.4.4/src/sqlparse/engine/statement_splitter.py:31  StatementSplitter.process()
sqlparse/0.4.4/src/sqlparse/sql.py:90                        TokenList.__init__()   <-- vulnerable

entry point: expose('/export/<string:client_id>/')  (http_route)
```

Taint: data flow undetermined, source `SqlLabRestApi.export_csv(client_id)`.  
Run takes no tainted argument, but its receiver was built from client_id, and values carried on object state are not tracked.

What the extractor assumed to produce this sink:

- assumes both changed functions carry the flaw rather than only __init__

### CVE-2023-43804  (GHSA-v845-jxx5-vc9f)

`urllib3 1.26.6`, severity high, transitive dependency  
`Cookie` HTTP header isn't stripped on cross-origin redirects

Sink: `urllib3.util.retry.Retry`  (extraction confidence high, verified against the patch)

```
superset/views/base.py:1                      <module>()
superset/db_engine_specs/gsheets.py:1         <module>()
requests/2.31.0/src/requests/__init__.py:1    <module>()
urllib3/1.26.6/src/urllib3/__init__.py:1      <module>()
urllib3/1.26.6/src/urllib3/util/retry.py:1    <module>()
urllib3/1.26.6/src/urllib3/util/retry.py:602  Retry.__init__()   <-- vulnerable

entry point: superset_app.after_request  (signal_hook)
```

Taint: data flow undetermined.  
Path hop is a import edge, not a call.

What the extractor assumed to produce this sink:

- the sink is a class attribute, so the class node is named instead of a function
- the code that acts on it is HTTPConnectionPool.urlopen, which the fix did not touch

### CVE-2025-68480  (GHSA-428g-f7cq-pgp5)

`marshmallow 3.19.0`, severity moderate, transitive dependency  
Marshmallow has DoS in Schema.load(many)

Sink: `marshmallow.error_store.merge_errors`, `marshmallow.error_store.ErrorStore.store_error`  (extraction confidence high, verified against the patch)

```
superset/annotation_layers/annotations/api.py:250      AnnotationRestApi.post()
marshmallow/3.19.0/src/marshmallow/schema.py:290       Schema.load()
marshmallow/3.19.0/src/marshmallow/schema.py:722       Schema._do_load()
marshmallow/3.19.0/src/marshmallow/schema.py:861       Schema._deserialize()
marshmallow/3.19.0/src/marshmallow/error_store.py:615  ErrorStore.store_error()
marshmallow/3.19.0/src/marshmallow/error_store.py:25   merge_errors()   <-- vulnerable

entry point: expose(POST '/<int:pk>/annotation/')  (http_route)
```

Taint: **request data reaches the arguments**, source `request.json`.  
Request data reaches the vulnerable function's arguments.

What the extractor assumed to produce this sink:

- assumes the quadratic behaviour is in merge_errors rather than in Schema._do_load which calls it once per item

### CVE-2024-37891  (GHSA-34jh-p97f-mpxf)

`urllib3 1.26.6`, severity moderate, transitive dependency  
urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects

Sink: `urllib3.util.retry.Retry`  (extraction confidence medium, verified against the patch)

```
superset/views/base.py:1                      <module>()
superset/db_engine_specs/gsheets.py:1         <module>()
requests/2.31.0/src/requests/__init__.py:1    <module>()
urllib3/1.26.6/src/urllib3/__init__.py:1      <module>()
urllib3/1.26.6/src/urllib3/util/retry.py:1    <module>()
urllib3/1.26.6/src/urllib3/util/retry.py:602  Retry.__init__()   <-- vulnerable

entry point: superset_app.after_request  (signal_hook)
```

Taint: data flow undetermined.  
Path hop is a import edge, not a call.

What the extractor assumed to produce this sink:

- the sink is a class attribute, not a function, so the class node is named instead
- the code that acts on the value is HTTPConnectionPool.urlopen, which the fix did not touch

### The two urllib3 findings are weak, and here is why

Both `urllib3.util.retry.Retry` findings are class level sinks. The fix for each changed
`Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT`, a frozenset in the class body, and no function body
changed at all. The verifier accepted the class node because the class did change between versions,
and the path found is an import time `Retry(3)` at `retry.py:602`.

That is a true statement (the class is constructed on the import path) and a weak finding (the flaw
is a default value, and what matters is whether redirects are followed with a `Cookie` header set).
Function level reachability has nothing useful to say about a vulnerability whose sink is a constant.
It is reported rather than hidden, and it is the clearest example in this run of the tool being
technically right and practically thin.

### Taint: does attacker input actually get there

Reachability says the function is callable. The first question anyone asks next is whether the
attacker controls what it is called with, so the tool answers a narrow version of it: walk the
frames of a reachable path and ask at each hop whether the argument handed forward came from a
request. Sources are the Flask and Django request accessors and the URL path parameters of a route.

| Finding | Taint | Why |
|---|---|---|
| CVE-2025-68480 marshmallow | **tainted** | `request.json` is the argument to `Schema.load` |
| CVE-2026-54284 sqlparse | undetermined | `client_id` reaches the command object's state, not `run()`'s arguments |
| CVE-2023-43804 urllib3 | undetermined | the path hop is an import, which carries no arguments |
| CVE-2024-37891 urllib3 | undetermined | same |

**One of the four is confirmed attacker-controlled end to end.** `AnnotationRestApi.post` runs
`self.add_model_schema.load(request.json)` at `superset/annotation_layers/annotations/api.py:290`,
and `Schema.load` is the function whose error merging is quadratic. Reachable, and reached with a
body the caller writes.

The other three are `unknown`, and the reasons are the honest ones. The sqlparse case is the
instructive one: `SqlResultExportCommand(client_id=client_id).run()` puts the tainted value on the
object and takes it off again inside `run`. Object state is not tracked, so the analysis refuses
rather than reporting `clean`. A false `clean` would be exactly as damaging as a false
`unreachable`, and the receiver check exists to prevent it.

This is a partial answer and it is worth saying how partial. It is flow-sensitive inside a function,
positional across a call, and it treats any function call as passing taint through. It does not
model sanitisers, so a validated value stays tainted. It does not model object state, containers,
or globals. On this run it produced one `tainted`, no `clean`, and three `unknown`.

---

## 2. Why the other 72 were not reachable

### 17 not reachable

| CVE | Package | Severity | Sink | Reason |
|---|---|---|---|---|
| CVE-2024-6827 | gunicorn | high | `gunicorn.http.message.Message.parse_headers` | `module_never_imported` |
| CVE-2024-1135 | gunicorn | high | `gunicorn.http.message.Message.parse_headers` | `module_never_imported` |
| CVE-2026-4539 | pygments | low | `pygments.lexers.archetype.AdlLexer` | `module_never_imported` |
| CVE-2024-26130 | cryptography | high | `cryptography.hazmat.backends.openssl.backend.Backend.serialize_key_and_certificates_to_pkcs12` | `no_call_path` |
| CVE-2023-49083 | cryptography | moderate | `cryptography.hazmat.backends.openssl.backend.Backend._load_pkcs7_certificates` | `no_call_path` |
| CVE-2024-25128 | flask-appbuilder | critical | `flask_appbuilder.security.views.AuthOIDView.login_handler` | `no_call_path` |
| CVE-2025-32962 | flask-appbuilder | moderate | `flask_appbuilder.utils.base.is_safe_redirect_url` | `no_call_path` |
| CVE-2024-45314 | flask-appbuilder | moderate | `flask_appbuilder.security.views.AuthDBView.login` | `no_call_path` |
| CVE-2025-24023 | flask-appbuilder | low | `flask_appbuilder.security.manager.BaseSecurityManager.auth_user_db` | `no_call_path` |
| CVE-2024-56201 | jinja2 | moderate | `jinja2.compiler.CodeGenerator.visit_FromImport` | `no_call_path` |
| CVE-2025-69534 | markdown | moderate | `markdown.htmlparser.HTMLExtractor.parse_html_declaration` | `no_call_path` |
| CVE-2026-48526 | pyjwt | high | `jwt.algorithms.HMACAlgorithm.prepare_key` | `no_call_path` |
| CVE-2026-48522 | pyjwt | moderate | `jwt.jwks_client.PyJWKClient.fetch_data` | `no_call_path` |
| CVE-2026-48524 | pyjwt | low | `jwt.jwks_client.PyJWKClient.get_signing_key` | `no_call_path` |
| CVE-2026-28684 | python-dotenv | moderate | `dotenv.main.rewrite` | `no_call_path` |
| CVE-2024-35195 | requests | moderate | `requests.adapters.HTTPAdapter.send` | `no_call_path` |
| CVE-2026-25645 | requests | moderate | `requests.utils.extract_zipped_paths` | `no_call_path` |

Three of these are the strong kind. `gunicorn.http.message` is never imported from any entry point,
because Superset does not import its WSGI server, the server imports Superset. `pygments.lexers.archetype`
is one of about 500 lexer modules that pygments only loads for a language nobody asked for.

The other 14 are the weaker kind: the module is on the import path but the function is never called
on any static path, and it is not pulled in even when every unresolved call site is allowed to
dispatch by name. Four of them are flask-appbuilder authentication views. That result is correct for
this configuration and misleading in general: `AuthOIDView.login_handler` is unreachable because
Superset 3.1.0 uses database authentication, and the same code becomes reachable the moment a
deployment sets `AUTH_TYPE = AUTH_OID`. A verdict from this tool describes one configuration of one
checkout.

The pyjwt results are the same shape. `PyJWKClient` is only used by applications that fetch JWKS
from a remote issuer, which Superset does not do out of the box.

### 55 undetermined, by cause

| Cause | Count | What it means |
|---|---|---|
| `no_verified_sink` | 21 | No function level sink survived verification, so reachability was never computed |
| `dynamic_dispatch` | 16 | Reachable only when an unresolved call site or a `getattr` is allowed to dispatch by name |
| `callback_reference` | 14 | The function is registered as a value and invoked by a framework, never called directly |
| `virtual_dispatch` | 4 | Reachable only through a subclass override of a called base method |

**The 21 with no verified sink are the biggest single bucket, and 9 of them are cryptography.**
Those advisories are about the OpenSSL that ships statically linked inside the wheel, or about the
Rust path builder, and neither has a Python function to name. The tool cannot say anything about them
beyond "the package is present". That is a real limitation of function level reachability, not a bug:
for a vulnerability in native code the only honest answers are "the package is installed" and
"the boundary is opaque". 129 compiled extension modules were seen in this dependency tree.

The other 12 in that bucket break down as: 2 sinks that existed but were unchanged by the patch,
1 that did not exist in the vulnerable version at all, 1 advisory with no fixed version published,
and 8 where the extractor honestly returned an empty list.

**11 of the 16 `dynamic_dispatch` results are name matches with an unrelated caller.** The
over-approximation lets any unresolved `.flatten()` call stand in for `sqlparse.sql.TokenList.flatten`,
and the nearest such call site in this tree is inside numpy. The output labels these `name match only`
so a reader can discount them, but they are the least useful rows in the report and the place where a
points-to analysis would pay for itself.

Two of the dynamic results are the good kind. `flask_appbuilder.base.py:341` calls
`.register_views()` on an object the resolver cannot type, and that is exactly how
`BaseSecurityManager.register_views` (CVE-2025-58065, the password reset route that stays registered
under OAuth) would be reached. `jinja2/utils.py:149` performs a `getattr(..., "getattr")`, which is
how the sandbox escape in CVE-2024-56326 is reached.

The 14 `callback_reference` results are almost all framework registration. Every jinja2 filter
advisory lands here: `do_xmlattr` is never called by name, it sits in the `FILTERS` dict in
`jinja2/defaults.py` and the template engine looks it up by string at render time. A reachability
tool that resolved that dictionary would move three jinja2 CVEs from undetermined to reachable, and
would be wrong for any application that does not render a template using that filter.

### How much of this depends on excluding test code

Entry point discovery skips the repository's own tests, scripts, and release tooling by default.
That decision is worth a number, because it is the single largest lever on the result.

| | Production only | Including tests and repo tooling |
|---|---|---|
| Entry points | 269 | 2,691 |
| Functions reachable at high confidence | 5,608 | 10,017 |

Superset ships 2,422 test and tooling entry points against 269 production ones, and turning them on
nearly doubles the reachable set. Eight advisories change bucket:

| Advisory | Package | Production only | With tests and tooling |
|---|---|---|---|
| CVE-2026-45409 | idna | undetermined | reachable |
| CVE-2024-3651 | idna | undetermined | reachable |
| CVE-2026-32597 | pyjwt | undetermined | reachable |
| CVE-2024-47081 | requests | undetermined | reachable |
| CVE-2025-50181 | urllib3 | undetermined | reachable |
| CVE-2025-32962 | flask-appbuilder | unreachable | undetermined |
| CVE-2024-45314 | flask-appbuilder | unreachable | undetermined |
| CVE-2025-24023 | flask-appbuilder | unreachable | undetermined |

Fourteen of the seventeen `unreachable` verdicts hold either way. The three that move are the
flask-appbuilder authentication views, which the test suite exercises directly and the default
deployment never routes to. That is the honest shape of the result: a finding is unreachable from the
deployed application, not unreachable from the repository.

---

## 3. Sink extraction accuracy

Answer key: for 30 advisories with a linked fix commit, `tools/label.py` fetches the changed Python
files at the fixed commit, parses them, and records which functions contain the changed lines. That
key is derived from the patch alone. It was reviewed by hand afterwards and one entry was corrected
(`docs/labels/corrections.json`): the brotli advisory's linked commits are in scrapy and in C, so the
key had picked up scrapy functions that are not in the brotli package.

| Mode | Exact | Right function, wrong path | Honest empty | Wrong |
|---|---|---|---|---|
| Advisory text only | 12 / 30 | 4 | 9 | 5 |
| Advisory plus the fix diff | 29 / 30 | 1 | 0 | 0 |

**40% from advisory text alone.** That is the number that matters, because it is what an extractor
gets when a fix commit is not linked, which was the case for 21 of the 76 advisories in this run.

The failures in advisory-only mode fall into four kinds:

1. **Right function, wrong module.** `werkzeug.utils.safe_join` instead of `werkzeug.security.safe_join`,
   twice. The advisory names the function and never says which module holds it. The verifier catches
   this, because the named path does not exist in the package.
2. **Named the public API instead of the flaw.** `marshmallow.schema.Schema.load` for a quadratic
   merge inside `error_store.merge_errors`, and
   `cryptography...pkcs12.serialize_key_and_certificates` for a NULL check inside the openssl backend.
   The advisory describes the symptom at the API boundary, which is where the user experiences it.
3. **Named a plausible neighbour.** `urllib3.response.HTTPResponse._init_decoder` for a chained
   encoding limit that actually landed in `MultiDecoder.__init__`.
4. **Refused.** 9 of 30 returned an empty list with a stated reason. Those cost recall and cost
   nothing in precision, and they are the behaviour the prompt asks for.

The 29/30 in patch mode is not a blind measurement and should not be read as one. The extraction and
the answer key both derive from the same diff, so that number mostly says "a model can read a diff
and name the changed function". It is still worth having, because it puts a ceiling on how much of
the 60% gap is a model problem rather than a data problem: almost all of it closes when the patch is
in the prompt, so the fix is better patch linking, not a better prompt.

**Verification is what makes the extraction safe to use.** Across all 76 advisories: 55 verified,
17 produced no sink, 2 named a function that exists but was unchanged by the patch, 1 named a
function that does not exist in the vulnerable version, and 1 had no published fixed version. Every
one of the last four categories was routed to undetermined. None of them cleared an advisory.

---

## 4. What broke the call graph, ranked

Numbers below are from `tools/graph_report.py --skip-tests`, which builds the same graph with the
test suites of Superset and of all 129 dependencies excluded, so the ranking describes code that
ships rather than code that asserts. Raw table: [`docs/graph-failures.json`](docs/graph-failures.json).

| | Call sites | Share |
|---|---|---|
| Total | 293,962 | |
| Resolved to an edge | 103,322 | 35.1% |
| Builtin, deliberately not an edge | 56,583 | 19.2% |
| Unresolved | 134,057 | 45.6% |

**One call site in three resolves.** That is the honest headline for AST based call graph
construction on real Python, and it is why the undetermined bucket is large and why an `unreachable`
verdict is stated as "no path even under over-approximation" rather than "no path".

| Rank | Count | Share | Cause |
|---|---|---|---|
| 1 | 55,638 | 18.9% | `outside_analysed_tree` |
| 2 | 18,310 | 6.2% | `attribute_on_self_not_a_method` |
| 3 | 17,546 | 6.0% | `parameter_without_annotation` |
| 4 | 15,103 | 5.1% | `local_bound_to_unknown_return` |
| 5 | 8,312 | 2.8% | `indirect_call_subscript` |
| 6 | 4,899 | 1.7% | `attribute_on_imported_object` |
| 7 | 3,679 | 1.2% | `parameter_annotation_unresolved` |
| 8 | 1,986 | 0.7% | `compiled_extension` |
| 9 | 1,092 | 0.4% | `indirect_call_expression` |
| 10 | 919 | 0.3% | `builtin_or_unbound_name` |
| 11 | 554 | 0.2% | `super_call_unresolved` |
| 12 | 475 | 0.2% | `attribute_on_local_definition` |
| 13 | 57 | 0.0% | `unknown_receiver` |

What each of the top causes actually is, with a real example from the run:

**1. `outside_analysed_tree`, 55,638 sites.** Stdlib or a package not in the lockfile.
   Example: `ADVANCED_DATA_TYPES.get()` in `superset.advanced_data_type.api:AdvancedDataTypeRestApi.get` line 97.

**2. `attribute_on_self_not_a_method`, 18,310 sites.** `self.x.y()` where x is an instance attribute the resolver never typed.
   Example: `self._load_explore_json_into_cache_job.delay()` in `superset.async_events.async_query_manager:AsyncQueryManager.submit_explore_json_job` line 195.

**3. `parameter_without_annotation`, 17,546 sites.** `def f(conn)` then `conn.execute()`, no annotation to type it.
   Example: `kwargs.get()` in `superset.async_events.async_query_manager:build_job_metadata` line 46.

**4. `local_bound_to_unknown_return`, 15,103 sites.** `x = f()` then `x.y()`, and f has no return annotation.
   Example: `addon.translate_type()` in `superset.advanced_data_type.api:AdvancedDataTypeRestApi.get` line 106.

**5. `indirect_call_subscript`, 8,312 sites.** `handlers[key]()`, the callee comes out of a container.
   Example: `append()` in `superset.advanced_data_type.plugins.internet_address:cidr_func` line 48.

**6. `attribute_on_imported_object`, 4,899 sites.** Attribute of an imported object that is not a module, class, or function.
   Example: `event_logger.log_this_with_context()` in `superset.advanced_data_type.api:<module>` line 58.

### What this says about where the effort goes

Discount rank 1. `outside_analysed_tree` is 18.9% of all call sites and almost all of it is the
standard library, which is correctly not in the graph: nothing in the lockfile is `os.path` and no
advisory points there. Strip it out and the picture is much sharper.

**Three causes account for nearly all of the addressable failure, and all three are the same
problem: no type for the receiver.**

| Cause | Sites | What would fix it |
|---|---|---|
| `attribute_on_self_not_a_method` | 18,310 | Track `self.x = expr` for every expression, not only constructor calls |
| `parameter_without_annotation` | 17,546 | Nothing static. This needs inference across call sites, or running the program |
| `local_bound_to_unknown_return` | 15,103 | Propagate return types through unannotated functions, which is inference again |

Together they are 51,000 call sites, about 17% of the total, and they are one missing capability:
a points-to analysis. Everything the resolver does well (import aliases, re-exports through
`__init__.py`, MRO lookups, constructor bindings, parameter annotations, `super()`) is a cheap
approximation of it, and the remaining 17% is the part that will not yield to cheap approximations.

Three smaller results were worth the fixes they prompted:

- `super().m()` was 3,885 unresolved sites before it was handled, and 554 after. The residual is
  entirely classes whose parent lives outside the analysed tree. Resolving it added 2,412 edges.
- `indirect_call_subscript` at 8,312 sites is the plugin registry pattern, and it is exactly what
  the undetermined bucket exists for. It cannot be resolved without knowing container contents.
- `compiled_extension` is only 1,986 call sites, which is smaller than the C boundary's reputation
  suggests. The real cost of native code here is not the calls into it, it is the 9 cryptography
  advisories that have no Python function to name at all.

### The attribute names that go unresolved most often

| Count | Attribute |
|---|---|
| 4,397 | `.get()` |
| 3,019 | `.append()` |
| 2,683 | `.join()` |
| 2,122 | `.format()` |
| 1,953 | `.update()` |
| 1,479 | `.pop()` |
| 1,343 | `.items()` |
| 895 | `.add()` |
| 873 | `.split()` |
| 853 | `.execute()` |
| 821 | `.group()` |
| 811 | `.replace()` |

This list is the reason name based dispatch in the over-approximation is filtered against builtin
attribute names. The top seven are all `dict`, `list`, or `str` methods called on a value the
resolver could not type. Letting `.get()` match every function named `get` in every imported module
would put most of the dependency tree in the undetermined bucket and mean nothing.

---

## 5. What the adversary found

The `adversary` agent was told that finding a flaw is the success condition, and that a case only
counts when the sink provably executes and the tool says `unreachable`. It wrote ten applications.
Its report is [`tests/adversarial/RESULTS.md`](tests/adversarial/RESULTS.md), written before any fix.

**First pass: 10 hits out of 10 cases.** Every construct it tried produced a confident `unreachable`
for a function that printed `SINK EXECUTED` on every run.

| Construct | Before | After |
|---|---|---|
| `getattr(mod, name)()` with a computed name | unreachable | undetermined |
| dict of handlers built by `getattr`, dispatched by key | unreachable | undetermined |
| `importlib.import_module(prefix + suffix)` | unreachable | undetermined |
| `exec` of generated source | unreachable | **reachable** |
| metaclass `__call__` | unreachable | **reachable** |
| `__init_subclass__` hook | unreachable | **reachable** |
| module level `__getattr__` (PEP 562) | unreachable | undetermined |
| `functools.partial` stored in a list | unreachable | undetermined |
| monkeypatched method (`Service.handle = bad`) | unreachable | undetermined |
| descriptor `__get__` on attribute read | unreachable | undetermined |

**Second pass: 0 hits out of 10.** Three cases became precisely reachable rather than merely
undetermined, which is a resolution improvement and not a bucket shuffle. The fixes, in the order the
adversary forced them:

- A call whose callee is an expression (`getattr(...)()`, `handlers[k]()`) used to produce no edge
  and no unresolved entry, so it was absent from the arithmetic entirely. It is now recorded.
- `getattr(obj, computed)` now keeps the receiver. The name is unknowable, but the receiving module
  or class bounds what can be dispatched, and everything in it enters the undetermined set.
- `exec` and `eval` on a string literal, including one bound to a local name, are parsed and their
  imports and calls folded into the enclosing scope.
- A computed module name or unparseable generated source now marks the site opaque, which seeds every
  application module as dynamically importable rather than letting `module_never_imported` stand.
- Metaclass `__call__` is resolved at construction sites, and `__init_subclass__` is linked from the
  module scope of every subclass, because both run without a call site in the source.
- Module level `__getattr__` answers attribute lookups the module does not define.
- Descriptors stored in a class body are linked to their `__get__`, `__set__`, and `__set_name__`.
- A class attribute rebind (`Service.handle = bad`) records the right hand side as a callback.

All ten are now regression tests in `tests/test_adversarial.py`. Each test runs the application and
asserts the sink actually executes, then asserts the tool never returns `unreachable`.

### What is still broken

**Monkeypatching produces a confident wrong path.** Case 9 is fixed only in the sense that `bad` is
now undetermined instead of unreachable. The class body still contains `def handle(self)`, and
`s.handle()` still resolves to it with a high confidence `call` edge, so the tool prints a clean path
to a function that is dead at runtime. A reader has no way to tell that path from a correct one. This
is the worst residual defect in the tool and it is not fixed.

**Name based dispatch is crude.** The `name match only` label exists because 11 of 16 dynamic results
attribute a sink to a caller in an unrelated package. It is sound as an over-approximation and it is
noise as a report.

**Two constructs were never tried.** The adversary did not attempt C extension callbacks or
`sys.settrace`, and neither is modelled.

Separately, and not from the adversary: Superset's 293 alembic migration files are not indexed at all,
because their filenames start with a date and are not valid Python module names. Alembic loads them by
path. Any vulnerability reachable only from a migration is invisible to this tool.

---

## 6. What I would tell a team acting on this

Fix the sqlparse finding first and treat the rest of the reachable list as a queue rather than a
verdict. `CVE-2026-54284` has a call path from an authenticated CSV export endpoint straight into the
quadratic constructor, the path is eight frames with no guessed hops, and the fix is a version bump.
The two urllib3 rows are real but thin, because their sink is a class attribute and reachability of a
constant tells you very little. Then look at the undetermined bucket rather than the unreachable one:
55 rows is far more than 4, and the 21 with no verified sink are almost all native code where this
kind of analysis has nothing to offer and a version bump is the only answer. Do not treat `not
reachable` as `not vulnerable`. It means no path exists in this checkout with this configuration, and
four of the seventeen are authentication views that light up the moment somebody sets `AUTH_TYPE`
to something other than the default.

On how far to trust any of it: one call site in three resolves to an edge, and the largest single
addressable cause of the rest is that the receiver of a method call has no type the analyser could
work out. That is a ceiling on this technique, not a bug in this build of it. What the tool buys is a
defensible ordering of 76 rows, not a proof about any of them. Use the four with paths to argue for
an upgrade window, use the 21 native-code rows to argue that reachability analysis is the wrong tool
for those and they should be patched on schedule, and re-run it after any change to `AUTH_TYPE`,
installed plugins, or the set of enabled feature flags, because all three change the answer.
