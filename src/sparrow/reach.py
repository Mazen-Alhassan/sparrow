"""Reachability analysis and bucket assignment.

Two traversals. The first uses only high confidence edges and produces the `reachable` bucket, which
is the number a reader will check by hand. The second adds medium confidence edges and produces part
of `undetermined`. Everything the traversals cannot settle is classified by an explicit rule with a
reason code attached, and nothing falls through to a default.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .callgraph import HIGH_CONFIDENCE, MEDIUM_CONFIDENCE, CallGraph
from .entrypoints import EntryPoint
from .index import Index

REACHABLE = "reachable"
UNREACHABLE = "unreachable"
UNDETERMINED = "undetermined"

ALL_EDGES = HIGH_CONFIDENCE + MEDIUM_CONFIDENCE
DYNAMIC_KINDS = {"getattr", "getattr_any", "import", "opaque", "entry_points", "plugin_scan",
                 "namespace", "eval", "exec"}
IMPORT_KINDS = {"import", "opaque", "entry_points", "plugin_scan"}

# An unresolved `.format()` is a string method far more often than it is a call into sqlparse.
# Matching those names by hand would turn the over-approximation into noise, so attribute names that
# exist on a builtin type are not used for name based dispatch. The cost is a false negative
# whenever a library function shares a name with a builtin method, and that cost is documented.
BUILTIN_ATTRS = frozenset(
    name for kind in (str, bytes, list, dict, set, tuple, int, float, object, BaseException)
    for name in dir(kind)
) | {"read", "write", "close", "seek", "flush", "fileno", "readline", "readlines", "writelines",
     "group", "groups", "match", "search", "sub", "finditer", "next", "send", "throw"}


@dataclass
class Frame:
    node: str
    file: str
    line: int
    edge: str

    def to_dict(self) -> dict:
        return {"node": self.node, "file": self.file, "line": self.line, "edge": self.edge}


@dataclass
class Path:
    sink: str
    entrypoint: EntryPoint
    frames: list[Frame]

    def to_dict(self) -> dict:
        return {"sink": self.sink, "entrypoint": self.entrypoint.to_dict(),
                "frames": [f.to_dict() for f in self.frames]}

    @property
    def kinds(self) -> set[str]:
        return {f.edge for f in self.frames}


@dataclass
class Verdict:
    bucket: str
    reason: str
    paths: list[Path] = field(default_factory=list)
    evidence: str = ""
    sink_nodes: list[str] = field(default_factory=list)


class Traversal:
    """BFS from a set of entry points, keeping one shortest path to every node it reaches."""

    def __init__(self, graph: CallGraph, entries: list[EntryPoint], kinds: tuple[str, ...]) -> None:
        self.graph = graph
        self.kinds = kinds
        self.parent: dict[str, tuple[str, str]] = {}   # node -> (parent, edge kind)
        self.root: dict[str, EntryPoint] = {}
        self.line: dict[str, int] = {}
        self._run(entries)

    def _run(self, entries: list[EntryPoint]) -> None:
        queue: deque[str] = deque()
        for entry in entries:
            for seed in (entry.node, f"{entry.node.split(':', 1)[0]}:<module>"):
                if seed not in self.root:
                    self.root[seed] = entry
                    self.parent[seed] = ("", "entry")
                    queue.append(seed)
        while queue:
            node = queue.popleft()
            entry = self.root[node]
            for edge in self.graph.edges.get(node, ()):
                if edge.kind not in self.kinds or edge.dst in self.parent:
                    continue
                self.parent[edge.dst] = (node, edge.kind)
                self.line[edge.dst] = edge.line
                self.root[edge.dst] = entry
                queue.append(edge.dst)

    def __contains__(self, node: str) -> bool:
        return node in self.parent

    @property
    def nodes(self) -> set[str]:
        return set(self.parent)

    def path_to(self, node: str) -> Path | None:
        if node not in self.parent:
            return None
        chain: list[tuple[str, str]] = []
        cur = node
        guard = 0
        while cur and guard < 400:
            parent, kind = self.parent[cur]
            chain.append((cur, kind))
            cur = parent
            guard += 1
        chain.reverse()
        frames = []
        for name, kind in chain:
            file, line = self.graph.node_location(name)
            frames.append(Frame(name, file, self.line.get(name, line), "entry" if kind == "entry" else kind))
        return Path(sink=node, entrypoint=self.root[node], frames=frames)


def resolve_sink(index: Index, graph: CallGraph, sink: str) -> list[str]:
    """Turn `pkg.module.Class.method` into node ids that exist in the index."""
    hit = index.longest_module_prefix(sink)
    if hit is None:
        return []
    module_name, rest = hit
    module = index.modules[module_name]
    if not rest:
        return [f"{module_name}:{qual}" for qual in module.scopes]
    if rest in module.scopes:
        return [f"{module_name}:{rest}"]
    if rest in module.classes:
        info = module.classes[rest]
        nodes = [f"{module_name}:{qual}" for qual in info.methods.values()]
        return nodes or [f"{module_name}:{rest}"]
    resolved = graph.resolve_in_module(rest, module, None)
    if resolved and resolved[0] == "func":
        return [resolved[1]]
    if resolved and resolved[0] == "class":
        class_module, qual = resolved[1].split(":", 1)
        info = index.modules[class_module].classes.get(qual)
        if info:
            return [f"{class_module}:{q}" for q in info.methods.values()]
    tail = rest.split(".")[-1]
    matches = [f"{module_name}:{qual}" for qual in module.scopes
               if qual.split(".")[-1] == tail]
    return matches


class Analyzer:
    def __init__(self, index: Index, graph: CallGraph, entries: list[EntryPoint],
                 test_entries: list[EntryPoint] | None = None, closure_rounds: int = 3) -> None:
        self.index = index
        self.graph = graph
        self.entries = entries
        self.high = Traversal(graph, entries, HIGH_CONFIDENCE)
        self.medium = Traversal(graph, entries, ALL_EDGES)
        self.with_tests = (Traversal(graph, entries + test_entries, HIGH_CONFIDENCE)
                           if test_entries else None)
        self.imported_modules = {n.split(":", 1)[0] for n in self.high.nodes if n.endswith(":<module>")}
        self._dynamic_sites = self._collect_dynamic_sites()
        self._unresolved_by_attr = self._collect_unresolved()
        self._app_strings = self._collect_strings()
        self.closure_parent: dict[str, tuple[str, str]] = {}
        self.closure_line: dict[str, int] = {}
        self.dynamic_seeds = self._dynamic_import_seeds()
        self.dynamic, self.dynamic_evidence = self._dynamic_closure(closure_rounds)

    def _collect_dynamic_sites(self) -> dict[str, list]:
        out: dict[str, list] = {}
        for node in self.high.nodes:
            markers = [m for m in self.graph.markers.get(node, ()) if m.kind in DYNAMIC_KINDS]
            if markers:
                out[node] = markers
        return out

    def _collect_unresolved(self) -> dict[str, list[tuple[str, str, int]]]:
        out: dict[str, list[tuple[str, str, int]]] = {}
        for node in self.high.nodes:
            for attr, line in self.graph.unresolved.get(node, ()):
                out.setdefault(attr, []).append((node, self.graph.node_location(node)[0], line))
        return out

    def _collect_strings(self) -> set[str]:
        out: set[str] = set()
        for module in self.index.modules.values():
            if module.is_app:
                out |= module.strings
        return out

    def _dynamic_import_seeds(self) -> dict[str, str]:
        """Modules named by a string literal in application code that also runs `importlib`.

        A plugin loader leaves no call edge behind. It leaves the module name in a string, and that
        string is the only evidence a static tool gets.
        """
        importers = sorted(
            (node for node, markers in self._dynamic_sites.items()
             if any(m.kind in IMPORT_KINDS for m in markers)),
            key=lambda n: not self.index.modules[n.split(":", 1)[0]].is_app)
        if not importers:
            return {}
        seeds: dict[str, str] = {}
        for literal in self._app_strings:
            module = self.index.modules.get(literal)
            if module is not None and f"{literal}:<module>" not in self.high:
                seeds[f"{literal}:<module>"] = (
                    f"'{literal}' is imported by name at {importers[0]}")
        # A computed module name or a generated source string tells us nothing about which module
        # is loaded. The application's own modules are the bounded set it could be, so all of them
        # become undetermined rather than one of them being wrongly cleared.
        opaque = [node for node, markers in self._dynamic_sites.items()
                  if any(m.kind == "opaque" for m in markers)]
        if opaque:
            for module in self.index.modules.values():
                node = f"{module.name}:<module>"
                if module.is_app and not module.is_native and node not in self.high:
                    seeds.setdefault(node, f"module name is computed at {opaque[0]}")
        return seeds

    def _dynamic_closure(self, rounds: int) -> tuple[set[str], dict[str, str]]:
        """Over-approximate reachability.

        Every unresolved call site is allowed to dispatch to any function with a matching name, as
        long as that function's module is already imported on some path. A sink outside this set is
        not reachable even when static analysis is given the benefit of every doubt, and that is the
        claim the `unreachable` bucket makes. Parents are kept so an undetermined finding can show
        the same kind of stack a reachable one does, with the guessed hop marked.
        """
        seen = set(self.medium.nodes)
        imported = set(self.imported_modules)
        evidence: dict[str, str] = {}
        pending: deque[str] = deque()

        def push(node: str, parent: str, kind: str, why: str) -> None:
            seen.add(node)
            self.closure_parent[node] = (parent, kind)
            evidence[node] = why
            pending.append(node)

        def drain() -> set[str]:
            reached: set[str] = set()
            while pending:
                node = pending.popleft()
                reached.add(node)
                for edge in self.graph.edges.get(node, ()):
                    if edge.dst in seen:
                        continue
                    seen.add(edge.dst)
                    self.closure_parent[edge.dst] = (node, edge.kind)
                    self.closure_line[edge.dst] = edge.line
                    evidence[edge.dst] = evidence.get(node, "")
                    pending.append(edge.dst)
            return reached

        for node, why in self.dynamic_seeds.items():
            if node not in seen:
                push(node, "", "dynamic_import", why)
        drain()
        frontier = set(seen)
        imported |= {n.split(":", 1)[0] for n in seen if n.endswith(":<module>")}

        for _ in range(rounds):
            names: dict[str, list[tuple[str, int]]] = {}
            explicit: dict[str, list[tuple[str, int]]] = {}
            properties: dict[str, list[tuple[str, int]]] = {}
            for node in frontier:
                for attr, line in self.graph.unresolved.get(node, ()):
                    if attr in BUILTIN_ATTRS or attr.startswith("native:"):
                        continue
                    names.setdefault(attr, []).append((node, line))
                for marker in self.graph.markers.get(node, ()):
                    if marker.kind == "getattr" and marker.detail and "." not in marker.detail:
                        explicit.setdefault(marker.detail, []).append((node, marker.line))
                scope = self._scope_of(node)
                if scope is not None:
                    for attr in scope.attr_loads:
                        properties.setdefault(attr, []).append((node, scope.line))
            for candidate, site, line, why in self._getattr_any_candidates(frontier):
                if candidate in seen or candidate.split(":", 1)[0] not in imported:
                    continue
                push(candidate, site, "dynamic", why)
                self.closure_line[candidate] = line
            for name, sites in sorted(explicit.items()):
                for candidate in self.graph.nodes_by_name.get(name, ()):
                    if candidate in seen or candidate.split(":", 1)[0] not in imported:
                        continue
                    site, line = self._best_site(candidate, sites)
                    push(candidate, site, "dynamic",
                         f'getattr(..., "{name}") at {self.graph.node_location(site)[0]}:{line}')
                    self.closure_line[candidate] = line
            for name, sites in sorted(properties.items()):
                for candidate in self.graph.properties_by_name.get(name, ()):
                    if candidate in seen or candidate.split(":", 1)[0] not in imported:
                        continue
                    site, line = self._best_site(candidate, sites)
                    push(candidate, site, "property",
                         f"property .{name} read at {self.graph.node_location(site)[0]}:{line}")
                    self.closure_line[candidate] = line
            for name, sites in sorted(names.items()):
                for candidate in self.graph.nodes_by_name.get(name, ()):
                    if candidate in seen or candidate.split(":", 1)[0] not in imported:
                        continue
                    site, line = self._best_site(candidate, sites)
                    file = self.graph.node_location(site)[0]
                    caller = site.split(":", 1)[0].split(".")[0]
                    unrelated = (caller != candidate.split(":", 1)[0].split(".")[0]
                                 and not self.index.modules[site.split(":", 1)[0]].is_app)
                    prefix = "name match only, " if unrelated else ""
                    push(candidate, site, "dynamic",
                         f"{prefix}unresolved call .{name}() at {file}:{line}")
                    self.closure_line[candidate] = line
            if not pending:
                break
            frontier = drain()
            imported |= {n.split(":", 1)[0] for n in frontier if n.endswith(":<module>")}
        return seen, evidence

    def _getattr_any_candidates(self, frontier: set[str]):
        """`getattr(mod, name)` with a computed name can reach anything in `mod`."""
        for node in frontier:
            module_name = node.split(":", 1)[0]
            module = self.index.modules.get(module_name)
            if module is None:
                continue
            scope = self._scope_of(node)
            for marker in self.graph.markers.get(node, ()):
                if marker.kind != "getattr_any" or not marker.detail:
                    continue
                resolved = self.graph.resolve_in_module(marker.detail, module, scope)
                if resolved is None:
                    continue
                file = self.graph.node_location(node)[0]
                why = f"getattr({marker.detail}, <computed>) at {file}:{marker.line}"
                if resolved[0] == "module":
                    target = self.index.modules[resolved[1]]
                    for qual in target.scopes:
                        if qual != "<module>":
                            yield f"{resolved[1]}:{qual}", node, marker.line, why
                elif resolved[0] == "class":
                    class_module, qual = resolved[1].split(":", 1)
                    info = self.index.modules[class_module].classes.get(qual)
                    for method in (info.methods.values() if info else ()):
                        yield f"{class_module}:{method}", node, marker.line, why

    def _scope_of(self, node: str):
        module_name, qualname = node.split(":", 1)
        module = self.index.modules.get(module_name)
        return module.scopes.get(qualname) if module else None

    def _best_site(self, candidate: str, sites: list[tuple[str, int]]) -> tuple[str, int]:
        """Attribute the guess to the most plausible caller, not to whichever came first."""
        top = candidate.split(":", 1)[0].split(".")[0]

        def score(site: tuple[str, int]) -> tuple[int, str]:
            module_name = site[0].split(":", 1)[0]
            module = self.index.modules.get(module_name)
            if module_name.split(".")[0] == top:
                return (0, site[0])
            if module is not None and module.is_app:
                return (1, site[0])
            return (2, site[0])

        return min(sites, key=score)

    def closure_path(self, node: str) -> Path | None:
        """Walk back through the closure, then through the medium traversal, to an entry point."""
        chain: list[tuple[str, str]] = []
        cur = node
        guard = 0
        entry = None
        while cur and guard < 400:
            guard += 1
            if cur in self.closure_parent:
                parent, kind = self.closure_parent[cur]
            elif cur in self.medium.parent:
                parent, kind = self.medium.parent[cur]
                entry = entry or self.medium.root.get(cur)
            else:
                break
            chain.append((cur, kind))
            cur = parent
        chain.reverse()
        if not chain:
            return None
        frames = []
        for name, kind in chain:
            file, line = self.graph.node_location(name)
            frames.append(Frame(name, file, self.closure_line.get(name, self.medium.line.get(name, line)),
                                "entry" if kind == "entry" else kind))
        root = entry or EntryPoint("dynamic", frames[0].node, "loaded at runtime",
                                   frames[0].file, frames[0].line)
        return Path(sink=node, entrypoint=root, frames=frames)

    # ---- classification ------------------------------------------------------------------

    def classify(self, sinks: list[str], sink_status: str, package: str) -> Verdict:
        if sink_status != "verified" or not sinks:
            return Verdict(UNDETERMINED, "no_verified_sink",
                           evidence="no function-level sink survived patch verification")
        nodes: list[str] = []
        for sink in sinks:
            nodes.extend(resolve_sink(self.index, self.graph, sink))
        nodes = list(dict.fromkeys(nodes))
        if not nodes:
            return Verdict(UNDETERMINED, "no_verified_sink", sink_nodes=[],
                           evidence=f"sink {sinks[0]} not found in the analysed source tree")

        hits = [n for n in nodes if n in self.high]
        if hits:
            paths = [p for p in (self.high.path_to(n) for n in hits[:3]) if p]
            return Verdict(REACHABLE, "call_path", paths=paths, sink_nodes=nodes)

        medium_hits = [n for n in nodes if n in self.medium]
        if medium_hits:
            paths = [p for p in (self.medium.path_to(n) for n in medium_hits[:2]) if p]
            kinds = set().union(*[p.kinds for p in paths]) if paths else set()
            reason = "virtual_dispatch" if "virtual" in kinds else "callback_reference"
            return Verdict(UNDETERMINED, reason, paths=paths, sink_nodes=nodes,
                           evidence="path exists only through a medium confidence edge")

        sink_modules = {n.split(":", 1)[0] for n in nodes}
        for module_name in sink_modules:
            module = self.index.modules.get(module_name)
            if module is not None and module.is_native:
                return Verdict(UNDETERMINED, "native_boundary", sink_nodes=nodes,
                               evidence=f"{module_name} is a compiled extension")

        reachable_modules = self.imported_modules | {
            n.split(":", 1)[0] for n in self.dynamic if n.endswith(":<module>")}
        imported = sink_modules & reachable_modules
        names = {n.split(":", 1)[1].split(".")[-1] for n in nodes}
        closure_hits = [n for n in nodes if n in self.dynamic]
        if closure_hits:
            why = self.dynamic_evidence.get(closure_hits[0], "reached only in the over-approximation")
            paths = [p for p in (self.closure_path(n) for n in closure_hits[:1]) if p]
            return Verdict(UNDETERMINED, "dynamic_dispatch", sink_nodes=nodes, evidence=why, paths=paths)

        if self.with_tests and any(n in self.with_tests for n in nodes):
            return Verdict(UNREACHABLE, "dev_or_test_only", sink_nodes=nodes,
                           evidence="only reachable from test entry points")
        if imported:
            return Verdict(UNREACHABLE, "no_call_path", sink_nodes=nodes,
                           evidence=f"{sorted(imported)[0]} is imported, "
                                    f"{sorted(names)[0]} is never called on any path")
        return Verdict(UNREACHABLE, "module_never_imported", sink_nodes=nodes,
                       evidence=f"{sorted(sink_modules)[0]} is not imported on any path "
                                f"from an entry point")

    def _imports_any(self, module_name: str, targets: set[str]) -> bool:
        module = self.index.modules.get(module_name)
        if module is None:
            return False
        return any(imp in targets for imp in module.imports)

    def summary(self) -> dict:
        return {
            "entry_points": len(self.entries),
            "reachable_nodes": len(self.high.nodes),
            "reachable_nodes_medium": len(self.medium.nodes),
            "imported_modules": len(self.imported_modules),
            "dynamic_sites_in_reachable_code": len(self._dynamic_sites),
            "dynamic_closure_nodes": len(self.dynamic),
            "dynamic_import_seeds": len(self.dynamic_seeds),
        }
