"""Call graph construction.

Resolution is flow-insensitive and intra-procedural. It resolves import aliases, re-exports through
`__init__.py`, class hierarchies, parameter annotations, constructor bindings, and `self` attribute
types. Everything else is recorded as an unresolved call site with the attribute name kept, because
those sites are what the undetermined bucket is built from.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .index import Index, Marker, ModuleInfo, Scope, is_dev_module

HIGH_CONFIDENCE = ("call", "ctor", "import")
MEDIUM_CONFIDENCE = ("ref", "virtual")

_BUILTINS = {
    "len", "print", "range", "isinstance", "issubclass", "str", "int", "float", "bool", "list",
    "dict", "set", "tuple", "type", "super", "open", "sorted", "enumerate", "zip", "map", "filter",
    "min", "max", "sum", "abs", "round", "repr", "hash", "id", "iter", "next", "any", "all",
    "bytes", "bytearray", "frozenset", "format", "hasattr", "callable", "reversed", "slice",
    "property", "staticmethod", "classmethod", "object", "Exception", "ValueError", "TypeError",
    "KeyError", "IndexError", "RuntimeError", "AttributeError", "NotImplementedError", "OSError",
    "StopIteration", "ImportError", "self", "cls",
}


@dataclass(slots=True)
class Edge:
    dst: str
    kind: str
    line: int


class CallGraph:
    def __init__(self, index: Index, virtual_limit: int = 64) -> None:
        self.index = index
        self.virtual_limit = virtual_limit
        self.edges: dict[str, list[Edge]] = defaultdict(list)
        self.reverse: dict[str, set[str]] = defaultdict(set)
        self.unresolved: dict[str, list[tuple[str, int]]] = defaultdict(list)
        self.markers: dict[str, list[Marker]] = {}
        self.subclasses: dict[str, set[str]] = defaultdict(set)
        self.methods_by_name: dict[str, set[str]] = defaultdict(set)
        self.nodes_by_name: dict[str, set[str]] = defaultdict(set)
        self.properties_by_name: dict[str, set[str]] = defaultdict(set)
        self.stats = {"call": 0, "ctor": 0, "import": 0, "ref": 0, "virtual": 0,
                      "unresolved": 0, "external": 0, "native": 0}
        # Why resolution failed, counted. The ranking of these is the only honest description of
        # what a Python call graph actually cannot see.
        self.failures: Counter[str] = Counter()
        self.failure_examples: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
        self.call_sites = 0
        self._cache: dict[str, tuple | None] = {}
        self._class_cache: dict[str, list] = {}

    # ---- global resolution ---------------------------------------------------------------

    def resolve_global(self, path: str, depth: int = 0) -> tuple | None:
        """Resolve a dotted path that is already absolute (no local names left)."""
        if depth == 0 and path in self._cache:
            return self._cache[path]
        result = self._resolve_global(path, depth)
        if depth == 0:
            self._cache[path] = result
        return result

    def _resolve_global(self, path: str, depth: int) -> tuple | None:
        if depth > 8:
            return None
        hit = self.index.longest_module_prefix(path)
        if hit is None:
            return ("external", path.split(".")[0])
        module_name, rest = hit
        module = self.index.modules[module_name]
        if module.is_native:
            return ("native", module_name)
        if not rest:
            return ("module", module_name)
        return self._resolve_member(module, rest, depth)

    def _resolve_member(self, module: ModuleInfo, rest: str, depth: int) -> tuple | None:
        if rest in module.scopes:
            return ("func", f"{module.name}:{rest}")
        if rest in module.classes:
            return ("class", f"{module.name}:{rest}")
        parts = rest.split(".")
        first = parts[0]
        if first in module.classes:
            if len(parts) == 1:
                return ("class", f"{module.name}:{first}")
            found = self.find_in_mro(module.name, first, parts[1], depth)
            if found is not None and len(parts) == 2:
                return found
            if found is not None:
                return ("unresolved", parts[-1])
            attr_type = self._class_attr(module.name, first, parts[1], depth)
            if attr_type is not None and len(parts) > 2:
                kind, value = attr_type
                if kind == "class":
                    mod, qual = value.split(":", 1)
                    found = self.find_in_mro(mod, qual, parts[2], depth + 1)
                    if found is not None and len(parts) == 3:
                        return found
            return ("unresolved", parts[-1])
        if first in module.scopes:
            if len(parts) == 1:
                return ("func", f"{module.name}:{first}")
            chained = self._attr_on_func(f"{module.name}:{first}", parts[1], depth)
            return chained if chained is not None and len(parts) == 2 else ("unresolved", parts[-1])
        if first in module.aliases:
            target = module.aliases[first]
            if target != f"{module.name}.{first}":
                tail = "." + ".".join(parts[1:]) if len(parts) > 1 else ""
                return self.resolve_global(target + tail, depth + 1)
        top = module.scopes.get("<module>")
        if top is not None and depth < 6:
            # `decode = _jwt_global_obj.decode` at module level: a bound method exported as a name.
            alias = top.bindings.get(f"={first}") or top.bindings.get(first)
            if alias and alias != first:
                tail = "." + ".".join(parts[1:]) if len(parts) > 1 else ""
                found = self.resolve_in_module(alias + tail, module, top, depth + 1)
                if found is not None and found[0] in ("func", "class"):
                    return found
        for star in module.star_imports:
            found = self.resolve_global(f"{star}.{rest}", depth + 1)
            if found is not None and found[0] in ("func", "class"):
                return found
        if "__getattr__" in module.scopes and len(parts) == 1:
            return ("func", f"{module.name}:__getattr__")
        return ("unresolved", parts[-1])

    def _attr_on_func(self, func_node: str, attr: str, depth: int) -> tuple | None:
        """`build_parser().parse()` resolves when `build_parser` declares its return type."""
        if depth > 6:
            return None
        module_name, qualname = func_node.split(":", 1)
        module = self.index.modules.get(module_name)
        scope = module.scopes.get(qualname) if module else None
        if scope is None or not scope.returns:
            return None
        target = self.resolve_in_module(scope.returns, module, None, depth + 1)
        if target is None or target[0] != "class":
            return None
        class_module, class_qual = target[1].split(":", 1)
        return self.find_in_mro(class_module, class_qual, attr, depth + 1)

    # ---- class hierarchy -----------------------------------------------------------------

    def mro(self, module_name: str, qualname: str, depth: int = 0) -> list:
        key = f"{module_name}:{qualname}"
        if key in self._class_cache:
            return self._class_cache[key]
        self._class_cache[key] = []           # cycle guard
        module = self.index.modules.get(module_name)
        if module is None or qualname not in module.classes:
            return []
        info = module.classes[qualname]
        chain = [info]
        for base in info.bases:
            resolved = self.resolve_in_module(base, module, None, depth + 1)
            if resolved and resolved[0] == "class" and depth < 8:
                base_mod, base_qual = resolved[1].split(":", 1)
                for parent in self.mro(base_mod, base_qual, depth + 1):
                    if parent not in chain:
                        chain.append(parent)
        self._class_cache[key] = chain
        return chain

    def find_in_mro(self, module_name: str, qualname: str, attr: str, depth: int = 0) -> tuple | None:
        for info in self.mro(module_name, qualname, depth):
            if attr in info.methods:
                return ("func", f"{info.module}:{info.methods[attr]}")
        return None

    def _class_attr(self, module_name: str, qualname: str, attr: str, depth: int) -> tuple | None:
        for info in self.mro(module_name, qualname, depth):
            if attr in info.attrs:
                module = self.index.modules[info.module]
                return self.resolve_in_module(info.attrs[attr], module, None, depth + 1)
        return None

    # ---- local resolution ----------------------------------------------------------------

    def resolve_in_module(self, path: str, module: ModuleInfo, scope: Scope | None,
                          depth: int = 0) -> tuple | None:
        if depth > 8 or not path:
            return None
        parts = path.split(".")
        head, rest = parts[0], parts[1:]

        if scope is not None:
            found = self._resolve_local(head, rest, module, scope, depth)
            if found is not None:
                return found

        if head in module.classes:
            if not rest:
                return ("class", f"{module.name}:{head}")
            found = self.find_in_mro(module.name, head, rest[0], depth)
            if found is not None and len(rest) == 1:
                return found
            return ("unresolved", parts[-1])
        if head in module.scopes:
            if not rest:
                return ("func", f"{module.name}:{head}")
            chained = self._attr_on_func(f"{module.name}:{head}", rest[0], depth)
            return chained if chained is not None and len(rest) == 1 else ("unresolved", parts[-1])
        if head in module.aliases:
            target = module.aliases[head]
            tail = "." + ".".join(rest) if rest else ""
            return self.resolve_global(target + tail, depth + 1)
        if head in _BUILTINS:
            return None
        return self.resolve_global(path, depth + 1)

    def _resolve_local(self, head: str, rest: list[str], module: ModuleInfo, scope: Scope,
                       depth: int) -> tuple | None:
        if head == "super" and scope.class_qual and rest:
            # `super().__init__()` was rewritten to `super.__init__` by the constructor chain rule.
            # It resolves against the enclosing class's MRO with the class itself skipped.
            chain = self.mro(module.name, scope.class_qual, depth)[1:]
            for info in chain:
                if rest[0] in info.methods:
                    return ("func", f"{info.module}:{info.methods[rest[0]]}")
            return ("unresolved", rest[-1])
        if head in ("self", "cls") and scope.class_qual:
            if not rest:
                return None
            found = self.find_in_mro(module.name, scope.class_qual, rest[0], depth)
            if found is not None and len(rest) == 1:
                return found
            if found is not None and len(rest) == 2:
                chained = self._attr_on_func(found[1], rest[1], depth)
                if chained is not None:
                    return chained
            attr_type = self._class_attr(module.name, scope.class_qual, rest[0], depth)
            if attr_type is not None and attr_type[0] == "class" and len(rest) == 2:
                mod, qual = attr_type[1].split(":", 1)
                found = self.find_in_mro(mod, qual, rest[1], depth + 1)
                if found is not None:
                    return found
            return ("unresolved", rest[-1])

        for holder in self._scope_chain(module, scope):
            if head in holder.params and not holder.params[head]:
                # An unannotated parameter. The receiver is a local value, not a module, so the
                # call is unresolved rather than external, and it belongs in the undetermined maths.
                return ("unresolved", rest[-1]) if rest else None
            alias = holder.bindings.get(f"={head}")
            if alias is not None:
                tail = "." + ".".join(rest) if rest else ""
                return self.resolve_in_module(alias + tail, module, None, depth + 1)
            bound = holder.bindings.get(head)
            annotation = holder.params.get(head)
            hint = bound or annotation
            if hint:
                target = self.resolve_in_module(hint, module, None, depth + 1)
                if target is None or target[0] != "class":
                    return None if not rest else ("unresolved", rest[-1])
                if not rest:
                    return None      # calling an instance, not a class
                mod, qual = target[1].split(":", 1)
                found = self.find_in_mro(mod, qual, rest[0], depth + 1)
                if found is not None and len(rest) == 1:
                    return found
                return ("unresolved", rest[-1])
        return None

    def _scope_chain(self, module: ModuleInfo, scope: Scope):
        """A closure sees its enclosing function's locals, and everything sees module globals."""
        yield scope
        qual = scope.qualname
        while ".<locals>." in qual:
            qual = qual.rsplit(".<locals>.", 1)[0]
            parent = module.scopes.get(qual)
            if parent is None:
                break
            yield parent
        if scope.qualname != "<module>":
            top = module.scopes.get("<module>")
            if top is not None:
                yield top

    # ---- construction --------------------------------------------------------------------

    def _add(self, src: str, dst: str, kind: str, line: int) -> None:
        self.edges[src].append(Edge(dst, kind, line))
        self.reverse[dst].add(src)
        self.stats[kind] += 1

    def build(self) -> None:
        for module in self.index.modules.values():
            for qual, info in module.classes.items():
                self.methods_by_name  # touched below
                for name, method_qual in info.methods.items():
                    self.methods_by_name[name].add(f"{module.name}:{method_qual}")
            for qual, scope in module.scopes.items():
                if qual != "<module>":
                    name = qual.split(".")[-1]
                    self.nodes_by_name[name].add(scope.node_id)
                    if scope.is_property:
                        self.properties_by_name[name].add(scope.node_id)
                self._build_scope(module, scope)
        self._build_subclasses()
        self._add_descriptor_edges()
        self._add_subclass_hooks()
        self._add_virtual_edges()

    def _build_scope(self, module: ModuleInfo, scope: Scope) -> None:
        if scope.markers:
            self.markers[scope.node_id] = scope.markers
        for target, local in scope.imports:
            self._import_edges(scope, target, local)
        for call in scope.calls:
            self.call_sites += 1
            if call.target is None:
                kind = ("indirect_call_subscript" if call.attr else "indirect_call_expression")
                self._note_failure(kind, scope, call.attr or "<expr>", call.line)
                if call.attr:
                    self.unresolved[scope.node_id].append((call.attr, call.line))
                    self.stats["unresolved"] += 1
                continue
            if call.target in _BUILTINS:
                self.failures["builtin"] += 1
                continue
            if call.target.startswith("super."):
                resolved = self.resolve_in_module(call.target, module, scope)
                if resolved is None or resolved[0] == "unresolved":
                    self._note_failure("super_call_unresolved", scope, call.target, call.line)
                self._emit(scope, resolved, call.attr, call.line, is_call=True)
                continue
            resolved = self.resolve_in_module(call.target, module, scope)
            if resolved is None:
                self._note_failure("builtin_or_unbound_name", scope, call.target, call.line)
            elif resolved[0] == "unresolved":
                self._note_failure(self._failure_kind(call.target, module, scope), scope,
                                   call.target, call.line)
            elif resolved[0] == "external":
                self._note_failure("outside_analysed_tree", scope, call.target, call.line)
            elif resolved[0] == "native":
                self._note_failure("compiled_extension", scope, call.target, call.line)
            self._emit(scope, resolved, call.attr, call.line, is_call=True)
        for ref in set(scope.refs):
            head = ref.split(".")[0]
            if head in _BUILTINS:
                continue
            resolved = self.resolve_in_module(ref, module, scope)
            if resolved is None:
                continue
            if resolved[0] == "func":
                self._add(scope.node_id, resolved[1], "ref", scope.line)
            elif resolved[0] == "class":
                init = self._init_of(resolved[1])
                if init:
                    self._add(scope.node_id, init, "ref", scope.line)

    def _note_failure(self, kind: str, scope: Scope, target: str, line: int) -> None:
        self.failures[kind] += 1
        examples = self.failure_examples[kind]
        shipped = not is_dev_module(scope.module)
        if len(examples) < 8 or (shipped and not any(
                not is_dev_module(e[0].split(":", 1)[0]) for e in examples)):
            examples.append((scope.node_id, target, line))
            del examples[16:]

    def _failure_kind(self, target: str, module: ModuleInfo, scope: Scope) -> str:
        """Name the resolution rule that ran out of road, so the count means something."""
        head = target.split(".")[0]
        if head in ("self", "cls"):
            return "attribute_on_self_not_a_method"
        for holder in self._scope_chain(module, scope):
            if head in holder.params:
                return ("parameter_without_annotation" if not holder.params[head]
                        else "parameter_annotation_unresolved")
            if head in holder.bindings or f"={head}" in holder.bindings:
                return "local_bound_to_unknown_return"
        if head in module.aliases:
            return "attribute_on_imported_object"
        if head in module.classes or head in module.scopes:
            return "attribute_on_local_definition"
        return "unknown_receiver"

    def _emit(self, scope: Scope, resolved: tuple | None, attr: str | None, line: int,
              is_call: bool) -> None:
        if resolved is None:
            return
        kind, value = resolved
        if kind == "func":
            self._add(scope.node_id, value, "call", line)
        elif kind == "class":
            init = self._init_of(value)
            if init:
                self._add(scope.node_id, init, "ctor", line)
            call_method = self.find_in_mro(*value.split(":", 1), "__call__")
            if call_method:
                # `Email()` builds a callable, it does not call it. Whoever holds the instance may
                # call it later, which is a callback, not a call site.
                self._add(scope.node_id, call_method[1], "ref", line)
            meta = self._metaclass_call(value)
            if meta:
                self._add(scope.node_id, meta, "call", line)
        elif kind == "native":
            self.stats["native"] += 1
            self.unresolved[scope.node_id].append((f"native:{value}", line))
        elif kind == "external":
            self.stats["external"] += 1
        elif kind == "unresolved" and attr:
            self.unresolved[scope.node_id].append((attr, line))
            self.stats["unresolved"] += 1

    def _metaclass_call(self, class_node: str) -> str | None:
        """`Service()` runs `type(Service).__call__` first, and that hook can run anything."""
        module_name, qualname = class_node.split(":", 1)
        for info in self.mro(module_name, qualname):
            if not info.metaclass:
                continue
            module = self.index.modules.get(info.module)
            if module is None:
                continue
            resolved = self.resolve_in_module(info.metaclass, module, None)
            if resolved and resolved[0] == "class":
                found = self.find_in_mro(*resolved[1].split(":", 1), "__call__")
                if found:
                    return found[1]
        return None

    def _init_of(self, class_node: str) -> str | None:
        module_name, qualname = class_node.split(":", 1)
        found = self.find_in_mro(module_name, qualname, "__init__")
        return found[1] if found else None

    def _import_edges(self, scope: Scope, target: str, local: str) -> None:
        parts = target.split(".")
        for cut in range(1, len(parts) + 1):
            name = ".".join(parts[:cut])
            if name in self.index.modules:
                self._add(scope.node_id, f"{name}:<module>", "import", scope.line)
        if local != "*":
            submodule = f"{target}.{local}" if target else local
            if submodule in self.index.modules:
                self._add(scope.node_id, f"{submodule}:<module>", "import", scope.line)

    def _build_subclasses(self) -> None:
        for module in self.index.modules.values():
            for qual, info in module.classes.items():
                for base in info.bases:
                    resolved = self.resolve_in_module(base, module, None)
                    if resolved and resolved[0] == "class":
                        self.subclasses[resolved[1]].add(f"{module.name}:{qual}")

    DESCRIPTOR_HOOKS = ("__get__", "__set__", "__set_name__")

    def _add_descriptor_edges(self) -> None:
        """A descriptor stored on a class runs on plain attribute access, with no call syntax."""
        for module in self.index.modules.values():
            for qualname, info in module.classes.items():
                for attr_type in set(info.attrs.values()):
                    resolved = self.resolve_in_module(attr_type, module, None)
                    if not resolved or resolved[0] != "class":
                        continue
                    for hook in self.DESCRIPTOR_HOOKS:
                        found = self.find_in_mro(*resolved[1].split(":", 1), hook)
                        if found:
                            self._add(f"{module.name}:<module>", found[1], "ref", info.line)

    def _add_subclass_hooks(self) -> None:
        """Defining `class Child(Base)` calls `Base.__init_subclass__` with no call site in sight."""
        for module in self.index.modules.values():
            for qualname, info in module.classes.items():
                for base in info.bases:
                    resolved = self.resolve_in_module(base, module, None)
                    if not resolved or resolved[0] != "class":
                        continue
                    hook = self.find_in_mro(*resolved[1].split(":", 1), "__init_subclass__")
                    if hook:
                        self._add(f"{module.name}:<module>", hook[1], "call", info.line)

    def _add_virtual_edges(self) -> None:
        """Class hierarchy analysis: a call to a base method may land on any override."""
        targets = {edge.dst for edges in self.edges.values() for edge in edges if edge.kind == "call"}
        for node in targets:
            module_name, qualname = node.split(":", 1)
            if "." not in qualname or qualname.endswith("<module>"):
                continue
            class_qual, method = qualname.rsplit(".", 1)
            base = f"{module_name}:{class_qual}"
            children = self._descendants(base)
            if not children or len(children) > self.virtual_limit:
                continue
            for child in children:
                child_module, child_qual = child.split(":", 1)
                info = self.index.modules[child_module].classes.get(child_qual)
                if info and method in info.methods:
                    override = f"{child_module}:{info.methods[method]}"
                    for caller in list(self.reverse.get(node, ())):
                        self._add(caller, override, "virtual", 0)

    def _descendants(self, class_node: str, seen: set[str] | None = None) -> set[str]:
        seen = seen if seen is not None else set()
        for child in self.subclasses.get(class_node, ()):
            if child in seen:
                continue
            seen.add(child)
            self._descendants(child, seen)
        return seen

    # ---- queries -------------------------------------------------------------------------

    def out_edges(self, node: str, kinds: tuple[str, ...] = HIGH_CONFIDENCE) -> list[Edge]:
        return [e for e in self.edges.get(node, ()) if e.kind in kinds]

    def node_location(self, node: str) -> tuple[str, int]:
        module_name, qualname = node.split(":", 1)
        module = self.index.modules.get(module_name)
        if module is None:
            return "<unknown>", 0
        scope = module.scopes.get(qualname)
        if scope is not None:
            return scope.file, scope.line
        info = module.classes.get(qualname)
        if info is not None:
            return info.file, info.line
        return module.file, 0
