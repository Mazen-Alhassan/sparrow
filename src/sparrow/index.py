"""AST index: files to modules, modules to definitions, imports, and dynamic markers.

This module does not resolve calls. It records what each scope literally contains, including the
things it cannot make sense of, and hands that to the call graph builder. Every construct that
defeats the resolver is recorded here as a marker rather than dropped, because the count of those
markers is the tool's honesty budget.
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

# Calls that mean "the target is decided at runtime". Presence of any of these in a reachable
# function is what moves a finding from unreachable to undetermined.
DYNAMIC_CALLS = {
    "getattr": "getattr",
    "setattr": "setattr",
    "eval": "eval",
    "exec": "exec",
    "compile": "compile",
    "__import__": "import",
    "importlib.import_module": "import",
    "import_module": "import",
    "importlib.__import__": "import",
    "pkgutil.iter_modules": "plugin_scan",
    "pkgutil.walk_packages": "plugin_scan",
    "pkg_resources.iter_entry_points": "entry_points",
    "pkg_resources.load_entry_point": "entry_points",
    "importlib.metadata.entry_points": "entry_points",
    "entry_points": "entry_points",
    "globals": "namespace",
    "locals": "namespace",
    "vars": "namespace",
    "operator.attrgetter": "getattr",
    "attrgetter": "getattr",
    "methodcaller": "getattr",
}

_NATIVE_SUFFIX = re.compile(r"\.(cpython-[^.]+|abi3|pypy[^.]*)?\.?(so|pyd|dylib)$")


# Calls that register a callable with a framework. The keyword arguments of these are kept so a
# route registered by `app.add_url_rule("/x", view_func=handler)` is found as an entry point.
REGISTRARS = {"add_url_rule", "add_route", "add_api_route", "add_command", "add_handler",
              "connect", "subscribe", "register", "add_periodic_task", "add_websocket_route",
              "add_view", "register_view", "add_resource"}


@dataclass(slots=True)
class CallSite:
    target: str | None      # dotted source text when it is a Name/Attribute chain
    attr: str | None        # trailing attribute name when the receiver is not statically known
    line: int
    kind: str = "call"      # call | unresolved_expr
    args: list[str] = field(default_factory=list)   # dotted callables passed to a registrar


@dataclass(slots=True)
class Marker:
    kind: str
    line: int
    detail: str = ""


@dataclass(slots=True)
class Scope:
    """One executable scope: a function, a method, or a module's top level."""

    node_id: str
    module: str
    qualname: str
    file: str
    line: int
    is_async: bool = False
    decorators: list[str] = field(default_factory=list)
    decorator_details: list[str] = field(default_factory=list)
    params: dict[str, str] = field(default_factory=dict)     # name -> annotation dotted path
    calls: list[CallSite] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)            # names used as values, not called
    bindings: dict[str, str] = field(default_factory=dict)   # local name -> class dotted path
    markers: list[Marker] = field(default_factory=list)
    attr_loads: set[str] = field(default_factory=set)   # attribute names read, for property calls
    str_values: dict[str, str] = field(default_factory=dict)   # name -> literal source, for exec
    is_property: bool = False
    imports: list[tuple[str, str]] = field(default_factory=list)  # (module, alias_or_star)
    class_qual: str = ""                                     # enclosing class, for self resolution
    returns: str = ""


@dataclass(slots=True)
class ClassInfo:
    node_id: str
    module: str
    qualname: str
    file: str
    line: int
    bases: list[str] = field(default_factory=list)
    methods: dict[str, str] = field(default_factory=dict)    # name -> qualname
    attrs: dict[str, str] = field(default_factory=dict)      # self.<name> -> class dotted path
    metaclass: str = ""
    decorators: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ModuleInfo:
    name: str
    file: str
    root: str
    package: str = ""            # distribution that owns it, "" for application code
    is_app: bool = False
    is_native: bool = False
    aliases: dict[str, str] = field(default_factory=dict)   # local name -> dotted target
    star_imports: list[str] = field(default_factory=list)
    scopes: dict[str, Scope] = field(default_factory=dict)  # qualname -> Scope
    classes: dict[str, ClassInfo] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)
    strings: set[str] = field(default_factory=set)   # identifier-shaped literals, app code only
    parse_error: str = ""


def dotted(node: ast.AST) -> str | None:
    """Render a Name/Attribute chain as a dotted string, or None for anything else."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _decorator_detail(node: ast.AST) -> str:
    """`@expose("/export/", methods=["POST"])` rendered back to something a reader recognises."""
    if not isinstance(node, ast.Call):
        return dotted(node) or ""
    name = dotted(node.func) or ""
    literals = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
    methods = [
        m.value for kw in node.keywords if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple))
        for m in kw.value.elts if isinstance(m, ast.Constant) and isinstance(m.value, str)
    ]
    if not literals:
        return name
    verb = "|".join(methods) + " " if methods else ""
    return f'{name}({verb}{literals[0]!r})'


def annotation_of(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip("'\" ")
    if isinstance(node, ast.Subscript):      # Optional[Foo], list[Foo]
        return annotation_of(node.slice)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):   # Foo | None
        left = annotation_of(node.left)
        return left or annotation_of(node.right)
    if isinstance(node, ast.Tuple) and node.elts:
        return annotation_of(node.elts[0])
    return dotted(node) or ""


_IDENTLIKE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


class _Indexer(ast.NodeVisitor):
    def __init__(self, module: ModuleInfo):
        self.m = module
        self.stack: list[Scope] = []
        self.class_stack: list[str] = []
        root = Scope(node_id=f"{module.name}:<module>", module=module.name, qualname="<module>",
                     file=module.file, line=1)
        module.scopes["<module>"] = root
        self.stack.append(root)

    @property
    def scope(self) -> Scope:
        return self.stack[-1]

    # ---- imports -------------------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            target = alias.name
            local = alias.asname or target.split(".")[0]
            # `import a.b` binds `a`, and `a.b` must still resolve, so record both.
            self.m.aliases[local] = target if alias.asname else target.split(".")[0]
            if not alias.asname:
                self.m.aliases.setdefault(target, target)
            self.m.imports.append(target)
            self.scope.imports.append((target, local))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = node.module or ""
        if node.level:
            parent = self.m.name.split(".")
            # `from . import x` inside a package __init__ resolves against the package itself
            if self.m.file.endswith("__init__.py"):
                parent = parent + [""]
            cut = len(parent) - node.level
            base = ".".join([p for p in parent[:cut] if p] + ([base] if base else []))
        for alias in node.names:
            if alias.name == "*":
                self.m.star_imports.append(base)
                self.scope.imports.append((base, "*"))
                self.m.imports.append(base)
                continue
            local = alias.asname or alias.name
            self.m.aliases[local] = f"{base}.{alias.name}" if base else alias.name
            self.m.imports.append(base)
            self.scope.imports.append((base, local))

    # ---- definitions ---------------------------------------------------------------------

    def _enter_function(self, node, is_async: bool) -> None:
        qual = ".".join(self.class_stack + [node.name]) if self.class_stack else node.name
        if len(self.stack) > 1 and not self.class_stack:
            qual = f"{self.scope.qualname}.<locals>.{node.name}"
        scope = Scope(
            node_id=f"{self.m.name}:{qual}", module=self.m.name, qualname=qual, file=self.m.file,
            line=node.lineno, is_async=is_async,
            decorators=[dotted(d.func) if isinstance(d, ast.Call) else dotted(d) or "" for d in node.decorator_list],
            decorator_details=[_decorator_detail(d) for d in node.decorator_list],
            class_qual=".".join(self.class_stack),
            returns=annotation_of(node.returns),
        )
        scope.is_property = any(d.split(".")[-1].endswith("property") for d in scope.decorators)
        args = node.args
        for arg in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
            scope.params[arg.arg] = annotation_of(arg.annotation)
        if args.vararg:
            scope.params[args.vararg.arg] = ""
        if args.kwarg:
            scope.params[args.kwarg.arg] = ""
        self.m.scopes[qual] = scope
        if self.class_stack:
            owner = self.m.classes.get(".".join(self.class_stack))
            if owner is not None:
                owner.methods[node.name] = qual
        # Decorators run at import time and receive the function as a value.
        for dec in node.decorator_list:
            self._visit_value(dec, self.stack[0] if len(self.stack) == 1 else self.scope)
        self.stack.append(scope)
        for stmt in node.body:
            self.visit(stmt)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_function(node, True)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qual = ".".join(self.class_stack + [node.name])
        info = ClassInfo(
            node_id=f"{self.m.name}:{qual}", module=self.m.name, qualname=qual, file=self.m.file,
            line=node.lineno,
            bases=[dotted(b) or "" for b in node.bases if dotted(b)],
            decorators=[dotted(d.func) if isinstance(d, ast.Call) else dotted(d) or "" for d in node.decorator_list],
        )
        self.m.classes[qual] = info
        for dec in node.decorator_list:
            self._visit_value(dec, self.scope)
        for base in node.bases:
            self._visit_value(base, self.scope)
        for kw in node.keywords:
            if kw.arg == "metaclass":
                info.metaclass = dotted(kw.value) or ""
                self.scope.markers.append(Marker("metaclass", node.lineno, info.metaclass or "?"))
        self.class_stack.append(qual)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()

    # ---- statements that bind types ------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        self._bind(node.targets, node.value)
        self.visit(node.value)
        for target in node.targets:
            if isinstance(target, (ast.Attribute, ast.Subscript)):
                self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        hint = annotation_of(node.annotation)
        if isinstance(node.target, ast.Name) and hint:
            self.scope.bindings[node.target.id] = hint
        if node.value is not None:
            self._bind([node.target], node.value)
            self.visit(node.value)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._bind([item.optional_vars], item.context_expr)
            self.visit(item.context_expr)
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncWith = visit_With

    def _bind(self, targets, value) -> None:
        target = targets[0]
        if isinstance(target, ast.Attribute) and not (
                isinstance(target.value, ast.Name) and target.value.id in ("self", "cls")):
            # `Service.handle = bad` at import time replaces a method. The class body still holds
            # the original def, so without this the graph confidently points at dead code.
            alias = dotted(value)
            if alias:
                self.scope.refs.append(alias)
            return
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) \
                and target.value.id in ("self", "cls") and self.class_stack:
            owner = self.m.classes.get(".".join(self.class_stack))
            if owner is not None and isinstance(value, ast.Call):
                callee = dotted(value.func)
                if callee:
                    owner.attrs.setdefault(target.attr, callee)
            return
        if not isinstance(target, ast.Name):
            return
        name = target.id
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            self.scope.str_values[name] = value.value
        if self.class_stack and self.scope.qualname == "<module>" and isinstance(value, ast.Call):
            # `thing = Trigger()` in a class body is an attribute whose type we know.
            owner = self.m.classes.get(".".join(self.class_stack))
            callee = dotted(value.func)
            if owner is not None and callee:
                owner.attrs.setdefault(name, callee)
        if isinstance(value, ast.Call):
            callee = dotted(value.func)
            if callee:
                self.scope.bindings[name] = callee
        else:
            alias = dotted(value)
            if alias:
                # `handler = mod.func` is an alias, tracked so a later `handler()` resolves.
                self.scope.bindings.setdefault(f"={name}", alias)
                self.scope.refs.append(alias)

    def visit_Constant(self, node: ast.Constant) -> None:
        # String literals in application code are the only trace a plugin loader leaves behind.
        if self.m.is_app and isinstance(node.value, str) and 2 < len(node.value) <= 120 \
                and _IDENTLIKE.match(node.value):
            self.m.strings.add(node.value)

    def visit_If(self, node: ast.If) -> None:
        test = node.test
        if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) \
                and test.left.id == "__name__" \
                and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in test.comparators):
            # The body of a main guard does not run on import. Folding it into the module scope
            # makes every library with a `__main__` block look like it calls its own CLI, which is
            # a false path that looks completely ordinary in the output.
            self.scope.markers.append(Marker("main_guard", node.lineno, self.m.name))
            guard = self.m.scopes.get("<main>")
            if guard is None:
                guard = Scope(node_id=f"{self.m.name}:<main>", module=self.m.name,
                              qualname="<main>", file=self.m.file, line=node.lineno)
                self.m.scopes["<main>"] = guard
            self.stack.append(guard)
            for stmt in node.body:
                self.visit(stmt)
            self.stack.pop()
            for stmt in node.orelse:
                self.visit(stmt)
            return
        self.generic_visit(node)

    # ---- calls and value references ------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        target = dotted(node.func)
        if target is not None:
            kind = DYNAMIC_CALLS.get(target) or DYNAMIC_CALLS.get(target.split(".")[-1])
            if kind and target.split(".")[-1] in DYNAMIC_CALLS:
                detail = target
                # `getattr(obj, "run")` names its target in a string. That string is the only
                # thing a static tool gets, and it is worth more than the call site itself.
                literal = next((a.value for a in node.args[1:2]
                                if isinstance(a, ast.Constant) and isinstance(a.value, str)), None)
                if literal and _IDENTLIKE.match(literal):
                    detail = literal
                elif kind == "getattr" and node.args:
                    # `getattr(vuln, name)` with a computed name. The name is unknowable, but the
                    # receiver is not, and it bounds the set of things that can be dispatched.
                    receiver = dotted(node.args[0])
                    if receiver:
                        kind = "getattr_any"
                        detail = receiver
                elif kind in ("eval", "exec") and node.args:
                    if not self._absorb_literal_source(node.args[0], node.lineno):
                        kind = "opaque"      # generated source, nothing to read
                elif kind == "import" and node.args:
                    if not isinstance(node.args[0], ast.Constant):
                        kind = "opaque"      # a computed module name
                self.scope.markers.append(Marker(kind, node.lineno, detail))
            site = CallSite(target=target, attr=target.split(".")[-1], line=node.lineno)
            if site.attr in REGISTRARS:
                site.args = [name for name in
                             (dotted(a) for a in list(node.args) + [k.value for k in node.keywords])
                             if name]
            self.scope.calls.append(site)
        elif isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            if isinstance(receiver, ast.Call):
                # `Parser(source).parse()` names its own type. Rewriting it to `Parser.parse` lets
                # the ordinary class attribute rule resolve it instead of giving up.
                inner = dotted(receiver.func)
                if inner:
                    self.scope.calls.append(
                        CallSite(target=f"{inner}.{node.func.attr}", attr=node.func.attr,
                                 line=node.lineno))
                    for arg in list(receiver.args) + [k.value for k in receiver.keywords]:
                        self._visit_value(arg, self.scope)
                    for arg in list(node.args) + [k.value for k in node.keywords]:
                        self._visit_value(arg, self.scope)
                    return
            site = CallSite(target=None, attr=node.func.attr, line=node.lineno, kind="unresolved_expr")
            if node.func.attr in REGISTRARS:
                site.args = [name for name in
                             (dotted(a) for a in list(node.args) + [k.value for k in node.keywords])
                             if name]
            self.scope.calls.append(site)
            self.visit(node.func.value)
        else:
            container = node.func.value if isinstance(node.func, ast.Subscript) else None
            self.scope.calls.append(CallSite(
                target=None, attr=dotted(container) if container is not None else None,
                line=node.lineno, kind="indirect_call"))
            self.visit(node.func)
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            self._visit_value(arg, self.scope)

    def _absorb_literal_source(self, node: ast.AST, line: int) -> bool:
        """`exec("from vuln import bad\nbad()")` is a call graph hiding inside a string.

        When the argument is a literal that parses as Python, its imports and calls are folded into
        the enclosing scope. A computed string stays opaque, which is what the `opaque` marker is
        for.
        """
        source = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            source = node.value
        elif isinstance(node, ast.Name):
            source = self.scope.str_values.get(node.id)
        if source is None:
            return False
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                inner = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return False
        for stmt in inner.body:
            for child in ast.walk(stmt):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    self.visit(child)
                elif isinstance(child, ast.Call):
                    target = dotted(child.func)
                    if target:
                        self.scope.calls.append(
                            CallSite(target=target, attr=target.split(".")[-1], line=line))
        return True

    def _visit_value(self, node: ast.AST, scope: Scope) -> None:
        """A callable passed as a value is a possible call the graph cannot see directly."""
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = dotted(node)
            if name:
                scope.refs.append(name)
            return
        self.visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            self.scope.attr_loads.add(node.attr)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self._visit_value(node.value, self.scope)

    def _visit_container(self, elements) -> None:
        for element in elements:
            if element is not None:
                self._visit_value(element, self.scope)

    def visit_List(self, node: ast.List) -> None:
        self._visit_container(node.elts)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        self._visit_container(node.elts)

    def visit_Set(self, node: ast.Set) -> None:
        self._visit_container(node.elts)

    def visit_Dict(self, node: ast.Dict) -> None:
        self._visit_container(node.values)


def module_name_for(path: Path, root: Path) -> str | None:
    rel = path.relative_to(root)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    elif parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    else:
        return None
    if not parts or any(not p.isidentifier() for p in parts):
        return None
    return ".".join(parts)


def native_modules(root: Path) -> set[str]:
    out: set[str] = set()
    for ext in ("*.so", "*.pyd", "*.dylib"):
        for path in root.rglob(ext):
            rel = path.relative_to(root)
            stem = _NATIVE_SUFFIX.sub("", rel.name)
            stem = stem.split(".")[0]
            parts = list(rel.parts[:-1]) + [stem]
            if all(p.isidentifier() for p in parts):
                out.add(".".join(parts))
    return out


SKIP_DIRS = {".git", ".tox", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
             ".pytest_cache", "build", "dist", ".eggs", "site-packages"}

# Modules that live in the repository but do not ship with the application. Entry point discovery
# skips them by default and the diagnostics prefer examples from code that actually runs.
DEV_MODULE = re.compile(r"(^|\.)(tests?|testing|conftest|scripts?|tools|docs?|examples?|"
                        r"benchmarks?|docker|RELEASING|ci|dev)(\.|$)")


def is_dev_module(name: str) -> bool:
    return (bool(DEV_MODULE.search(name)) or name.split(".")[-1].startswith("test_")
            or name in ("setup", "conftest", "noxfile"))


class Index:
    def __init__(self) -> None:
        self.modules: dict[str, ModuleInfo] = {}
        self.native: set[str] = set()
        self.errors: list[tuple[str, str]] = []
        self.file_count = 0

    def add_root(self, root: Path, package: str = "", is_app: bool = False,
                 skip_tests: bool = False) -> int:
        root = root.resolve()
        added = 0
        self.native |= native_modules(root)
        for path in sorted(root.rglob("*.py")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if skip_tests and any(part in ("tests", "test", "testing") for part in path.relative_to(root).parts[:-1]):
                continue
            name = module_name_for(path, root)
            if name is None or name in self.modules:
                continue
            self.file_count += 1
            info = ModuleInfo(name=name, file=str(path), root=str(root), package=package, is_app=is_app)
            try:
                with warnings.catch_warnings():
                    # Old packages are full of invalid escape sequences. They parse fine and the
                    # warnings would drown the run's own output.
                    warnings.simplefilter("ignore")
                    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                                     filename=str(path))
            except (SyntaxError, ValueError, RecursionError) as exc:
                info.parse_error = f"{type(exc).__name__}: {exc}"
                self.errors.append((name, info.parse_error))
                self.modules[name] = info
                continue
            indexer = _Indexer(info)
            try:
                for stmt in tree.body:
                    indexer.visit(stmt)
            except RecursionError:
                info.parse_error = "RecursionError while walking"
                self.errors.append((name, info.parse_error))
            self.modules[name] = info
            added += 1
        for name in self.native:
            if name not in self.modules:
                self.modules[name] = ModuleInfo(name=name, file="<native>", root=str(root),
                                                package=package, is_native=True)
        return added

    def is_module(self, name: str) -> bool:
        return name in self.modules

    def longest_module_prefix(self, dotted_name: str) -> tuple[str, str] | None:
        """Split `pkg.mod.Class.method` into the longest known module and the remainder."""
        parts = dotted_name.split(".")
        for cut in range(len(parts), 0, -1):
            candidate = ".".join(parts[:cut])
            if candidate in self.modules:
                return candidate, ".".join(parts[cut:])
        return None

    def stats(self) -> dict:
        scopes = sum(len(m.scopes) for m in self.modules.values())
        return {
            "modules": len(self.modules),
            "files": self.file_count,
            "scopes": scopes,
            "classes": sum(len(m.classes) for m in self.modules.values()),
            "parse_errors": len(self.errors),
            "native_modules": len(self.native),
        }
