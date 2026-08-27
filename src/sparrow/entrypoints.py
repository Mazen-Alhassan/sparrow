"""Entry point discovery.

Missing an entry point under-reports reachability, which is the dangerous direction of wrong, so the
rules here are deliberately generous. A wrongly included entry point costs a false positive that a
human can see and dismiss from the call path. A missed one costs a vulnerability nobody looks at.
"""

from __future__ import annotations

import ast
import configparser
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .callgraph import CallGraph
from .index import Index, dotted, is_dev_module

ROUTE_DECORATORS = re.compile(
    r"(^|\.)(route|get|post|put|delete|patch|head|options|websocket|expose|expose_api|"
    r"add_url_rule|api_route|endpoint)$"
)
ROUTE_RECEIVERS = re.compile(r"^(app|application|api|bp|blueprint|router|mod|self|cls)$|"
                             r"(_bp|_app|_api|_router|blueprint|_view)$")
TASK_DECORATORS = re.compile(r"(^|\.)(task|shared_task|periodic_task|celery_task)$")
CLI_DECORATORS = re.compile(r"(^|\.)(command|group|cli)$")
SIGNAL_DECORATORS = re.compile(r"(^|\.)(receiver|connect|listens_for|on_event|before_request|"
                               r"after_request|teardown_request|errorhandler|hookimpl)$")
# Reachability that runs only through repository tooling is real, but it is not production
# reachability, and conflating the two inflates the number a reader is asked to act on.


@dataclass
class EntryPoint:
    kind: str
    node: str
    detail: str = ""
    file: str = ""
    line: int = 0

    def to_dict(self) -> dict:
        return {"kind": self.kind, "node": self.node, "detail": self.detail,
                "file": self.file, "line": self.line}


_is_dev_module = is_dev_module


def discover(index: Index, graph: CallGraph, target_root: Path,
             include_tests: bool = False) -> list[EntryPoint]:
    found: dict[str, EntryPoint] = {}

    def add(kind: str, node: str, detail: str = "") -> None:
        if node in found:
            return
        module_name = node.split(":", 1)[0]
        if not include_tests and _is_dev_module(module_name):
            return
        file, line = graph.node_location(node)
        found[node] = EntryPoint(kind, node, detail, file, line)

    app_modules = [m for m in index.modules.values() if m.is_app and not m.parse_error]

    for module in app_modules:
        if module.name.endswith("__main__") or module.name == "__main__":
            add("dunder_main", f"{module.name}:<module>", module.name)
        for scope in module.scopes.values():
            for marker in scope.markers:
                if marker.kind == "main_guard":
                    add("main_guard", f"{module.name}:<main>", module.name)
        if module.name.split(".")[-1] in ("wsgi", "asgi", "app", "application", "manage"):
            add("wsgi_asgi", f"{module.name}:<module>", module.name.split(".")[-1])

        for qualname, scope in module.scopes.items():
            for position, decorator in enumerate(scope.decorators):
                if not decorator:
                    continue
                head = decorator.split(".")[0]
                tail = decorator.rsplit(".", 1)[-1]
                label = (scope.decorator_details[position]
                         if position < len(scope.decorator_details) else decorator) or decorator
                if ROUTE_DECORATORS.search(decorator) and (
                    "." not in decorator or ROUTE_RECEIVERS.search(head) or tail in ("route", "expose", "expose_api")
                ):
                    add("http_route", scope.node_id, label)
                elif TASK_DECORATORS.search(decorator):
                    add("task", scope.node_id, label)
                elif CLI_DECORATORS.search(decorator):
                    add("cli_command", scope.node_id, label)
                elif SIGNAL_DECORATORS.search(decorator):
                    add("signal_hook", scope.node_id, label)

    _registrar_calls(index, graph, app_modules, add)
    _app_factories(index, graph, app_modules, add)
    _django_urls(index, graph, app_modules, add)
    _entry_point_metadata(index, graph, target_root, add)
    _as_view_calls(index, graph, app_modules, add)

    if include_tests:
        for module in index.modules.values():
            if not module.is_app or not _is_dev_module(module.name):
                continue
            for qualname, scope in module.scopes.items():
                if qualname.split(".")[-1].startswith("test_") or qualname == "main" or \
                        any(CLI_DECORATORS.search(d) for d in scope.decorators if d):
                    add("dev_tool", scope.node_id, module.name)

    return sorted(found.values(), key=lambda e: (e.kind, e.node))


FACTORY_NAMES = {"create_app", "make_app", "make_wsgi_app", "get_application", "create_application",
                 "main", "run", "app_factory"}
FACTORY_MODULES = {"wsgi", "asgi", "app", "application", "manage", "__main__", "server", "main"}


def _registrar_calls(index: Index, graph: CallGraph, app_modules, add) -> None:
    """`app.add_url_rule("/x", view_func=handler)` registers `handler` with the framework."""
    for module in app_modules:
        for scope in module.scopes.values():
            for call in scope.calls:
                if not call.args:
                    continue
                for name in call.args:
                    resolved = graph.resolve_in_module(name, module, scope)
                    if resolved is None:
                        continue
                    if resolved[0] == "func":
                        add("registered_callable", resolved[1], f"{call.attr}()")
                    elif resolved[0] == "class":
                        class_module, qual = resolved[1].split(":", 1)
                        info = index.modules[class_module].classes.get(qual)
                        for method in ("dispatch_request", "get", "post", "run", "__call__", "handle"):
                            if info and method in info.methods:
                                add("registered_callable", f"{class_module}:{info.methods[method]}",
                                    f"{call.attr}()")


def _app_factories(index: Index, graph: CallGraph, app_modules, add) -> None:
    """A WSGI server calls the factory named in its config, and nothing in the repo calls it."""
    for module in app_modules:
        if module.name.split(".")[-1] not in FACTORY_MODULES and "." in module.name:
            continue
        for qualname, scope in module.scopes.items():
            if qualname in FACTORY_NAMES:
                add("app_factory", scope.node_id, f"{module.name}:{qualname}")


def _django_urls(index: Index, graph: CallGraph, app_modules, add) -> None:
    """Views named in a urls module are entry points, whether referenced or `.as_view()`d."""
    for module in app_modules:
        if not module.name.split(".")[-1].startswith("urls"):
            continue
        scope = module.scopes.get("<module>")
        if scope is None:
            continue
        for ref in set(scope.refs):
            resolved = graph.resolve_in_module(ref, module, scope)
            if resolved is None:
                continue
            if resolved[0] == "func":
                add("django_url", resolved[1], module.name)
            elif resolved[0] == "class":
                class_module, qual = resolved[1].split(":", 1)
                info = index.modules[class_module].classes.get(qual)
                for name in ("get", "post", "dispatch", "as_view", "__call__"):
                    if info and name in info.methods:
                        add("django_url", f"{class_module}:{info.methods[name]}", module.name)


def _as_view_calls(index: Index, graph: CallGraph, app_modules, add) -> None:
    for module in app_modules:
        for scope in module.scopes.values():
            for call in scope.calls:
                if not call.target or not call.target.endswith(".as_view"):
                    continue
                resolved = graph.resolve_in_module(call.target[: -len(".as_view")], module, scope)
                if resolved and resolved[0] == "class":
                    class_module, qual = resolved[1].split(":", 1)
                    info = index.modules[class_module].classes.get(qual)
                    for name in ("get", "post", "put", "delete", "dispatch"):
                        if info and name in info.methods:
                            add("django_url", f"{class_module}:{info.methods[name]}", "as_view")


def _record_target(index: Index, graph: CallGraph, target: str, kind: str, detail: str, add) -> None:
    """`pkg.module:func` from packaging metadata."""
    if ":" not in target:
        module_name, attr = target.strip(), ""
    else:
        module_name, attr = (part.strip() for part in target.split(":", 1))
    module = index.modules.get(module_name)
    if module is None:
        return
    if not attr:
        add(kind, f"{module_name}:<module>", detail)
        return
    resolved = graph.resolve_in_module(attr, module, None)
    if resolved and resolved[0] == "func":
        add(kind, resolved[1], detail)
    elif resolved and resolved[0] == "class":
        init = graph._init_of(resolved[1])
        if init:
            add(kind, init, detail)
    else:
        add(kind, f"{module_name}:<module>", detail)


def _entry_point_metadata(index: Index, graph: CallGraph, root: Path, add) -> None:
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            data = {}
        project = data.get("project", {})
        for name, target in (project.get("scripts", {}) or {}).items():
            _record_target(index, graph, target, "console_script", name, add)
        for group, entries in (project.get("entry-points", {}) or {}).items():
            for name, target in (entries or {}).items():
                _record_target(index, graph, target, "plugin_entry", f"{group}:{name}", add)
        poetry = data.get("tool", {}).get("poetry", {})
        for name, target in (poetry.get("scripts", {}) or {}).items():
            _record_target(index, graph, target, "console_script", name, add)

    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists():
        parser = configparser.ConfigParser()
        try:
            parser.read(setup_cfg)
            if parser.has_section("options.entry_points"):
                for group, block in parser.items("options.entry_points"):
                    for line in block.strip().splitlines():
                        if "=" in line:
                            name, target = line.split("=", 1)
                            kind = "console_script" if "console" in group else "plugin_entry"
                            _record_target(index, graph, target, kind, f"{group}:{name.strip()}", add)
        except (configparser.Error, OSError):
            pass

    setup_py = root / "setup.py"
    if setup_py.exists():
        try:
            tree = ast.parse(setup_py.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, OSError):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or dotted(node.func) not in ("setup", "setuptools.setup"):
                continue
            for keyword in node.keywords:
                if keyword.arg != "entry_points":
                    continue
                for group, targets in _literal_entry_points(keyword.value):
                    for target in targets:
                        name, _, spec = target.partition("=")
                        kind = "console_script" if "console" in group else "plugin_entry"
                        _record_target(index, graph, spec or name, kind, f"{group}:{name.strip()}", add)


def _literal_entry_points(node: ast.AST):
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant):
                continue
            items: list[str] = []
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                items = [line for line in value.value.splitlines() if line.strip()]
            elif isinstance(value, (ast.List, ast.Tuple)):
                items = [e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            yield str(key.value), items
