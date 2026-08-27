"""Partial taint tracking, from a request parameter to the sink.

Reachability says the vulnerable function is callable. It does not say an attacker controls what it
is called with, and that gap is the most common and most correct critique of every reachability
tool. This narrows it a little.

The analysis is deliberately small. It runs only on paths that are already reachable, walks the
frames from the entry point to the sink, and asks at each hop whether the argument handed to the next
frame came from a request. It is flow-sensitive within a function, positional across a call, and it
gives up loudly rather than guessing. It is not a substitute for a real data flow analysis, and the
`unknown` verdict is expected to be the common one.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from .index import Index, dotted

# Attribute chains that hand an application attacker-controlled bytes. Flask and Django spellings.
SOURCE_ROOTS = ("request", "self.request", "req", "flask.request")
SOURCE_ATTRS = (
    "args", "form", "json", "values", "data", "files", "headers", "cookies", "query_params",
    "get_json", "get_data", "GET", "POST", "body", "stream", "form_data", "params", "view_args",
)

TAINTED = "tainted"
CLEAN = "clean"
UNKNOWN = "unknown"


@dataclass
class TaintResult:
    status: str
    reason: str = ""
    source: str = ""
    broke_at: str = ""
    hops: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason, "source": self.source,
                "broke_at": self.broke_at, "hops": self.hops}


def _is_source(node: ast.AST) -> str:
    """Return the source expression text when this node reads request data."""
    text = dotted(node)
    if text:
        parts = text.split(".")
        for position, part in enumerate(parts[:-1]):
            if part in ("request", "req") and parts[position + 1] in SOURCE_ATTRS:
                return text
        if text in SOURCE_ROOTS:
            return text
    if isinstance(node, ast.Call):
        inner = dotted(node.func)
        if inner and any(inner.endswith(f".{attr}") for attr in ("get_json", "get_data")):
            if any(part in ("request", "req") for part in inner.split(".")):
                return inner
    return ""


def _is_source_text(text: str) -> bool:
    parts = text.split(".")
    return any(part in ("request", "req") and position + 1 < len(parts)
               and parts[position + 1] in SOURCE_ATTRS
               for position, part in enumerate(parts))


def _expression_taint(node: ast.AST, tainted: set[str]) -> str:
    """Non-empty when the expression carries tainted data. Any call is treated as passing it on."""
    for child in ast.walk(node):
        source = _is_source(child)
        if source:
            return source
        if isinstance(child, ast.Name) and child.id in tainted:
            return child.id
        if isinstance(child, ast.Attribute):
            base = dotted(child)
            if base and base.split(".")[0] in tainted:
                return base
    return ""


def _parse(path: str) -> ast.Module | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError, RecursionError):
        return None


def _find_def(tree: ast.Module, qualname: str) -> ast.AST | None:
    """Locate a function by the qualname the index uses."""
    if qualname in ("<module>", "<main>"):
        return tree
    parts = [p for p in qualname.split(".") if p != "<locals>"]
    node: ast.AST = tree
    for part in parts:
        found = None
        for child in ast.walk(node) if node is tree else ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                    and child.name == part:
                found = child
                break
        if found is None:
            return None
        node = found
    return node


def _param_names(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    args = node.args
    names = [a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)]
    return [n for n in names if n not in ("self", "cls")]


def _calls_to(node: ast.AST, target_name: str) -> list[ast.Call]:
    """Call sites in this function whose callee ends in the next frame's name."""
    out = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        text = dotted(child.func)
        if text and text.split(".")[-1] == target_name:
            out.append(child)
        elif isinstance(child.func, ast.Attribute) and child.func.attr == target_name:
            out.append(child)
    return out


def trace(path_frames: list[dict], index: Index, entry_kind: str) -> TaintResult:
    """Walk a reachable path and decide whether request data reaches the sink."""
    if len(path_frames) < 2:
        return TaintResult(UNKNOWN, "path has no call hops")

    tainted: set[str] = set()
    source = ""
    hops: list[str] = []

    for position, frame in enumerate(path_frames[:-1]):
        following = path_frames[position + 1]
        if following.get("edge") not in ("call", "ctor"):
            return TaintResult(UNKNOWN, f"path hop is a {following.get('edge')} edge, not a call",
                               source=source, broke_at=following["node"], hops=hops)

        tree = _parse(frame["file"])
        if tree is None:
            return TaintResult(UNKNOWN, "could not parse the frame", source=source,
                               broke_at=frame["node"], hops=hops)
        qualname = frame["node"].split(":", 1)[1]
        definition = _find_def(tree, qualname)
        if definition is None:
            return TaintResult(UNKNOWN, "could not locate the function in its file",
                               source=source, broke_at=frame["node"], hops=hops)

        if position == 0 and entry_kind == "http_route":
            # URL path converters arrive as parameters of the view.
            for name in _param_names(definition):
                tainted.add(name)
                source = source or f"{qualname}({name})"

        for statement in ast.walk(definition):
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if value is None:
                    continue
                carried = _expression_taint(value, tainted)
                if not carried:
                    continue
                source = source or carried
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)
                    elif isinstance(target, ast.Tuple):
                        for element in target.elts:
                            if isinstance(element, ast.Name):
                                tainted.add(element.id)

        next_name = following["node"].split(":", 1)[1].split(".")[-1]
        call_sites = _calls_to(definition, next_name)
        if not call_sites:
            return TaintResult(UNKNOWN, f"could not find the call to {next_name} in the source",
                               source=source, broke_at=frame["node"], hops=hops)

        carried = ""
        receiver_carried = ""
        for call in call_sites:
            for argument in list(call.args) + [kw.value for kw in call.keywords]:
                found = _expression_taint(argument, tainted)
                if found:
                    carried = found
                    if _is_source_text(found):
                        break
            if isinstance(call.func, ast.Attribute):
                receiver_carried = _expression_taint(call.func.value, tainted) or receiver_carried
        if not carried:
            if receiver_carried:
                # `Command(client_id=tainted).run()`. The value is on the object, and object state
                # is not tracked, so calling this clean would be a guess dressed as an answer.
                return TaintResult(
                    UNKNOWN,
                    f"{next_name} takes no tainted argument, but its receiver was built from "
                    f"{receiver_carried}, and values carried on object state are not tracked",
                    source=source or receiver_carried, broke_at=frame["node"], hops=hops)
            return TaintResult(CLEAN, f"{next_name} is called with no request derived argument",
                               source=source, broke_at=frame["node"], hops=hops)

        # A literal request read beats a parameter seeded at the entry point.
        if _is_source_text(carried) or not source:
            source = carried
        hops.append(f"{frame['node']} -> {following['node']} carrying {carried}")

        next_tree = _parse(following["file"])
        next_def = _find_def(next_tree, following["node"].split(":", 1)[1]) if next_tree else None
        tainted = set(_param_names(next_def)) if next_def else set()
        if not tainted and position + 1 < len(path_frames) - 1:
            return TaintResult(UNKNOWN, f"{next_name} takes no named parameters to carry it",
                               source=source, broke_at=following["node"], hops=hops)

    return TaintResult(TAINTED, "request data reaches the vulnerable function's arguments",
                       source=source, hops=hops)
