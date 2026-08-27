"""Terminal and JSON output.

Read at 100 columns by someone who will not scroll. The funnel first, then every reachable finding
with its call path, then the undetermined count at the same visual weight as the reachable count.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path

from .reach import REACHABLE, UNDETERMINED, UNREACHABLE

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"

EDGE_TEXT = {
    "ref": "guessed, callback reference",
    "virtual": "guessed, subclass override",
    "dynamic": "guessed, name match at a dynamic call site",
    "property": "guessed, property read",
    "dynamic_import": "guessed, module imported by name",
}

REASON_TEXT = {
    "call_path": "concrete call path from an entry point",
    "module_never_imported": "module never imported from any entry point",
    "no_call_path": "module imported, function never called",
    "dev_or_test_only": "only reachable from test entry points",
    "dynamic_dispatch": "blocked by dynamic dispatch",
    "callback_reference": "referenced as a callback, never called directly",
    "native_boundary": "path crosses a compiled extension",
    "no_verified_sink": "no function-level sink survived verification",
    "virtual_dispatch": "only through a subclass override",
}


def _colour_enabled(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class Renderer:
    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self.colour = _colour_enabled(self.stream)

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.colour else text

    def write(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    # ---- sections ------------------------------------------------------------------------

    def header(self, results: dict) -> None:
        target = results["target"]
        self.write()
        self.write(f"{self._c('sparrow', BOLD)}  {target['name']}  "
                   f"{self._c(target['lockfile'], DIM)}")
        stats = results["stats"]
        self.write(self._c(
            f"  {stats['packages']} packages, {stats['modules']} modules, "
            f"{stats['scopes']} functions, {stats['entry_points']} entry points, "
            f"{stats['edges']} call edges", DIM))
        self.write()

    def funnel(self, results: dict) -> None:
        counts = results["counts"]
        total = counts["advisories_unique"]
        raw = counts["advisories_raw"]
        width = 46

        def bar(value: int, code: str) -> str:
            filled = 0 if not total else max(1, round(value / total * width)) if value else 0
            return self._c("█" * filled, code) + self._c("·" * (width - filled), DIM)

        self.write(f"{self._c(str(raw), BOLD)} advisories reported by OSV, "
                   f"{self._c(str(total), BOLD)} unique after merging GHSA and PYSEC duplicates")
        self.write()
        rows = [
            ("reachable", counts[REACHABLE], RED),
            ("undetermined", counts[UNDETERMINED], YELLOW),
            ("not reachable", counts[UNREACHABLE], GREEN),
        ]
        for label, value, code in rows:
            self.write(f"  {label:<14} {self._c(f'{value:>4}', BOLD)}  {bar(value, code)}")
        self.write()
        direct = counts.get("reachable_direct", 0)
        self.write(self._c(f"  {counts[REACHABLE]} reachable ({direct} in a direct dependency), "
                           f"{counts[UNDETERMINED]} undetermined "
                           f"(dynamic dispatch, callbacks, native code, or no verified sink)", DIM))
        self.write()

    def findings(self, results: dict, bucket: str = REACHABLE, limit: int = 0) -> None:
        rows = [f for f in results["findings"] if f["bucket"] == bucket]
        if not rows:
            return
        rows = rows[:limit] if limit else rows
        for finding in rows:
            self._finding(finding, results["target"]["roots"])

    def _shorten(self, path: str, roots: list[str]) -> str:
        for root in roots:
            if path.startswith(root):
                return path[len(root):].lstrip("/")
        parts = Path(path).parts
        return "/".join(parts[-3:]) if len(parts) > 3 else path

    def _finding(self, finding: dict, roots: list[str]) -> None:
        name = finding["cve"] or finding["advisory"]
        head = (f"{self._c(name, BOLD)}  severity {finding['severity']}  "
                f"{finding['package']} {finding['version']}"
                f"{'' if finding['direct'] else self._c('  (transitive)', DIM)}")
        self.write(head)
        for sink in finding["sinks"]:
            self.write(f"  {self._c(sink, CYAN)}")
        for path in finding.get("paths", [])[:1]:
            self.write()
            frames = path["frames"]
            for position, frame in enumerate(frames):
                location = f"{self._shorten(frame['file'], roots)}:{frame['line']}"
                label = frame["node"].split(":", 1)[1]
                marker = ""
                if position == len(frames) - 1:
                    marker = self._c("   <-- vulnerable", RED)
                elif frame["edge"] in ("ref", "virtual", "dynamic", "property", "dynamic_import"):
                    marker = self._c(f"   <-- {EDGE_TEXT[frame['edge']]}", YELLOW)
                self.write(f"    {location:<44} {label}(){marker}")
            entry = path["entrypoint"]
            self.write()
            self.write(self._c(f"    reachable from: {entry['detail'] or entry['node']}  "
                               f"({entry['kind']})", DIM))
            taint = finding.get("taint")
            if taint:
                label = {"tainted": "request data reaches the arguments",
                         "clean": "no request data on this path",
                         "unknown": "data flow undetermined"}[taint["status"]]
                colour = RED if taint["status"] == "tainted" else DIM
                if taint["status"] == "tainted" and taint.get("source"):
                    label += f", source {taint['source']}"
                elif taint["status"] != "tainted":
                    label += f": {taint['reason']}"
                for position, line in enumerate(textwrap.wrap(f"taint: {label}", 92)):
                    self.write(self._c(("    " if position == 0 else "           ") + line, colour))
        if finding["bucket"] != REACHABLE:
            self.write(self._c(f"    {REASON_TEXT.get(finding['reason'], finding['reason'])}"
                               f"{': ' + finding['evidence'] if finding['evidence'] else ''}", DIM))
        self.write()

    def breakdown(self, results: dict) -> None:
        self.write(self._c("why the rest are not reachable", BOLD))
        self.write()
        by_reason: dict[str, int] = {}
        for finding in results["findings"]:
            if finding["bucket"] == REACHABLE:
                continue
            by_reason[finding["reason"]] = by_reason.get(finding["reason"], 0) + 1
        for reason, count in sorted(by_reason.items(), key=lambda kv: -kv[1]):
            self.write(f"  {count:>4}  {reason:<24} {self._c(REASON_TEXT.get(reason, ''), DIM)}")
        self.write()

    def timings(self, timings: dict) -> None:
        parts = ", ".join(f"{name} {value:.1f}s" for name, value in timings.items())
        self.write(self._c(f"  {parts}", DIM))
        self.write()


def render(results: dict, stream=None, show: str = "reachable", limit: int = 0) -> None:
    renderer = Renderer(stream)
    renderer.header(results)
    renderer.funnel(results)
    if show in ("reachable", "all"):
        renderer.findings(results, REACHABLE, limit)
    if show in ("undetermined", "all"):
        renderer.findings(results, UNDETERMINED, limit)
    renderer.breakdown(results)
    renderer.timings(results.get("timings", {}))


def write_json(results: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2, sort_keys=False) + "\n")
