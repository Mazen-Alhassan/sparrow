"""Advisory prose to function-level sinks.

The model is asked for the vulnerable function, its confidence, its evidence, and its assumptions.
The assumptions field is the one that matters: it is what `verify.py` checks. Extraction output is
cached on disk and committed, so a run reproduces without an API key and the numbers in the README
do not move when a model changes.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from ..net import context
from ..osv import Advisory
from .patches import patch_context

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-opus-4-5-20251101"
MODES = ("advisory-only", "advisory+patch")

PROMPT = """You convert advisory prose into function-level sinks for a static reachability analyser.

Mode: {mode}
{mode_rule}

Advisory {id} ({aliases})
Package: {package} {version}
Fixed in: {fixed}
Severity: {severity}

Summary: {summary}

Details:
{details}

References:
{references}
{patch}

Return exactly this JSON object and nothing else:

{{"advisory": "{id}", "package": "{package}", "sinks": ["pkg.module.Class.method"],
 "confidence": "high|medium|low", "evidence": "...", "assumptions": ["..."], "mode": "{mode}"}}

Rules:
- Fully qualified identifiers only. A bare function name is not an answer.
- Name the function that contains the flaw, not the public API a user calls, unless they are the same.
- sinks may be empty. An empty list with an honest assumption beats a guess.
- confidence is high only when the advisory or the patch names the function.
- Put every inference that could be wrong in assumptions. A verifier checks them against the patch diff.
"""

MODE_RULES = {
    "advisory-only": "You get the advisory text and nothing else. No diff, no source, no lookups.",
    "advisory+patch": "You get the advisory text and the Python hunks of the linked fix commit below.",
}


@dataclass
class SinkRecord:
    advisory: str
    package: str
    sinks: list[str] = field(default_factory=list)
    confidence: str = "low"
    evidence: str = ""
    assumptions: list[str] = field(default_factory=list)
    mode: str = "advisory-only"
    verification: dict = field(default_factory=dict)

    @property
    def status(self) -> str:
        """A record is usable only when at least one sink verified against the patch."""
        if not self.sinks:
            return "no_sink"
        states = {v.get("status") for v in self.verification.values()}
        if "verified" in states:
            return "verified"
        if not states:
            return "unverified"
        return sorted(states)[0]

    @property
    def verified_sinks(self) -> list[str]:
        return [s for s in self.sinks if self.verification.get(s, {}).get("status") == "verified"]

    def to_dict(self) -> dict:
        return {
            "advisory": self.advisory, "package": self.package, "sinks": self.sinks,
            "confidence": self.confidence, "evidence": self.evidence,
            "assumptions": self.assumptions, "mode": self.mode, "verification": self.verification,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SinkRecord":
        return cls(
            advisory=data["advisory"], package=data.get("package", ""),
            sinks=list(data.get("sinks") or []), confidence=data.get("confidence", "low"),
            evidence=data.get("evidence", ""), assumptions=list(data.get("assumptions") or []),
            mode=data.get("mode", "advisory-only"), verification=data.get("verification", {}) or {},
        )


def build_prompt(advisory: Advisory, mode: str = "advisory-only", patch: str = "") -> str:
    references = "\n".join(f"- {r.get('type', '?')}: {r.get('url', '')}" for r in advisory.references[:12])
    patch_block = f"\nFix commit, Python hunks only:\n{patch}\n" if patch and mode == "advisory+patch" else (
        "\n(no fix commit is linked from this advisory)\n" if mode == "advisory+patch" else "")
    return PROMPT.format(
        patch=patch_block,
        mode=mode, mode_rule=MODE_RULES[mode], id=advisory.id,
        aliases=", ".join(advisory.aliases) or "none", package=advisory.package,
        version=advisory.version, fixed=", ".join(advisory.fixed_versions) or "unknown",
        severity=advisory.severity, summary=advisory.summary or "(none)",
        details=(advisory.details or "(none)")[:6000], references=references or "(none)",
    )


def load_cache(directory: Path) -> dict[str, SinkRecord]:
    out: dict[str, SinkRecord] = {}
    if not directory.exists():
        return out
    for path in sorted(directory.glob("*.json")):
        try:
            record = SinkRecord.from_dict(json.loads(path.read_text()))
        except (json.JSONDecodeError, KeyError, OSError):
            continue
        out[record.advisory] = record
    return out


def save(record: SinkRecord, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{record.advisory}.json").write_text(json.dumps(record.to_dict(), indent=2) + "\n")


def emit_prompts(advisories: list[Advisory], directory: Path, mode: str = "advisory-only") -> int:
    """Write one prompt per advisory for the cve-extractor agent to answer."""
    directory.mkdir(parents=True, exist_ok=True)
    for advisory in advisories:
        patch = patch_context(advisory) if mode == "advisory+patch" else ""
        (directory / f"{advisory.id}.txt").write_text(build_prompt(advisory, mode, patch))
    return len(advisories)


_JSON = re.compile(r"\{.*\}", re.S)


def extract_with_api(advisory: Advisory, mode: str = "advisory-only", model: str = MODEL,
                     timeout: int = 120) -> SinkRecord | None:
    """Live extraction. Used when ANTHROPIC_API_KEY is set; otherwise the cache is authoritative."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    payload = {
        "model": model, "max_tokens": 1024,
        "messages": [{"role": "user", "content": build_prompt(
            advisory, mode, patch_context(advisory) if mode == "advisory+patch" else "")}],
    }
    request = urllib.request.Request(
        API_URL, data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "x-api-key": key,
                 "anthropic-version": "2023-06-01"},
    )
    with urllib.request.urlopen(request, timeout=timeout, context=context()) as response:
        body = json.loads(response.read())
    text = "".join(block.get("text", "") for block in body.get("content", []))
    match = _JSON.search(text)
    if not match:
        return None
    try:
        return SinkRecord.from_dict(json.loads(match.group(0)))
    except (json.JSONDecodeError, KeyError):
        return None
