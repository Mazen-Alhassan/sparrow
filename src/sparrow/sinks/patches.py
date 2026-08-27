"""Fetch the fix commit diff for an advisory.

The advisory text usually says what went wrong. The patch says where. Fetching the diff here, rather
than letting the extractor browse, keeps `advisory+patch` mode reproducible: the same bytes go into
the prompt on every run, and the two extraction modes differ by exactly one block of text.
"""

from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from ..net import context

DEFAULT_CACHE = Path.home() / ".cache" / "sparrow" / "patches"
COMMIT = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
PULL = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)/?$")
FILE_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$")


def patch_urls(advisory) -> list[str]:
    urls: list[str] = []
    for reference in advisory.references:
        url = reference.get("url", "")
        commit = COMMIT.search(url)
        if commit:
            owner, repo, sha = commit.groups()
            urls.append(f"https://github.com/{owner}/{repo}/commit/{sha}.patch")
            continue
        pull = PULL.search(url)
        if pull:
            owner, repo, number = pull.groups()
            urls.append(f"https://github.com/{owner}/{repo}/pull/{number}.diff")
    return list(dict.fromkeys(urls))[:3]


def _get(url: str, timeout: int = 60) -> str:
    headers = {"User-Agent": "sparrow/0.1", "Accept": "text/plain"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout, context=context()) as response:
        return response.read().decode("utf-8", errors="replace")


def fetch_patch(url: str, cache: Path = DEFAULT_CACHE) -> str:
    cache.mkdir(parents=True, exist_ok=True)
    key = cache / (re.sub(r"[^A-Za-z0-9]+", "_", url)[-120:] + ".patch")
    if key.exists():
        return key.read_text(encoding="utf-8", errors="replace")
    try:
        body = _get(url)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        body = f"__ERROR__ {exc}"
    key.write_text(body)
    return body


def python_hunks(patch: str, max_chars: int = 9000) -> str:
    """Keep only the hunks that touch Python files, and only as much as fits."""
    if patch.startswith("__ERROR__"):
        return ""
    out: list[str] = []
    keep = False
    size = 0
    for line in patch.splitlines():
        header = FILE_HEADER.match(line)
        if header:
            keep = header.group(2).endswith(".py")
            if keep:
                out.append(line)
                size += len(line)
            continue
        if not keep:
            continue
        if line.startswith(("index ", "--- ", "+++ ", "@@", "+", "-", " ")):
            out.append(line)
            size += len(line) + 1
        if size > max_chars:
            out.append("... diff truncated ...")
            break
    return "\n".join(out)


def patch_context(advisory, cache: Path = DEFAULT_CACHE, max_chars: int = 9000) -> str:
    chunks: list[str] = []
    budget = max_chars
    for url in patch_urls(advisory):
        hunks = python_hunks(fetch_patch(url, cache), budget)
        if not hunks:
            continue
        chunks.append(f"--- {url} ---\n{hunks}")
        budget -= len(hunks)
        if budget <= 500:
            break
    return "\n\n".join(chunks)
