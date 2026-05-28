"""
Shared utilities for AI Agent Risk Analyzers.

Provides:
  - smart_truncate()     : head + tail + keyword-context truncation
  - extract_local_imports(): parse import statements → local file paths
"""
import re
from typing import List


# ── Smart truncation constants ────────────────────────────────────────────────
HEAD_LINES    = 200   # always include first N lines (class defs, imports, init)
TAIL_LINES    = 100   # always include last N lines  (main(), entry points, tool registration)
CTX_WINDOW    = 10    # lines before/after each keyword hit

# Keywords indicating relevant code sections (union of capability + safety terms)
_CAPABILITY_KW = [
    "tool", "exec", "shell", "run", "agent", "bash", "subprocess", "os.system",
    "eval", "invoke", "dispatch", "browser", "email", "database", "cloud", "aws",
    "file", "write", "delete", "upload", "download", "request", "http",
]
_SAFETY_KW = [
    "approve", "confirm", "human", "guardrail", "safety", "limit", "max_step",
    "allowlist", "whitelist", "permission", "dry_run", "sandbox", "prompt",
    "injection", "validate", "sanitize", "checkpoint",
]
_ALL_KW = list(set(_CAPABILITY_KW + _SAFETY_KW))


def smart_truncate(content: str, max_lines: int, mode: str = "capability") -> str:
    """
    Return up to max_lines lines from content, prioritising:
      1. First HEAD_LINES lines
      2. Last  TAIL_LINES lines
      3. ±CTX_WINDOW lines around keyword matches

    Gaps are replaced with a single marker line so the LLM knows content was omitted.

    mode: "capability" | "safety" | "all"
    """
    lines = content.splitlines()
    if len(lines) <= max_lines:
        return content

    kws = _SAFETY_KW if mode == "safety" else (_ALL_KW if mode == "all" else _CAPABILITY_KW)

    # Collect line indices
    head_idx = set(range(min(HEAD_LINES, len(lines))))
    tail_idx  = set(range(max(0, len(lines) - TAIL_LINES), len(lines)))

    kw_idx: set = set()
    for i, line in enumerate(lines):
        if any(kw in line.lower() for kw in kws):
            lo = max(0, i - CTX_WINDOW)
            hi = min(len(lines), i + CTX_WINDOW + 1)
            kw_idx.update(range(lo, hi))

    all_idx = sorted(head_idx | tail_idx | kw_idx)

    # If still over budget, drop keyword context first
    if len(all_idx) > max_lines:
        priority = sorted(head_idx | tail_idx)
        remaining = max_lines - len(priority)
        extra = sorted(kw_idx - head_idx - tail_idx)
        all_idx = sorted(set(priority) | set(extra[:max(0, remaining)]))

    # Build numbered output with omission markers
    result: List[str] = []
    prev = -1
    for idx in all_idx:
        if prev >= 0 and idx > prev + 1:
            skipped = idx - prev - 1
            result.append(f"     | ··· {skipped} lines omitted ···")
        result.append(f"{idx+1:4d} | {lines[idx]}")
        prev = idx

    return "\n".join(result)


# ── Import tracking ───────────────────────────────────────────────────────────

# Entry-point file names to seed import traversal
ENTRY_NAMES = {
    "main.py", "app.py", "agent.py", "run.py", "server.py",
    "cli.py", "entrypoint.py", "start.py", "__main__.py",
    "main.ts", "app.ts", "agent.ts", "index.ts", "index.js",
}

_IMPORT_PATTERNS = [
    re.compile(r'^\s*import\s+([\w.]+)'),
    re.compile(r'^\s*from\s+([\w.]+)\s+import'),
    # TypeScript / JS
    re.compile(r'''^\s*import\s+.*?from\s+['"](\.{1,2}/[\w./]+)['"]'''),
    re.compile(r'''^\s*(?:const|let|var)\s+\w+\s*=\s*require\(['"](.+?)['"]\)'''),
]


def extract_local_imports(content: str, all_files: List[str]) -> List[str]:
    """
    Parse import/require statements from content and return matching file paths
    that actually exist in the repo's file tree (all_files).

    Handles:
      Python:     import foo.bar / from foo.bar import baz
      TS/JS:      import X from './tools/browser'  /  require('./core/executor')
    """
    file_set = set(all_files)
    modules: set = set()

    for line in content.splitlines():
        for pat in _IMPORT_PATTERNS:
            m = pat.match(line)
            if m:
                modules.add(m.group(1))

    matched: List[str] = []
    for mod in modules:
        # ── Python: foo.bar.baz → foo/bar/baz.py ─────────────────────────────
        if not mod.startswith("."):
            path_base = mod.replace(".", "/")
            _check_candidates(path_base, file_set, matched, extensions=[".py"])
        # ── TS/JS relative: ./tools/browser → tools/browser.ts etc. ──────────
        else:
            norm = mod.lstrip("./").replace("/./", "/")
            _check_candidates(norm, file_set, matched, extensions=[".ts", ".js", ".py"])

    # Deduplicate preserving order
    return list(dict.fromkeys(matched))


def _check_candidates(path_base: str, file_set: set, matched: list, extensions: list):
    """Try common file-path expansions and add any that exist in file_set."""
    guesses = []
    for ext in extensions:
        guesses += [
            f"{path_base}{ext}",
            f"{path_base}/__init__{ext}",   # Python package
            f"src/{path_base}{ext}",
        ]
    for guess in guesses:
        if guess in file_set:
            matched.append(guess)
        else:
            # Partial suffix match (handles deep paths like agents/tools/browser.py)
            for f in file_set:
                if f.endswith(f"/{path_base}{ext}") or f.endswith(f"/{path_base}/__init__{ext}"):
                    matched.append(f)
                    break


def boost_imports(
    entry_contents: dict,   # {path: content} of already-fetched entry files
    all_files: List[str],
    candidates: List[str],
    max_candidates: int,
) -> List[str]:
    """
    For each entry file, extract local imports and prepend them to candidates
    (without exceeding max_candidates total).

    Returns updated candidates list.
    """
    imported: List[str] = []
    for content in entry_contents.values():
        imported.extend(extract_local_imports(content, all_files))

    # Deduplicate; exclude already-present candidates
    new_imports = [f for f in dict.fromkeys(imported) if f not in candidates]
    # Prepend imported files (high priority), keep total ≤ max_candidates
    combined = new_imports + candidates
    return list(dict.fromkeys(combined))[:max_candidates]
