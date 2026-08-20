"""Deterministic hardcoded-secret / credential leak detection.

Scans a directory of skill files for accidentally committed credentials
(API keys, cloud AK/SK, private keys, tokens).  SkillSpector itself has no
rule family for *leaked* secrets (its E2/PE3/TT3 rules detect credential
*theft behaviour*), and its SQP semantic rules are outside this project's
malicious-intent allowlist — so this module closes that gap with
regex + Shannon-entropy checks.

Findings are returned in the same dict shape SkillSpector issues use, so
they can be merged straight into ``SkillAnalyzer`` results:

    {
        "id": "HS-AWS",
        "severity": "CRITICAL",
        "category": "Hardcoded Secret",
        "location": {"file": "relative/path.md", "start_line": 12},
        "finding": "...",
        "explanation": "...",
        "remediation": "...",
        "code_snippet": "<redacted line>",
    }

Secrets are ALWAYS redacted in every emitted field — the full value must
never reach a report.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

CATEGORY = "Hardcoded Secret"

MAX_FILE_BYTES = 1_000_000  # skip files larger than ~1 MB
ENTROPY_THRESHOLD = 4.0     # Shannon-entropy cutoff for HS-GENERIC values

# ---------------------------------------------------------------------------
# High-confidence patterns: a match is a leak by shape alone, no entropy check.
# ---------------------------------------------------------------------------

HIGH_CONFIDENCE_RULES: list[dict[str, Any]] = [
    {
        "id": "HS-PRIVKEY",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        "label": "private key block",
    },
    {
        "id": "HS-AWS",
        "severity": "CRITICAL",
        # AKIA = long-term access key, ASIA = temporary STS credentials.
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "label": "AWS access key ID",
    },
    {
        "id": "HS-ALICLOUD",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\bLTAI[A-Za-z0-9]{12,30}\b"),
        "label": "Alibaba Cloud AccessKey ID",
    },
    {
        "id": "HS-GITHUB",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"
        ),
        "label": "GitHub token",
    },
    {
        "id": "HS-SLACK",
        "severity": "HIGH",
        "pattern": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "label": "Slack token",
    },
    {
        "id": "HS-GOOGLE",
        "severity": "HIGH",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "label": "Google API key",
    },
    {
        "id": "HS-JWT",
        "severity": "HIGH",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "label": "JSON Web Token",
    },
    {
        "id": "HS-ANTHROPIC",
        "severity": "HIGH",
        "pattern": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "label": "Anthropic API key",
    },
    {
        "id": "HS-OPENAI",
        "severity": "HIGH",
        # sk-proj-... and other sk- prefixed keys (incl. dotted variants
        # such as sk-ws- workspace keys).
        "pattern": re.compile(r"\bsk-[A-Za-z0-9_.\-]{20,}\b"),
        "label": "OpenAI-style API key (sk- prefix)",
    },
]

# Rule ids whose matches shadow others on the same span — e.g. an Anthropic
# key (sk-ant-) also matches the generic sk- rule; keep the specific one.
_SHADOWED: dict[str, str] = {"HS-OPENAI": "HS-ANTHROPIC"}

# ---------------------------------------------------------------------------
# Generic assignment rule: keyword + '=' / ':' + high-entropy value.
# ---------------------------------------------------------------------------

_GENERIC_ASSIGN = re.compile(
    r"(?ix)"
    r"(?P<key>[A-Za-z0-9_.-]*"
    r"(?:api[_-]?key|apikey|secret|passwd|password|token|access[_-]?key|"
    r"private[_-]?key|credential|auth[_-]?key|client[_-]?secret)"
    r"[A-Za-z0-9_.-]*)"
    r"\s*[:=]\s*"
    r"(?P<quote>[\"']?)"
    r"(?P<value>[A-Za-z0-9_+/=.\-]{16,128})"
)

# Values that are obviously placeholders / references, never real secrets.
_PLACEHOLDER_MARKERS = (
    "your", "xxx", "example", "sample", "dummy", "placeholder", "changeme",
    "change_me", "redacted", "todo", "fixme", "none", "null", "test",
)

_ENV_REFERENCE = re.compile(
    r"(?i)(?:\$\{?[A-Z0-9_]+\}?|\{\{[^}]+\}\}|%s|%v|<[a-z0-9_. -]+>)"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if _ENV_REFERENCE.search(value):
        return True
    # Repeated-char junk such as "aaaaaaaaaaaaaaaa".
    if len(set(lowered)) <= 2 and len(lowered) >= 8:
        return True
    return False


def redact_secret(value: str, keep: int = 6) -> str:
    """Mask a secret, keeping only a short prefix for identification."""
    value = value.strip()
    if len(value) <= keep:
        return value[:2] + "***"
    return value[:keep] + "***"


def redact_secrets_in_text(text: str) -> str:
    """Mask every high-confidence secret occurrence inside free text.

    Use this on any scanner/LLM free-text that may quote the source file
    (findings, explanations, filter reasons) so full secrets never reach a
    report or an LLM prompt.
    """
    if not text or not isinstance(text, str):
        return text
    for rule in HIGH_CONFIDENCE_RULES:
        text = rule["pattern"].sub(lambda m: redact_secret(m.group(0)), text)
    return text


def _redact_line(line: str, secret: str) -> str:
    if secret:
        return line.replace(secret, redact_secret(secret))
    return line


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _make_issue(
    rule_id: str,
    severity: str,
    label: str,
    rel_path: str,
    line_no: int,
    secret: str,
    line: str,
) -> dict[str, Any]:
    masked = redact_secret(secret) if secret else "(see pattern)"
    return {
        "id": rule_id,
        "severity": severity,
        "category": CATEGORY,
        "location": {"file": rel_path, "start_line": line_no},
        "finding": f"Hardcoded {label} detected ({masked}).",
        "explanation": (
            f"A value matching the shape of a {label} is committed in this "
            "file. Even if the key has been rotated, its presence in a skill "
            "repository means it may already be exposed."
        ),
        "remediation": (
            "Remove the credential from the file and its git history, rotate "
            "it immediately, and load it from an environment variable or "
            "secrets manager instead."
        ),
        "code_snippet": _redact_line(line.rstrip("\n")[:200], secret),
    }


def _scan_content(content: str, rel_path: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    lines = content.splitlines()

    def line_at(line_no: int) -> str:
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1]
        return ""

    # Track spans consumed by specific rules so the generic sk- fallback does
    # not double-report e.g. Anthropic keys.
    claimed: list[tuple[int, int, str]] = []  # (start, end, rule_id)

    for rule in HIGH_CONFIDENCE_RULES:
        for match in rule["pattern"].finditer(content):
            start, end = match.span()
            shadow = _SHADOWED.get(rule["id"])
            if shadow and any(
                rid == shadow and not (end <= cs or start >= ce)
                for cs, ce, rid in claimed
            ):
                continue
            line_no = _line_number(content, start)
            key = (line_no, match.start())
            if key in seen:
                continue
            seen.add(key)
            claimed.append((start, end, rule["id"]))
            issues.append(_make_issue(
                rule["id"], rule["severity"], rule["label"], rel_path,
                line_no, match.group(0), line_at(line_no),
            ))

    # Lines already flagged by a high-confidence rule do not need the
    # generic assignment rule on top (one finding per leaked line).
    claimed_lines = {_line_number(content, start) for start, _end, _rid in claimed}

    for match in _GENERIC_ASSIGN.finditer(content):
        value = match.group("value")
        if not value or _is_placeholder(value):
            continue
        if shannon_entropy(value) < ENTROPY_THRESHOLD:
            continue
        start = match.start("value")
        line_no = _line_number(content, start)
        if line_no in claimed_lines:
            continue
        key = (line_no, start)
        if key in seen:
            continue
        seen.add(key)
        issues.append(_make_issue(
            "HS-GENERIC", "HIGH", f"credential assignment ('{match.group('key')}')",
            rel_path, line_no, value, line_at(line_no),
        ))

    return issues


def scan_directory_for_secrets(scan_dir: str) -> list[dict[str, Any]]:
    """Scan every text file under ``scan_dir`` for hardcoded secrets.

    Returns SkillSpector-shaped issue dicts with paths relative to
    ``scan_dir`` (posix style), sorted by file then line.
    """
    root = Path(scan_dir).resolve()
    if not root.is_dir():
        return []

    issues: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            resolved = path.resolve()
            resolved.relative_to(root)  # skip symlinks escaping scan_dir
        except (ValueError, OSError):
            continue
        try:
            size = path.stat().st_size
            if size == 0 or size > MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if _is_binary(data):
            continue
        content = data.decode("utf-8", errors="ignore")
        rel_path = path.relative_to(root).as_posix()
        issues.extend(_scan_content(content, rel_path))

    issues.sort(key=lambda i: (i["location"]["file"], i["location"]["start_line"], i["id"]))
    return issues
