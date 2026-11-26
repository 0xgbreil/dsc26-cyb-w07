"""Secrets scanner. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ALLOW_MARKER = "dsc:allow-secret"

# Provider rule ids and patterns, exactly as in README.md. (Implement with these, do not invent more.)
RULE_IDS = ("private_key", "aws_access_key_id", "github_token", "slack_token", "generic_secret")
PLACEHOLDERS = {"changeme", "password", "example", "redacted", "xxxxxxxx", "secret", "your_token_here"}

_PROVIDER_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
)
_GENERIC = re.compile(
    r"(?i)([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api_key|apikey|token))"
    r"[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{8,})"
)
MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    path: str
    line: int        # 1-based
    column: int       # 1-based, where the secret starts
    masked: str       # never the full secret


def entropy(s: str) -> float:
    """Shannon entropy of `s`, in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return (
        low in PLACEHOLDERS
        or "example" in low
        or low.startswith(("${", "<", "{{", "[redacted"))
        or all(ch in "x*" for ch in low)
    )


def iter_secrets(line: str) -> list[tuple[str, int, int]]:
    """Yield (rule_id, start, end), 0-based, end exclusive, for each non-overlapping secret span."""
    cands: list[tuple[str, int, int]] = []
    for rule_id, rx in _PROVIDER_PATTERNS:
        for m in rx.finditer(line):
            if "EXAMPLE" in m.group(0):
                continue
            cands.append((rule_id, m.start(), m.end()))
    for m in _GENERIC.finditer(line):
        value = m.group(2)
        if entropy(value) < 3.0 or _is_placeholder(value):
            continue
        cands.append(("generic_secret", m.start(2), m.end(2)))
    cands.sort(key=lambda c: (c[1], -(c[2] - c[1])))   # stable: ties keep provider-rule order
    kept: list[tuple[str, int, int]] = []
    last_end = 0
    for c in cands:
        if c[1] >= last_end:
            kept.append(c)
            last_end = c[2]
    return kept


def _mask(secret: str) -> str:
    return secret[:4] + "****" if len(secret) > 8 else "****"


def scan_text(text: str, path: str) -> list[SecretFinding]:
    """Scan `text` line by line (skipping lines containing ALLOW_MARKER) and return findings."""
    findings: list[SecretFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for rule_id, start, end in iter_secrets(line):
            findings.append(SecretFinding(rule_id, path, lineno, start + 1, _mask(line[start:end])))
    return findings


def scan_tree(root) -> list[SecretFinding]:
    """Scan every regular file under `root` (see README.md for what to skip), sorted by path/line/column."""
    root = Path(root)
    findings: list[SecretFinding] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            full = Path(dirpath) / name
            try:
                if full.is_symlink() or not full.is_file():
                    continue
                if full.stat().st_size > MAX_FILE_BYTES:
                    continue
                data = full.read_bytes()
            except OSError:
                continue
            if len(data) > MAX_FILE_BYTES or b"\x00" in data[:1024]:
                continue
            rel = full.relative_to(root).as_posix()
            findings.extend(scan_text(data.decode("utf-8", errors="replace"), rel))
    findings.sort(key=lambda f: (f.path, f.line, f.column))
    return findings
