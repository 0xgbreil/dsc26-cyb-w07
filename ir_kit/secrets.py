"""Secrets scanner. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

from dataclasses import dataclass

ALLOW_MARKER = "dsc:allow-secret"

# Provider rule ids and patterns, exactly as in README.md. (Implement with these, do not invent more.)
RULE_IDS = ("private_key", "aws_access_key_id", "github_token", "slack_token", "generic_secret")
PLACEHOLDERS = {"changeme", "password", "example", "redacted", "xxxxxxxx", "secret", "your_token_here"}


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    path: str
    line: int        # 1-based
    column: int       # 1-based, where the secret starts
    masked: str       # never the full secret


def entropy(s: str) -> float:
    """Shannon entropy of `s`, in bits per character."""
    raise NotImplementedError


def iter_secrets(line: str) -> list[tuple[str, int, int]]:
    """Yield (rule_id, start, end), 0-based, end exclusive, for each non-overlapping secret span."""
    raise NotImplementedError


def scan_text(text: str, path: str) -> list[SecretFinding]:
    """Scan `text` line by line (skipping lines containing ALLOW_MARKER) and return findings."""
    raise NotImplementedError


def scan_tree(root) -> list[SecretFinding]:
    """Scan every regular file under `root` (see README.md for what to skip), sorted by path/line/column."""
    raise NotImplementedError
