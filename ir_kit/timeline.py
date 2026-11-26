"""Incident timeline builder. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Event:
    ts: datetime      # timezone-aware, UTC
    source: str       # "wazuh" | "nginx" | "app"
    message: str      # already redacted


def build_timeline(sources: dict[str, str]) -> tuple[list[Event], list[str]]:
    """Parse each source's text, convert to UTC, redact, sort, dedupe. See README.md for the exact
    per-source formats, error reporting and ordering rules. An unknown source name raises ValueError."""
    raise NotImplementedError


def render_markdown(events: list[Event]) -> str:
    """A GitHub-flavoured markdown table: header, separator, one escaped row per event, final newline."""
    raise NotImplementedError
