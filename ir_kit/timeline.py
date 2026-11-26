"""Incident timeline builder. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from .redact import redact_text


@dataclass(frozen=True)
class Event:
    ts: datetime      # timezone-aware, UTC
    source: str       # "wazuh" | "nginx" | "app"
    message: str      # already redacted


SOURCE_ORDER = {"wazuh": 0, "nginx": 1, "app": 2}
_NGINX_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)')
_WAZUH_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (.+)$")
_CAIRO = ZoneInfo("Africa/Cairo")


def _parse_nginx(line: str):
    m = _NGINX_RE.match(line)
    if not m:
        return None
    ip, when, request, status, _size = m.groups()
    ts = datetime.strptime(when, "%d/%b/%Y:%H:%M:%S %z")
    return ts, f'{ip} "{request}" {status}'


def _parse_app(line: str):
    obj = json.loads(line)
    if not isinstance(obj, dict):
        return None
    ts_raw, level, msg = obj.get("ts"), obj.get("level"), obj.get("msg")
    if not (isinstance(ts_raw, str) and isinstance(level, str) and isinstance(msg, str)):
        return None
    ts = datetime.fromisoformat(ts_raw)
    if ts.tzinfo is None or ts.utcoffset() is None:
        return None
    message = f"{level.upper()} {msg}"
    if obj.get("user") is not None:
        message += f" user={obj['user']}"
    if obj.get("doc_id") is not None:
        message += f" doc_id={obj['doc_id']}"
    return ts, message


def _parse_wazuh(line: str):
    m = _WAZUH_RE.match(line)
    if not m:
        return None
    naive = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    return naive.replace(tzinfo=_CAIRO, fold=0), m.group(2)


_PARSERS = {"nginx": _parse_nginx, "app": _parse_app, "wazuh": _parse_wazuh}


def build_timeline(sources: dict[str, str]) -> tuple[list[Event], list[str]]:
    """Parse each source's text, convert to UTC, redact, sort, dedupe. See README.md for the exact
    per-source formats, error reporting and ordering rules. An unknown source name raises ValueError."""
    for name in sources:
        if name not in _PARSERS:
            raise ValueError(f"unknown source: {name!r}")
    rows, errors = [], []
    for name, text in sources.items():
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                parsed = _PARSERS[name](line)
            except (ValueError, OverflowError, RecursionError):
                parsed = None
            if parsed is None:
                errors.append(f"{name}:{lineno}")
                continue
            ts, message = parsed
            rows.append((ts.astimezone(timezone.utc), SOURCE_ORDER[name], lineno, name, redact_text(message)))
    rows.sort(key=lambda r: (r[0], r[1], r[2]))
    events, seen = [], set()
    for ts, _order, _lineno, name, message in rows:
        key = (ts, name, message)
        if key in seen:
            continue
        seen.add(key)
        events.append(Event(ts=ts, source=name, message=message))
    return events, errors


def render_markdown(events: list[Event]) -> str:
    """A GitHub-flavoured markdown table: header, separator, one escaped row per event, final newline."""
    lines = ["| Time (UTC) | Source | Event |", "|---|---|---|"]
    for e in events:
        when = e.ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        lines.append(f"| {when} | {e.source} | {e.message.replace('|', chr(92) + '|')} |")
    return "\n".join(lines) + "\n"
