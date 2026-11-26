"""Log redaction. Rules: README.md, "What to build", part 2."""
from __future__ import annotations

import json
import re
from datetime import date

from .secrets import iter_secrets

# Egyptian national ID governorate codes, exactly as in README.md.
GOVERNORATES = {1, 2, 3, 4, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                31, 32, 33, 34, 35, 88}


SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token",
                  "api_key", "apikey", "authorization", "cookie"}
_ID_RE = re.compile(r"(?<![0-9])[23][0-9]{13}(?![0-9])")
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
_PHONE_RE = re.compile(r"(?<![0-9+])(?:\+20|0020|0)?1[0125][0-9]{8}(?![0-9])")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def is_national_id(s: str) -> bool:
    """14 ASCII digits; century digit 2 or 3; a real YYMMDD date in that century; a known governorate."""
    if not isinstance(s, str) or not re.fullmatch(r"[0-9]{14}", s):
        return False
    if s[0] not in "23":
        return False
    century = 1900 if s[0] == "2" else 2000
    try:
        date(century + int(s[1:3]), int(s[3:5]), int(s[5:7]))
    except ValueError:
        return False
    return int(s[7:9]) in GOVERNORATES


def redact_text(text: str) -> str:
    """Escape CR/LF, then redact secrets, bearer tokens, national ids, phone numbers and emails,
    in the exact order given in README.md."""
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    out, pos = [], 0
    for rule_id, start, end in iter_secrets(text):
        out.append(text[pos:start])
        out.append(f"[REDACTED:{rule_id}]")
        pos = end
    out.append(text[pos:])
    text = "".join(out)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED:bearer]", text)
    text = _ID_RE.sub(lambda m: "[REDACTED:national_id]" if is_national_id(m.group(0)) else m.group(0), text)
    text = _PHONE_RE.sub("[REDACTED:phone]", text)
    return _EMAIL_RE.sub("[REDACTED:email]", text)


def _walk(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_walk(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS and v is not None and v != "":
                out[k] = "[REDACTED:field]"
            else:
                out[k] = _walk(v)
        return out
    return value


def redact_line(line: str) -> str:
    """If the stripped line is a JSON object, redact it structurally; otherwise redact_text(line)."""
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except (ValueError, RecursionError):
            obj = None
        if isinstance(obj, dict):
            return json.dumps(_walk(obj), ensure_ascii=False)
    return redact_text(line)
