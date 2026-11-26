"""Log redaction. Rules: README.md, "What to build", part 2."""
from __future__ import annotations

# Egyptian national ID governorate codes, exactly as in README.md.
GOVERNORATES = {1, 2, 3, 4, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                31, 32, 33, 34, 35, 88}


def is_national_id(s: str) -> bool:
    """14 ASCII digits; century digit 2 or 3; a real YYMMDD date in that century; a known governorate."""
    raise NotImplementedError


def redact_text(text: str) -> str:
    """Escape CR/LF, then redact secrets, bearer tokens, national ids, phone numbers and emails,
    in the exact order given in README.md."""
    raise NotImplementedError


def redact_line(line: str) -> str:
    """If the stripped line is a JSON object, redact it structurally; otherwise redact_text(line)."""
    raise NotImplementedError
