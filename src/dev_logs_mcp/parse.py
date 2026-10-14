"""Bounded format metadata extraction; raw input stays in the redaction pipeline.

State contains only canonical timestamps and a finite level. No temporal ordering
is assumed. This module is not source authorization or secret redaction.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .shared.mcpkit.errors import MAX_PHYSICAL_LINE_BYTES
from .shared.mcpkit.models import Level

_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)")
_LEVEL = re.compile(r"^\s*(?:\[)?(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|ERR|FATAL|CRITICAL)\b", re.I)
_LEVELS = {name: name for name in ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "CRITICAL")}
_LEVELS.update(WARNING="WARN", ERR="ERROR")
_PINO = {10: "TRACE", 20: "DEBUG", 30: "INFO", 40: "WARN", 50: "ERROR", 60: "FATAL"}


def source_timezone(name: str) -> tzinfo:
    if name == "UTC":
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        raise ValueError("configured timezone is unavailable") from None


def normalize_time(value: str, zone: tzinfo = UTC) -> str:
    if type(value) is not str or not 1 <= len(value) <= 64:
        raise ValueError("invalid timestamp")
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=zone)
        return stamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        raise ValueError("invalid timestamp") from None


@dataclass(frozen=True, slots=True)
class ParseState:
    timestamp: str | None = None
    level: Level | None = None


@dataclass(frozen=True, slots=True)
class ParsedLine:
    text: str = field(repr=False)
    state: ParseState
    timestamp_inherited: bool = False
    level_inherited: bool = False
    fallback: bool = False


def _level(value: object) -> Level | None:
    if type(value) is int:
        return _PINO.get(value)
    if type(value) is str and len(value) <= 16:
        return _LEVELS.get(value.upper())
    return None


def _first(record: dict, keys: tuple[str, ...]) -> object:
    for key in keys:
        if key in record:
            return record[key]
    return None


def parse_line(
    text: str, state: ParseState | None = None, *, format: str = "auto", timezone: str = "UTC"
) -> ParsedLine:
    """Extract finite metadata; caller redacts the full returned physical text.

    JSON messages are deliberately not unwrapped: exact physical evidence includes
    all fields, and redaction must see contextual keys and nested values. Invalid
    JSON, invalid dates and unknown levels are explicit metadata fallback.
    """
    state = ParseState() if state is None else state
    if (
        type(text) is not str
        or len(text) > MAX_PHYSICAL_LINE_BYTES
        or len(text.encode("utf-8")) > MAX_PHYSICAL_LINE_BYTES
        or format not in {"auto", "plain_iso", "jsonl", "plain"}
        or not isinstance(state, ParseState)
    ):
        raise ValueError("bounded supported parser input required")
    zone = source_timezone(timezone)
    timestamp = level = None
    header = fallback = False
    if format in {"auto", "jsonl"} and (format == "jsonl" or text.lstrip().startswith("{")):
        try:
            record = json.loads(text)
            if not isinstance(record, dict):
                raise ValueError
            raw_stamp = _first(record, ("timestamp", "time", "ts", "@timestamp"))
            if raw_stamp is not None:
                timestamp = normalize_time(raw_stamp, zone)
            raw_level = _first(record, ("level", "severity", "log_level"))
            level = _level(raw_level)
            # A JSON object is its own record, never an inherited stack frame.
            header = True
            fallback = (timestamp is None and level is None) or (
                raw_level is not None and level is None
            )
        except (ValueError, TypeError, RecursionError, OverflowError):
            fallback = True
    elif format in {"auto", "plain_iso"}:
        match = _ISO.match(text)
        if match:
            try:
                timestamp = normalize_time(match[1], zone)
                header = True
                severity = _LEVEL.match(text[match.end() :])
                level = _level(severity[1]) if severity else None
            except ValueError:
                fallback = True
        elif format == "plain_iso":
            fallback = True
    if header:
        return ParsedLine(text, ParseState(timestamp, level), fallback=fallback)
    return ParsedLine(
        text,
        state,
        timestamp_inherited=state.timestamp is not None,
        level_inherited=state.level is not None,
        fallback=fallback or format == "plain",
    )
