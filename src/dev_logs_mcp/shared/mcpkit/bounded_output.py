"""Render an already sanitized result within actual JSON-RPC wire/line ceilings.

No source access, redaction, source verification or cursor generation occurs here.
An optional trusted pure callback rebuilds whole evidence units and continuation.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel

from .errors import MAX_FRAME_BYTES, MAX_LINES, ErrorCode, ToolError
from .models import ToolEnvelope

MAX_SAFE_REQUEST_ID = 2**53 - 1
MAX_REQUEST_ID_BYTES = 256


class ProtocolBudgetError(ValueError):
    """The transport must reject/close without echoing an unbounded request ID."""


@dataclass(frozen=True)
class RenderedResponse:
    envelope: ToolEnvelope
    wire_bytes: bytes
    accepted_units: int
    truncated: bool


def _request_id_is_bounded(request_id: object) -> bool:
    if type(request_id) is int:
        return abs(request_id) <= MAX_SAFE_REQUEST_ID
    if type(request_id) is str:
        try:
            return len(request_id.encode("utf-8")) <= MAX_REQUEST_ID_BYTES
        except UnicodeEncodeError:
            return False
    return False


def _physical_lines(result: ToolEnvelope) -> int:
    numbers = {line.line_no for line in result.lines}
    numbers.update(match.line_no for match in result.matches)
    for group in result.groups:
        numbers.add(group.first_in_coverage.line_no)
        numbers.update(line.line_no for line in group.trace)
    return len(numbers)


def _units(result: ToolEnvelope) -> int:
    return max(_physical_lines(result), len(result.sources), len(result.groups))


def _strings_exceed_lower_bound(result: ToolEnvelope, bound: int) -> bool:
    """Avoid allocating a huge JSON dump that cannot possibly fit the frame.

    UTF8 and the mirrored JSON can only increase this character-count lower bound.
    The node ceiling also fails closed on accidentally cyclic/malformed Python data.
    """
    pending: list[object] = [result]
    characters = visited = 0
    while pending:
        value = pending.pop()
        visited += 1
        if visited > 10000:
            return True
        if isinstance(value, str):
            characters += len(value)
            if characters > bound:
                return True
        elif isinstance(value, BaseModel):
            pending.extend(getattr(value, name) for name in type(value).model_fields)
        elif isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list | tuple):
            pending.extend(value)
    return False


class OutputBudget:
    def __init__(self, max_lines: int = MAX_LINES, max_wire_bytes: int = MAX_FRAME_BYTES):
        if type(max_lines) is not int or not 1 <= max_lines <= MAX_LINES:
            raise ValueError("invalid line ceiling")
        if type(max_wire_bytes) is not int or not 1 <= max_wire_bytes <= MAX_FRAME_BYTES:
            raise ValueError("invalid wire ceiling")
        self.max_lines = max_lines
        self.max_wire_bytes = max_wire_bytes

    def _wire(self, result: ToolEnvelope, request_id: int | str) -> bytes | None:
        if _physical_lines(result) > self.max_lines:
            return None
        if _strings_exceed_lower_bound(result, self.max_wire_bytes):
            return None
        try:
            payload = result.model_dump(mode="json", exclude_none=True)
            text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            frame = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "structuredContent": payload,
                    "content": [{"type": "text", "text": text}],
                    "isError": not result.ok,
                },
            }
            wire = (
                json.dumps(
                    frame, ensure_ascii=False, separators=(",", ":"), allow_nan=False
                ).encode("utf-8")
                + b"\n"
            )
        except (ValueError, TypeError, UnicodeError):
            return None
        return wire if len(wire) <= self.max_wire_bytes else None

    def render(
        self,
        result: ToolEnvelope,
        request_id: int | str,
        shrink: Callable[[int], ToolEnvelope] | None = None,
    ) -> RenderedResponse:
        """Try complete prefixes with at most eleven pure-callback probes.

        A callback LIMIT_EXCEEDED with no units signals that its line allowance
        cannot hold one whole unit. Renderable prefixes still need a cursor or
        narrowing hint; the callback never receives source-access authority.
        """
        if not _request_id_is_bounded(request_id):
            raise ProtocolBudgetError("request ID violates bounded transport policy")
        if not isinstance(result, ToolEnvelope):
            raise TypeError("typed sanitized result required")
        wire = self._wire(result, request_id)
        if wire is not None:
            return RenderedResponse(result, wire, _units(result), False)

        line_overflow = _physical_lines(result) > self.max_lines
        byte_overflow = not line_overflow
        callback_failed = False
        if shrink is not None:
            # Fixed probe bound for the approved 500-unit ceiling.
            original_units = _units(result)
            maximum = min(self.max_lines, max(1, original_units))
            # The original full-unit result already failed its wire check. If
            # the line ceiling reduces that result, try its entire allowance
            # before halving; otherwise avoid an identical no-continuation page.
            limit = maximum if maximum < original_units else maximum // 2
            lower = 0
            upper = maximum if maximum < original_units else maximum - 1
            for _attempt in range(11):
                try:
                    candidate = shrink(limit)
                    if not isinstance(candidate, ToolEnvelope):
                        raise TypeError("typed callback result required")
                    candidate_units = _units(candidate)
                    if candidate_units > limit:
                        raise ValueError("callback exceeded whole-unit limit")
                    if not candidate.next_cursor and not candidate.hint:
                        raise ValueError("callback did not supply continuation or narrowing hint")
                    too_small = (
                        original_units > 0
                        and candidate_units == 0
                        and candidate.error is not None
                        and candidate.error.code == ErrorCode.LIMIT_EXCEEDED
                    )
                    data = candidate.model_dump()
                    data["truncation"]["output_lines"] |= line_overflow
                    data["truncation"]["output_bytes"] |= byte_overflow
                    candidate = ToolEnvelope.model_validate(data)
                    wire = None if too_small else self._wire(candidate, request_id)
                    if wire is None and not too_small and not byte_overflow:
                        # A line-limited candidate may also exceed the byte cap.
                        # Record both limits for subsequent smaller prefixes;
                        # changing a flag must not admit this oversized page.
                        byte_overflow = True
                except Exception:
                    callback_failed = True
                    break
                if wire is not None:
                    return RenderedResponse(candidate, wire, _units(candidate), True)
                # No complete unit fits below this limit, whereas a nonempty
                # oversized page needs fewer units. Refine between those bounds
                # instead of jumping over a fitting atomic context unit.
                if too_small:
                    lower = limit + 1
                else:
                    upper = limit - 1
                if lower > upper:
                    break
                limit = (lower + upper + 1) // 2

        error = ToolError(
            code=ErrorCode.INTERNAL_ERROR if callback_failed else ErrorCode.LIMIT_EXCEEDED,
            message="Result cannot be safely rendered within the configured limits",
            hint="Narrow the query or request fewer complete evidence units",
        )
        fallback = ToolEnvelope(ok=False, error=error, hint=error.hint)
        wire = self._wire(fallback, request_id)
        if wire is None:
            raise ProtocolBudgetError(
                "mandatory response metadata cannot fit configured wire budget"
            )
        return RenderedResponse(fallback, wire, 0, True)
