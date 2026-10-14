"""Generation-guarded bounded physical windows, parse state, then redaction."""

import hashlib
from dataclasses import dataclass

from .index import CHUNK_BYTES, GenerationIndex, ReadBudget, ReadFailure, ReadHandle, decode_line
from .parse import ParseState, parse_line
from .shared.mcpkit.errors import MAX_LINES, MAX_PHYSICAL_LINE_BYTES
from .shared.mcpkit.matcher import RedactedText
from .shared.mcpkit.models import LogLine
from .shared.mcpkit.redact import RedactionState, Redactor


@dataclass(frozen=True, slots=True)
class EvidenceLine:
    line: LogLine
    redacted: RedactedText


class VerifiedWindow:
    """No raw data escapes this per-call guard; every loaded chunk is hashed.

    At most two source chunks are retained, charged on every actual read. A call
    needing more source/index bytes fails before exceeding the shared read cap.
    """

    def __init__(self, handle: ReadHandle, index: GenerationIndex, budget: ReadBudget):
        index.assert_current(handle)
        self.handle, self.index, self.budget = handle, index, budget
        self._chunks: dict[int, bytes] = {}

    def __repr__(self) -> str:
        return "VerifiedWindow(<bounded generation guard>)"

    def _chunk(self, number: int) -> bytes:
        if number in self._chunks:
            self.budget.check()
            return self._chunks[number]
        self.index.assert_current(self.handle)
        start = number * CHUNK_BYTES
        size = min(CHUNK_BYTES, self.index.identity.size_bytes - start)
        if size <= 0:
            raise ReadFailure("INDEX_STALE")
        if size > self.budget.remaining:
            raise ReadFailure("LIMIT_EXCEEDED")
        self.handle.seek(start)
        raw = bytearray()
        while len(raw) < size:
            data = self.budget.read(self.handle, min(65536, size - len(raw)))
            if not data:
                raise ReadFailure("SOURCE_CHANGED")
            raw.extend(data)
        if hashlib.sha256(raw).hexdigest() != self.index.chunk_hashes[number]:
            raise ReadFailure("SOURCE_CHANGED")
        self.index.assert_current(self.handle)
        if len(self._chunks) >= 2:
            self._chunks.pop(next(iter(self._chunks)))
        self._chunks[number] = bytes(raw)
        return self._chunks[number]

    def physical(self, line_no: int) -> bytes | None:
        self.budget.check()
        if type(line_no) is not int or not 1 <= line_no <= self.index.total_lines:
            raise ReadFailure("INVALID_ARGUMENT")
        start, end = self.index.offsets[line_no - 1 : line_no + 1]
        if end - start > MAX_PHYSICAL_LINE_BYTES:
            return None
        pieces = []
        while start < end:
            number, offset = divmod(start, CHUNK_BYTES)
            block = self._chunk(number)
            count = min(len(block) - offset, end - start)
            if count <= 0:
                raise ReadFailure("INDEX_STALE")
            pieces.append(block[offset : offset + count])
            start += count
        return b"".join(pieces)

    def lines(
        self,
        start: int,
        end: int,
        redactor: Redactor,
        *,
        format: str = "auto",
        timezone: str = "UTC",
    ) -> list[EvidenceLine]:
        if (
            type(start) is not int
            or type(end) is not int
            or start < 1
            or end < start
            or end - start + 1 > MAX_LINES
        ):
            raise ReadFailure("INVALID_ARGUMENT")
        end = min(end, self.index.total_lines)
        if start > end:
            return []
        point = self.index.checkpoint(start)
        parse_state = point.parse
        redact_state = RedactionState(point.pem_active)
        result = []
        for number in range(point.line_no, end + 1):
            raw = self.physical(number)
            inherited_time = inherited_level = False
            if raw is None:
                parse_state = ParseState()
                redacted = redactor.omit_unread(redact_state)
            else:
                text = decode_line(raw, first=number == 1)
                parsed = parse_line(text, parse_state, format=format, timezone=timezone)
                parse_state = parsed.state
                inherited_time, inherited_level = parsed.timestamp_inherited, parsed.level_inherited
                redacted = redactor.redact(parsed.text, redact_state)
            redact_state = redacted.state
            self.budget.check()  # A deadline cannot publish a half-redacted line.
            if number >= start:
                line = LogLine(
                    line_no=number,
                    byte_offset=self.index.offsets[number - 1],
                    timestamp=parse_state.timestamp,
                    level=parse_state.level,
                    timestamp_inherited=inherited_time,
                    level_inherited=inherited_level,
                    text=redacted.text.value,
                    omitted=redacted.omitted,
                )
                result.append(EvidenceLine(line, redacted.text))
        self.index.assert_current(self.handle)
        return result

    def finish(self) -> None:
        self.budget.check()
        self.index.assert_current(self.handle)
