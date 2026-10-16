"""Five-tool deterministic query engine; the stdio adapter is a separate boundary."""

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime

from .config import ToolLimits
from .contracts import (
    AUTO_INDEX_BYTES,
    ErrorsRequest,
    ReadRangeRequest,
    SearchRequest,
    TailRequest,
    validate_request,
)
from .index import (
    MAX_SOURCE_BYTES,
    GenerationIndex,
    PrivateIndexCache,
    ReadBudget,
    ReadFailure,
    prepare_index,
)
from .parse import normalize_time, source_timezone
from .reader import EvidenceLine, VerifiedWindow
from .shared.mcpkit.bounded_output import OutputBudget, RenderedResponse
from .shared.mcpkit.errors import MAX_LINES, MAX_READ_BYTES, ErrorCode, ToolError
from .shared.mcpkit.matcher import Matcher, PatternError
from .shared.mcpkit.models import Coverage, ErrorGroup, Match, ToolEnvelope, Truncation
from .shared.mcpkit.redact import Redactor
from .shared.mcpkit.safe_path import PathPolicyError
from .sources import SourceCatalog

EXPLICIT_PREPARE_SECONDS = 120.0


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class Cursors:
    def __init__(self, key: bytes | None = None):
        if key is not None and (type(key) is not bytes or len(key) != 32):
            raise ValueError("invalid cursor key")
        self.__key = secrets.token_bytes(32) if key is None else key

    def encode(self, binding: dict, line_no: int) -> str:
        raw = _canonical({"binding": binding, "line": line_no})
        signature = hmac.digest(self.__key, raw, "sha256")
        return base64.urlsafe_b64encode(signature + raw).decode().rstrip("=")

    def decode(self, token: str, binding: dict, total_lines: int) -> int:
        try:
            if type(token) is not str or not 1 <= len(token) <= 4096:
                raise ValueError
            raw = base64.b64decode(token + "=" * ((-len(token)) % 4), altchars=b"-_", validate=True)
            if base64.urlsafe_b64encode(raw).decode().rstrip("=") != token or len(raw) < 33:
                raise ValueError
            signature, body = raw[:32], raw[32:]
            if not hmac.compare_digest(signature, hmac.digest(self.__key, body, "sha256")):
                raise ValueError
            payload = json.loads(body)
            if set(payload) != {"binding", "line"} or payload["binding"] != binding:
                raise ValueError
            line = payload["line"]
            if type(line) is not int or not 1 <= line <= total_lines:
                raise ValueError
            return line
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ReadFailure("INVALID_CURSOR") from None


def _failure(code: str, budget: ReadBudget | None = None) -> ToolEnvelope:
    try:
        kind = ErrorCode(code)
    except ValueError:
        kind = ErrorCode.INTERNAL_ERROR
    hint = {
        ErrorCode.INDEX_REQUIRED: "Explicitly prepare this stable large source with index-source.",
        ErrorCode.INDEX_STALE: "Prepare the changed generation again; old cursors are invalid.",
        ErrorCode.INDEX_INCOMPLETE: "Explicitly prepare a stable source before querying.",
        ErrorCode.SOURCE_NOT_LOCAL: "Required platform safety is unavailable for this source.",
        ErrorCode.INVALID_CURSOR: "Start a new query with this process and current generation.",
        ErrorCode.LIMIT_EXCEEDED: "Narrow the range or prepare the source; units did not fit.",
    }.get(kind, "Check the configured source and bounded tool arguments.")
    return ToolEnvelope(
        ok=False,
        error=ToolError(
            code=kind, message="The bounded log operation could not complete", hint=hint
        ),
        hint=hint,
        coverage=Coverage(bytes_read=min(MAX_READ_BYTES, budget.bytes_read) if budget else 0),
    )


@dataclass(frozen=True)
class QueryResult:
    envelope: ToolEnvelope
    shrink: Callable[[int], ToolEnvelope] | None = None
    limits: ToolLimits | None = None

    def render(self, request_id: int | str, budget: OutputBudget | None = None) -> RenderedResponse:
        selected = budget or OutputBudget()
        if self.limits is not None:
            selected = OutputBudget(
                max_lines=min(selected.max_lines, self.limits.lines),
                max_wire_bytes=min(selected.max_wire_bytes, self.limits.frame_bytes),
            )
        return selected.render(self.envelope, request_id, self.shrink)


@dataclass(frozen=True)
class _Unit:
    anchor: EvidenceLine
    evidence: tuple[EvidenceLine, ...]


def _signature(line: EvidenceLine) -> str:
    value = re.sub(r"\[[A-Z_]+:\d+:[0-9a-f]{4}\]", "[REDACTED]", line.line.text)
    value = re.sub(
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?\b",
        "[TIME]",
        value,
    )
    value = re.sub(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b", "[ID]", value)
    value = re.sub(r"\b(?:[0-9a-fA-F]{8,}|\d+)\b", "#", value)
    return " ".join(value.split())[:160]


class LogEngine:
    def __init__(
        self,
        catalog: SourceCatalog,
        *,
        redactor: Redactor | None = None,
        cache: PrivateIndexCache | None = None,
    ):
        self.catalog = catalog
        self.tool_limits = catalog.tool_limits
        self.redactor = redactor or Redactor(custom_rules=getattr(catalog, "custom_rules", ()))
        self.cache = cache
        self.cursors = Cursors()
        self._indexes: dict[str, GenerationIndex] = {}

    def prepare(self, source_id: str) -> GenerationIndex:
        """Explicit full-source preparation, <=2 fresh handles, no append reuse.

        This is CLI preflight, never a hidden large-file tool operation. Both
        attempts share one 120-second/full-source-byte preflight budget. This
        explicit operation is separate from five-second MCP calls and their
        bounded small-file auto-indexing; no request invokes this preflight.
        """
        source = self.catalog.get(source_id)
        budget = ReadBudget(MAX_SOURCE_BYTES, seconds=EXPLICIT_PREPARE_SECONDS)
        for attempt in range(2):
            try:
                with self.catalog.open(source_id) as handle:
                    index = prepare_index(
                        handle,
                        source_id,
                        self.catalog.config_hash,
                        self.redactor,
                        budget,
                        format=source.format,
                        timezone=source.timezone,
                    )
                    index.assert_current(handle)
                    if self.cache:
                        self.cache.save(index)
                    self._indexes[source_id] = index
                    return index
            except (ReadFailure, PathPolicyError) as failure:
                if failure.code != "SOURCE_CHANGED" or attempt == 1:
                    raise
        raise ReadFailure("SOURCE_CHANGED")

    def _index(self, source, handle, budget):
        index = self._indexes.get(source.id)
        if index is None and self.cache is not None:
            index = self.cache.load(source.id, self.catalog.config_hash, budget)
        changed = False
        if index is not None:
            try:
                index.assert_current(handle)
            except ReadFailure:
                self._indexes.pop(source.id, None)
                changed = True
                index = None
        if index is None:
            if handle.metadata().size_bytes > AUTO_INDEX_BYTES:
                raise ReadFailure("INDEX_STALE" if changed else "INDEX_REQUIRED")
            index = prepare_index(
                handle,
                source.id,
                self.catalog.config_hash,
                self.redactor,
                budget,
                format=source.format,
                timezone=source.timezone,
            )
            self._indexes[source.id] = index
        return index

    def call(
        self, tool: str, arguments: dict[str, object], *, budget: ReadBudget | None = None
    ) -> QueryResult:
        limits = self.tool_limits
        budget = budget or ReadBudget(limits.read_bytes, seconds=limits.seconds)
        if budget.max_bytes > limits.read_bytes:
            raise ValueError("tool calls cannot raise the configured read ceiling")
        # An injected budget may tighten, never extend the same queue+call origin.
        budget.deadline = min(budget.deadline, budget.started_at + limits.seconds)
        return replace(self._call(tool, arguments, budget), limits=limits)

    def _call(self, tool: str, arguments: dict[str, object], budget: ReadBudget) -> QueryResult:
        try:
            request = validate_request(tool, arguments)
            budget.check()
            if tool == "list_sources":
                infos = self.catalog.infos(self.redactor, budget)
                envelope = ToolEnvelope(
                    ok=True,
                    sources=infos,
                    coverage=Coverage(complete=True, bytes_read=budget.bytes_read),
                )

                def shrink_catalog(limit):
                    return envelope.model_copy(
                        update={
                            "sources": infos[:limit],
                            "hint": "Shorten source display metadata to see the complete catalog.",
                        }
                    )

                return QueryResult(envelope, shrink_catalog)
            source = self.catalog.get(request.source_id)
            with self.catalog.open(source.id) as handle:
                index = self._index(source, handle, budget)
                window = VerifiedWindow(handle, index, budget)
                if isinstance(request, ReadRangeRequest):
                    evidence = window.lines(
                        request.start_line,
                        request.end_line,
                        self.redactor,
                        format=source.format,
                        timezone=source.timezone,
                    )
                    window.finish()
                    result = self._range(
                        index, evidence, budget, requested_start=request.start_line
                    )
                elif isinstance(request, TailRequest):
                    result = self._tail(source, index, window, request, budget)
                else:
                    result = self._scan(tool, source, index, window, request, budget)
                # A scan may stop at its cooperative deadline after complete
                # redacted units. Recheck generation without erasing that partial
                # result by applying the already-expired scan deadline again.
                index.assert_current(handle)
                return result
        except PatternError:
            return QueryResult(_failure("INVALID_PATTERN", budget))
        except (ReadFailure, PathPolicyError) as failure:
            return QueryResult(_failure(failure.code, budget))
        except (ValueError, TypeError, KeyError, OverflowError):
            # Validation exceptions may embed configured paths/patterns: never echo.
            return QueryResult(_failure("INVALID_ARGUMENT", budget))
        except Exception:
            return QueryResult(_failure("INTERNAL_ERROR", budget))

    @staticmethod
    def _coverage(index, rows, budget, *, complete=True, orphaned=0):
        numbers = [item.line.line_no for item in rows]
        return Coverage(
            first_line=min(numbers) if numbers else None,
            last_line=max(numbers) if numbers else None,
            total_lines=index.total_lines,
            bytes_read=budget.bytes_read,
            complete=complete,
            omitted_oversize_lines=sum(item.line.omitted == "overlong_line" for item in rows),
            excluded_untimestamped=orphaned,
        )

    def _range(self, index, rows, budget, *, requested_start):
        coverage = self._coverage(index, rows, budget)
        envelope = ToolEnvelope(
            ok=True,
            source_id=index.source_id,
            generation_id=index.generation_id,
            lines=[item.line for item in rows],
            coverage=coverage,
            truncation=Truncation(oversize_line=coverage.omitted_oversize_lines > 0),
        )

        def shrink(limit):
            if limit == 0 and rows:
                return _failure("LIMIT_EXCEEDED", budget)
            accepted = rows[:limit]
            next_line = accepted[-1].line.line_no + 1 if accepted else requested_start
            return envelope.model_copy(
                update={
                    "lines": [item.line for item in accepted],
                    "hint": f"Continue read_range at physical line {next_line}.",
                }
            )

        return QueryResult(envelope, shrink)

    @staticmethod
    def _time_bounds(request, source):
        zone = source_timezone(source.timezone)
        since = (
            datetime.fromisoformat(normalize_time(request.since, zone)) if request.since else None
        )
        until_raw = getattr(request, "until", None)
        until = datetime.fromisoformat(normalize_time(until_raw, zone)) if until_raw else None
        if since is not None and until is not None and since >= until:
            raise ReadFailure("INVALID_ARGUMENT")
        return since, until

    @staticmethod
    def _eligible(row, since, until):
        stamp = row.line.timestamp
        if since is None and until is None:
            return True
        if stamp is None:
            return False
        moment = datetime.fromisoformat(stamp)
        return (since is None or moment >= since) and (until is None or moment < until)

    def _tail(self, source, index, window, request, budget):
        since, until = self._time_bounds(request, source)
        rows = window.lines(
            max(1, index.total_lines - request.lines + 1),
            max(1, index.total_lines),
            self.redactor,
            format=source.format,
            timezone=source.timezone,
        )
        accepted = [row for row in rows if self._eligible(row, since, until)]
        coverage = self._coverage(
            index,
            rows,
            budget,
            orphaned=sum(row.line.timestamp is None for row in rows) if since else 0,
        )
        result = self._range(index, accepted, budget, requested_start=1)
        envelope = result.envelope.model_copy(update={"coverage": coverage})

        def shrink(limit):
            if limit == 0 and accepted:
                return _failure("LIMIT_EXCEEDED", budget)
            return envelope.model_copy(
                update={
                    "lines": [row.line for row in accepted[-limit:]] if limit else [],
                    "hint": "Use read_range for earlier lines omitted by the response cap.",
                }
            )

        return QueryResult(envelope, shrink)

    def _scan(self, tool, source, index, window, request, budget):
        if not isinstance(request, SearchRequest | ErrorsRequest):
            raise ReadFailure("INVALID_ARGUMENT")
        query = request.model_dump(exclude={"cursor"})
        binding = {
            "source": source.id,
            "generation": index.generation_id,
            "config": index.config_hash,
            "query": hashlib.sha256(_canonical([tool, query])).hexdigest(),
        }
        descending = getattr(request, "direction", "newest_first") == "newest_first"
        step = -1 if descending else 1
        position = index.total_lines if descending else 1
        if request.cursor:
            position = self.cursors.decode(request.cursor, binding, index.total_lines)
        matcher = Matcher(request.pattern) if isinstance(request, SearchRequest) else None
        since, until = self._time_bounds(request, source)
        units = []
        returned_numbers = set()
        scanned_first = scanned_last = None
        orphaned = oversized = 0
        output_limited = False
        budget_limited = False
        max_matches = request.max_matches if isinstance(request, SearchRequest) else 100
        while 1 <= position <= index.total_lines:
            try:
                first = max(1, position - 255) if descending else position
                last = position if descending else min(index.total_lines, position + 255)
                block = window.lines(
                    first, last, self.redactor, format=source.format, timezone=source.timezone
                )
                if descending:
                    block.reverse()
                for row in block:
                    budget.check()
                    number = row.line.line_no
                    scanned_first = number if scanned_first is None else min(scanned_first, number)
                    scanned_last = number if scanned_last is None else max(scanned_last, number)
                    orphaned += int(
                        (since is not None or until is not None) and row.line.timestamp is None
                    )
                    oversized += int(row.line.omitted == "overlong_line")
                    eligible = self._eligible(row, since, until)
                    matched = (
                        matcher.search(row.redacted)
                        if matcher and eligible
                        else (
                            matcher is None
                            and eligible
                            and row.line.level in {"WARN", "ERROR", "FATAL", "CRITICAL"}
                            and not row.line.level_inherited
                            and row.line.omitted is None
                        )
                    )
                    if matched:
                        context = request.context if isinstance(request, SearchRequest) else 0
                        end = min(index.total_lines, number + context)
                        begin = max(1, number - context)
                        evidence = window.lines(
                            begin,
                            end,
                            self.redactor,
                            format=source.format,
                            timezone=source.timezone,
                        )
                        if matcher is None:
                            # A trace is bounded physical continuation, not new occurrences.
                            trace_end = min(index.total_lines, number + 29)
                            if trace_end > number:
                                following = window.lines(
                                    number + 1,
                                    trace_end,
                                    self.redactor,
                                    format=source.format,
                                    timezone=source.timezone,
                                )
                                for frame in following:
                                    if (
                                        not frame.line.level_inherited
                                        and not frame.line.timestamp_inherited
                                    ):
                                        break
                                    evidence.append(frame)
                        numbers = {item.line.line_no for item in evidence}
                        if len(returned_numbers | numbers) > MAX_LINES:
                            output_limited = True
                            position = number
                            break
                        units.append(_Unit(row, tuple(evidence)))
                        returned_numbers.update(numbers)
                    position = number + step
                    if len(units) >= max_matches:
                        output_limited = True
                        break
                else:
                    continue
                break
            except ReadFailure as failure:
                if failure.code != "LIMIT_EXCEEDED":
                    raise
                if scanned_first is None:
                    raise
                budget_limited = True
                break
        next_line = position if 1 <= position <= index.total_lines else None
        complete = next_line is None
        coverage = Coverage(
            first_line=scanned_first,
            last_line=scanned_last,
            bytes_read=budget.bytes_read,
            total_lines=index.total_lines,
            complete=complete,
            omitted_oversize_lines=oversized,
            excluded_untimestamped=orphaned,
        )

        def assemble(selected, next_position, *, shortened=False):
            rows = {item.line.line_no: item.line for unit in selected for item in unit.evidence}
            anchor_numbers = {unit.anchor.line.line_no for unit in selected}
            matches = [Match(line_no=value) for value in sorted(anchor_numbers)] if matcher else []
            groups = {}
            if matcher is None:
                for unit in selected:
                    signature = _signature(unit.anchor)
                    key = (unit.anchor.line.level, signature)
                    if key not in groups:
                        groups[key] = ErrorGroup(
                            signature=signature,
                            level=unit.anchor.line.level,
                            first_in_coverage=unit.anchor.line,
                            occurrence_count_in_coverage=1,
                            trace=[item.line for item in unit.evidence[1:]],
                        )
                    else:
                        old = groups[key]
                        groups[key] = old.model_copy(
                            update={
                                "occurrence_count_in_coverage": old.occurrence_count_in_coverage + 1
                            }
                        )
                        if unit.anchor.line.line_no < old.first_in_coverage.line_no:
                            groups[key] = groups[key].model_copy(
                                update={
                                    "first_in_coverage": unit.anchor.line,
                                    "trace": [item.line for item in unit.evidence[1:]],
                                }
                            )
            return ToolEnvelope(
                ok=True,
                source_id=source.id,
                generation_id=index.generation_id,
                lines=[
                    rows[number].model_copy(update={"context": number not in anchor_numbers})
                    for number in sorted(rows)
                ]
                if matcher
                else [],
                matches=matches,
                groups=sorted(groups.values(), key=lambda group: group.first_in_coverage.line_no),
                coverage=coverage,
                next_cursor=self.cursors.encode(binding, next_position) if next_position else None,
                truncation=Truncation(
                    output_lines=shortened or (output_limited and not complete),
                    input_window=budget_limited and not complete,
                    oversize_line=oversized > 0,
                ),
                hint="Continue with the same query and next_cursor." if next_position else "",
            )

        envelope = assemble(units, next_line)

        def shrink(limit):
            selected = []
            numbers = set()
            for unit in units:
                candidate = numbers | {item.line.line_no for item in unit.evidence}
                if len(candidate) > limit:
                    break
                selected.append(unit)
                numbers = candidate
            if not selected and units:
                return _failure("LIMIT_EXCEEDED", budget)
            resume = (
                units[len(selected)].anchor.line.line_no
                if len(selected) < len(units)
                else next_line
            )
            return assemble(selected, resume, shortened=len(selected) < len(units))

        return QueryResult(envelope, shrink)
