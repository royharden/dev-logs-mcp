"""Version-one boundary schemas. Validation never opens log sources.

These schemas are shared-file owned. Path authorization, reads, redaction and
serialized frame enforcement are separate implementation gates.
"""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

MAX_SOURCES = 100
MAX_LINES = 500
MAX_FRAME_BYTES = 32 * 1024
MAX_READ_BYTES = 8 * 1024 * 1024
MAX_PHYSICAL_LINE_BYTES = 64 * 1024
AUTO_INDEX_BYTES = 6 * 1024 * 1024
MAX_PATTERN_BYTES = 512
MAX_CUSTOM_RULES = 32
CALL_DEADLINE_SECONDS = 5
MAX_ACTIVE_CALLS = 4
MAX_QUEUED_CALLS = 16

SourceId = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
]
PositiveLine = Annotated[int, Field(ge=1)]
Level = Literal["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "CRITICAL"]


class BoundaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ErrorCode(StrEnum):
    CONFIG_INVALID = "CONFIG_INVALID"
    UNKNOWN_SOURCE = "UNKNOWN_SOURCE"
    PATH_FORBIDDEN = "PATH_FORBIDDEN"
    SOURCE_NOT_LOCAL = "SOURCE_NOT_LOCAL"
    NOT_REGULAR_FILE = "NOT_REGULAR_FILE"
    SOURCE_MISSING = "SOURCE_MISSING"
    BINARY_CONTENT = "BINARY_CONTENT"
    UNSUPPORTED_ENCODING = "UNSUPPORTED_ENCODING"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_PATTERN = "INVALID_PATTERN"
    INDEX_REQUIRED = "INDEX_REQUIRED"
    INDEX_STALE = "INDEX_STALE"
    INDEX_INCOMPLETE = "INDEX_INCOMPLETE"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    INVALID_CURSOR = "INVALID_CURSOR"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    BUSY = "BUSY"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ListSourcesRequest(BoundaryModel):
    pass


class SourceRequest(BoundaryModel):
    source_id: SourceId


class SinceRequest(SourceRequest):
    since: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def valid_since(self):
        if self.since is not None:
            datetime.fromisoformat(self.since)
        return self


class TailRequest(SinceRequest):
    lines: int = Field(default=200, ge=1, le=MAX_LINES)


class SearchRequest(SinceRequest):
    pattern: str = Field(min_length=1, max_length=MAX_PATTERN_BYTES)
    max_matches: int = Field(default=100, ge=1, le=100)
    context: int = Field(default=2, ge=0, le=5)
    until: str | None = Field(default=None, max_length=64)
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)
    direction: Literal["newest_first", "oldest_first"] = "newest_first"

    @model_validator(mode="after")
    def valid_query(self):
        if len(self.pattern.encode("utf-8")) > MAX_PATTERN_BYTES:
            raise ValueError("pattern exceeds UTF-8 byte limit")
        if self.until is not None:
            datetime.fromisoformat(self.until)
        # Temporal ordering uses the configured source timezone in the query layer.
        return self


class ReadRangeRequest(SourceRequest):
    start_line: PositiveLine
    end_line: PositiveLine

    @model_validator(mode="after")
    def valid_range(self):
        if self.end_line < self.start_line:
            raise ValueError("end_line precedes start_line")
        if self.end_line - self.start_line + 1 > MAX_LINES:
            raise ValueError("range exceeds line limit")
        return self


class ErrorsRequest(SinceRequest):
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)


REQUEST_MODELS: dict[str, type[BoundaryModel]] = {
    "list_sources": ListSourcesRequest,
    "tail": TailRequest,
    "search": SearchRequest,
    "read_range": ReadRangeRequest,
    "errors": ErrorsRequest,
}


def validate_request(name: str, arguments: dict[str, object]) -> BoundaryModel:
    """Validate a known tool request without executing it or opening a source."""
    model = REQUEST_MODELS.get(name)
    if model is None:
        raise ValueError("unknown tool")
    return model.model_validate(arguments)


class ToolError(BoundaryModel):
    code: ErrorCode
    message: str = Field(max_length=256)
    hint: str = Field(max_length=256)
    retryable: bool = False


class LogLine(BoundaryModel):
    line_no: PositiveLine
    byte_offset: int = Field(ge=0)
    timestamp: str | None = Field(default=None, max_length=64)
    level: Level | None = None
    timestamp_inherited: bool = False
    level_inherited: bool = False
    text: str = Field(max_length=MAX_PHYSICAL_LINE_BYTES)
    context: bool = False
    omitted: Literal["overlong_line", "private_key"] | None = None


class Coverage(BoundaryModel):
    first_line: PositiveLine | None = None
    last_line: PositiveLine | None = None
    bytes_read: int = Field(default=0, ge=0, le=MAX_READ_BYTES)
    total_lines: int | None = Field(default=None, ge=0)
    complete: bool = False
    omitted_oversize_lines: int = Field(default=0, ge=0)
    excluded_untimestamped: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def consistent_lines(self):
        if (self.first_line is None) != (self.last_line is None):
            raise ValueError("coverage endpoints must both be present or absent")
        if self.first_line is not None and self.last_line < self.first_line:
            raise ValueError("coverage endpoints reversed")
        if self.total_lines is not None and self.last_line is not None:
            if self.last_line > self.total_lines:
                raise ValueError("coverage exceeds generation line count")
        return self


class Truncation(BoundaryModel):
    output_lines: bool = False
    output_bytes: bool = False
    input_window: bool = False
    oversize_line: bool = False


class Match(BoundaryModel):
    line_no: PositiveLine


class ErrorGroup(BoundaryModel):
    signature: str = Field(max_length=160)
    level: Level
    first_in_coverage: LogLine
    occurrence_count_in_coverage: int = Field(ge=1)
    trace: list[LogLine] = Field(default_factory=list, max_length=30)


class SourceInfo(BoundaryModel):
    id: SourceId
    display_path: str = Field(max_length=256)
    size: int | None = Field(default=None, ge=0)
    modified: str | None = Field(default=None, max_length=64)
    readable: bool
    problem: ErrorCode | None = None


class ToolEnvelope(BoundaryModel):
    schema_version: Literal[1] = 1
    ok: bool
    source_id: SourceId | None = None
    generation_id: str | None = Field(default=None, min_length=1, max_length=128)
    content_trust: Literal["untrusted_log_data"] = "untrusted_log_data"
    lines: list[LogLine] = Field(default_factory=list, max_length=MAX_LINES)
    matches: list[Match] = Field(default_factory=list, max_length=100)
    groups: list[ErrorGroup] = Field(default_factory=list, max_length=100)
    sources: list[SourceInfo] = Field(default_factory=list, max_length=MAX_SOURCES)
    coverage: Coverage = Field(default_factory=Coverage)
    truncation: Truncation = Field(default_factory=Truncation)
    next_cursor: str | None = Field(default=None, min_length=1, max_length=4096)
    warnings: list[str] = Field(default_factory=list, max_length=16)
    hint: str = Field(default="", max_length=256)
    error: ToolError | None = None

    @model_validator(mode="after")
    def consistent_status(self):
        if self.ok == (self.error is not None):
            raise ValueError("ok and error disagree")
        if not self.ok and (self.lines or self.matches or self.groups or self.sources):
            raise ValueError("failed call cannot return successful evidence")
        if self.lines or self.matches or self.groups:
            if not self.source_id or not self.generation_id:
                raise ValueError("evidence requires source and generation")
        return self
