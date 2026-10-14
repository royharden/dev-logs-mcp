"""Reusable version-one structured log evidence models, not a generic Pointer."""

from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from .errors import (
    MAX_LINES,
    MAX_PHYSICAL_LINE_BYTES,
    MAX_READ_BYTES,
    MAX_SOURCES,
    BoundaryModel,
    ErrorCode,
    ToolError,
)

SourceId = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
]
PositiveLine = Annotated[int, Field(ge=1)]
Level = Literal["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "CRITICAL"]


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
