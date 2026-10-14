"""App request schemas and compatibility re-exports of canonical mcpkit models."""

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from .shared.mcpkit.errors import (
    AUTO_INDEX_BYTES,
    CALL_DEADLINE_SECONDS,
    MAX_ACTIVE_CALLS,
    MAX_CUSTOM_RULES,
    MAX_FRAME_BYTES,
    MAX_LINES,
    MAX_PATTERN_BYTES,
    MAX_PHYSICAL_LINE_BYTES,
    MAX_QUEUED_CALLS,
    MAX_READ_BYTES,
    MAX_SOURCES,
    BoundaryModel,
    ErrorCode,
    ToolError,
)
from .shared.mcpkit.models import (
    Coverage,
    ErrorGroup,
    Level,
    LogLine,
    Match,
    PositiveLine,
    SourceId,
    SourceInfo,
    ToolEnvelope,
    Truncation,
)

__all__ = [
    "AUTO_INDEX_BYTES",
    "CALL_DEADLINE_SECONDS",
    "MAX_ACTIVE_CALLS",
    "MAX_CUSTOM_RULES",
    "MAX_FRAME_BYTES",
    "MAX_LINES",
    "MAX_PATTERN_BYTES",
    "MAX_PHYSICAL_LINE_BYTES",
    "MAX_QUEUED_CALLS",
    "MAX_READ_BYTES",
    "MAX_SOURCES",
    "BoundaryModel",
    "ErrorCode",
    "ToolError",
    "Coverage",
    "ErrorGroup",
    "Level",
    "LogLine",
    "Match",
    "PositiveLine",
    "SourceId",
    "SourceInfo",
    "ToolEnvelope",
    "Truncation",
    "ListSourcesRequest",
    "SourceRequest",
    "SinceRequest",
    "TailRequest",
    "SearchRequest",
    "ReadRangeRequest",
    "ErrorsRequest",
    "REQUEST_MODELS",
    "validate_request",
]


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
