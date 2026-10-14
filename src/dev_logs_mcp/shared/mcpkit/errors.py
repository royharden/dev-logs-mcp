"""Shared strict boundary/error models and default ceilings; no app imports."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

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


class ToolError(BoundaryModel):
    code: ErrorCode
    message: str = Field(max_length=256)
    hint: str = Field(max_length=256)
    retryable: bool = False
