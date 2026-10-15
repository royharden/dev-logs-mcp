"""Strict portable case wires; no SDK, application or filesystem imports."""

import json
from typing import Annotated, Literal

from pydantic import Field, JsonValue, StringConstraints, model_validator

from ..bounded_output import _request_id_is_bounded
from ..errors import MAX_FRAME_BYTES, MAX_READ_BYTES, BoundaryModel

Identifier = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
]


class Case(BoundaryModel):
    case_id: Identifier
    what_bug_this_catches: str = Field(min_length=1, max_length=512)
    tool: Identifier
    arguments: dict[str, JsonValue] = Field(default_factory=dict, repr=False)
    expect_error: str | None = Field(default=None, max_length=64)
    expect_protocol_error: int | None = None
    platforms: tuple[Literal["nt", "posix"], ...] = ("nt", "posix")
    required_capability: Identifier | None = None
    require_native: bool = False
    require_captured_wire: bool = False
    require_measured_reads: bool = False
    forbidden_literals: tuple[str, ...] = Field(default=(), max_length=32, repr=False)
    max_frame_bytes: int = Field(default=MAX_FRAME_BYTES, ge=256, le=MAX_FRAME_BYTES)
    max_read_bytes: int = Field(default=MAX_READ_BYTES, ge=1, le=MAX_READ_BYTES)
    timeout_seconds: float = Field(default=5.0, gt=0, le=5.0)

    @model_validator(mode="after")
    def bounded_case(self):
        if not self.platforms or len(set(self.platforms)) != len(self.platforms):
            raise ValueError("distinct applicable platforms required")
        if self.expect_error is not None and self.expect_protocol_error is not None:
            raise ValueError("one error channel expected")
        if any(not value or len(value.encode()) > 4096 for value in self.forbidden_literals):
            raise ValueError("bounded nonempty private markers required")
        if len(json.dumps(self.arguments, ensure_ascii=False, allow_nan=False).encode()) > 16384:
            raise ValueError("bounded tool arguments required")
        return self


class Observation(BoundaryModel):
    frame: bytes = Field(max_length=2 * MAX_FRAME_BYTES, repr=False)
    frame_origin: Literal["captured_wire", "adapter_serialization"]
    measured_read_bytes: int | None = Field(default=None, ge=0)
    request_id: int | str | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def bounded_request_id(self):
        if self.request_id is not None and not _request_id_is_bounded(self.request_id):
            raise ValueError("bounded observed request ID required")
        return self


class Result(BoundaryModel):
    case_id: Identifier
    status: Literal["passed", "failed", "not_applicable", "unsupported_required"]
    reason: str = Field(max_length=64)
    duration_ms: int = Field(default=0, ge=0)
    frame_bytes: int | None = Field(default=None, ge=0)
    measured_read_bytes: int | None = Field(default=None, ge=0)


class Report(BoundaryModel):
    platform: Literal["nt", "posix"]
    execution_kind: Literal["in_memory_synthetic", "local_adapter", "native_platform"]
    results: tuple[Result, ...]

    @property
    def counts(self) -> dict[str, int]:
        return {
            status: sum(row.status == status for row in self.results)
            for status in ("passed", "failed", "not_applicable", "unsupported_required")
        }

    @property
    def complete_pass(self) -> bool:
        counts = self.counts
        return bool(counts["passed"]) and counts["failed"] == counts["unsupported_required"] == 0
