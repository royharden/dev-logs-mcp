import pytest
from pydantic import ValidationError

from dev_logs_mcp.contracts import (
    MAX_FRAME_BYTES,
    MAX_LINES,
    MAX_READ_BYTES,
    REQUEST_MODELS,
    Coverage,
    ErrorCode,
    LogLine,
    ToolEnvelope,
    ToolError,
    validate_request,
)


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("list_sources", {}),
        ("tail", {"source_id": "web"}),
        ("search", {"source_id": "web", "pattern": "failure"}),
        ("read_range", {"source_id": "web", "start_line": 1, "end_line": 500}),
        ("errors", {"source_id": "web"}),
    ],
)
def test_all_five_request_shapes(tool, args):
    assert validate_request(tool, args).model_dump() is not None
    assert set(REQUEST_MODELS) == {"list_sources", "tail", "search", "read_range", "errors"}


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("tail", {"source_id": "web", "lines": True}),
        ("tail", {"source_id": "web", "lines": "200"}),
        ("tail", {"source_id": "web", "lines": 0}),
        ("tail", {"source_id": "web", "lines": MAX_LINES + 1}),
        ("tail", {"source_id": "web", "lines": float("nan")}),
        ("tail", {"source_id": "../outside"}),
        ("tail", {"source_id": "C:\\logs"}),
        ("tail", {"source_id": "bad\x00id"}),
        ("tail", {"source_id": "web", "path": "/etc/passwd"}),
        ("tail", {"source_id": "web", "since": "yesterday"}),
        ("search", {"source_id": "web", "pattern": "é" * 257}),
        ("search", {"source_id": "web", "pattern": "x", "context": 6}),
        ("search", {"source_id": "web", "pattern": "x", "max_matches": 101}),
        ("search", {"source_id": "web", "pattern": "x", "until": "soon"}),
        ("search", {"source_id": "web", "pattern": "x", "cursor": ""}),
        ("search", {"source_id": "web", "pattern": "x", "direction": "any"}),
        ("read_range", {"source_id": "web", "start_line": 4, "end_line": 3}),
        ("read_range", {"source_id": "web", "start_line": 1, "end_line": 501}),
        ("read_range", {"source_id": "web", "start_line": True, "end_line": 4}),
        ("list_sources", {"path": "/"}),
    ],
)
def test_adversarial_request_bounds(tool, args):
    """Catch type coercion, free paths and requests that raise hard ceilings."""
    with pytest.raises(ValidationError):
        validate_request(tool, args)


def test_unknown_tool_does_not_echo_untrusted_name():
    with pytest.raises(ValueError, match="^unknown tool$"):
        validate_request("sensitive-untrusted-input", {})


def test_exact_utf8_pattern_boundary():
    request = validate_request("search", {"source_id": "web", "pattern": "é" * 256})
    assert len(request.pattern.encode()) == 512


@pytest.mark.parametrize("line_no", [None, 0, -1, True, "1"])
def test_evidence_requires_exact_positive_line(line_no):
    with pytest.raises(ValidationError):
        LogLine(line_no=line_no, byte_offset=0, text="synthetic")


def test_error_cannot_carry_successful_evidence():
    error = ToolError(code=ErrorCode.INDEX_STALE, message="stale", hint="prepare again")
    with pytest.raises(ValidationError, match="successful evidence"):
        ToolEnvelope(
            ok=False,
            error=error,
            lines=[LogLine(line_no=1, byte_offset=0, text="synthetic")],
        )
    assert ToolEnvelope(ok=False, error=error).lines == []


def test_evidence_requires_generation_identity():
    with pytest.raises(ValidationError, match="source and generation"):
        ToolEnvelope(ok=True, lines=[LogLine(line_no=1, byte_offset=0, text="synthetic")])


def test_coverage_is_independent_of_output_truncation():
    from dev_logs_mcp.contracts import Truncation

    result = ToolEnvelope(
        ok=True,
        coverage=Coverage(first_line=1, last_line=4, total_lines=4, complete=True),
        truncation=Truncation(output_bytes=True),
    )
    assert result.coverage.complete and result.truncation.output_bytes
    assert MAX_FRAME_BYTES == 32768


@pytest.mark.parametrize(
    "kwargs",
    [
        {"first_line": 1},
        {"first_line": 3, "last_line": 2},
        {"first_line": 1, "last_line": 2, "total_lines": 1},
        {"bytes_read": MAX_READ_BYTES + 1},
    ],
)
def test_impossible_coverage_rejected(kwargs):
    with pytest.raises(ValidationError):
        Coverage(**kwargs)
