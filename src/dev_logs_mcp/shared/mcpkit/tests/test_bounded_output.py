import json

import pytest
from pydantic import ValidationError

from dev_logs_mcp.shared.mcpkit.bounded_output import OutputBudget, ProtocolBudgetError
from dev_logs_mcp.shared.mcpkit.errors import ErrorCode
from dev_logs_mcp.shared.mcpkit.models import Coverage, ErrorGroup, LogLine, ToolEnvelope


def evidence(lines):
    return ToolEnvelope(
        ok=True,
        source_id="web",
        generation_id="synthetic-generation",
        lines=lines,
        coverage=Coverage(complete=True),
    )


def test_actual_full_frame_boundary_includes_mirror_escaping_and_id():
    """Catch payload-byte/doubling estimates that miss the actual JSON-RPC frame."""
    result = evidence([LogLine(line_no=1, byte_offset=0, text='é🙂"\\ [TOKEN:20:0000]' * 30)])
    first = OutputBudget().render(result, "request-1")
    exact = len(first.wire_bytes)
    rendered = OutputBudget(max_wire_bytes=exact).render(result, "request-1")
    assert len(rendered.wire_bytes) == exact
    assert rendered.wire_bytes.endswith(b"\n")
    frame = json.loads(rendered.wire_bytes)
    assert frame["jsonrpc"] == "2.0" and frame["id"] == "request-1"
    assert json.loads(frame["result"]["content"][0]["text"]) == frame["result"]["structuredContent"]
    assert frame["result"]["structuredContent"]["lines"][0]["text"] == result.lines[0].text
    smaller = OutputBudget(max_wire_bytes=exact - 1).render(result, "request-1")
    assert len(smaller.wire_bytes) <= exact - 1
    assert not smaller.envelope.ok and smaller.envelope.error.code == ErrorCode.LIMIT_EXCEEDED
    assert smaller.envelope.lines == []


@pytest.mark.parametrize("request_id", [True, 1.5, None, 2**53, "é" * 129, "\ud800"])
def test_unbounded_or_ambiguous_request_id_not_echoed(request_id):
    with pytest.raises(ProtocolBudgetError, match="request ID"):
        OutputBudget().render(ToolEnvelope(ok=True), request_id)


def test_too_small_mandatory_metadata_budget_never_returns_oversize():
    with pytest.raises(ProtocolBudgetError, match="metadata"):
        OutputBudget(max_wire_bytes=1).render(ToolEnvelope(ok=True), 1)


@pytest.mark.parametrize(
    "kwargs",
    [{"max_lines": True}, {"max_lines": 501}, {"max_wire_bytes": 32769}, {"max_wire_bytes": 0}],
)
def test_configuration_cannot_raise_hard_caps(kwargs):
    with pytest.raises(ValueError):
        OutputBudget(**kwargs)


def test_whole_unit_shrink_preserves_callback_cursor_and_scan_completeness():
    """Catch raw-string clipping or invented/incorrect first-unreturned cursor."""
    rows = [LogLine(line_no=i + 1, byte_offset=i * 100, text="é" * 80) for i in range(20)]
    original = evidence(rows)
    calls = []

    def shrink(limit):
        calls.append(limit)
        return ToolEnvelope(
            ok=True,
            source_id="web",
            generation_id="synthetic-generation",
            lines=rows[:limit],
            coverage=Coverage(complete=True),
            next_cursor=f"resume-first-unreturned-{limit + 1}",
            hint="Continue with the returned cursor",
        )

    rendered = OutputBudget(max_wire_bytes=3000).render(original, 1, shrink)
    assert rendered.envelope.ok
    assert len(calls) <= 11
    assert rendered.accepted_units < 20
    assert rendered.envelope.next_cursor == f"resume-first-unreturned-{rendered.accepted_units + 1}"
    assert rendered.envelope.coverage.complete
    assert rendered.envelope.truncation.output_bytes
    assert all(line.text == "é" * 80 for line in rendered.envelope.lines)
    assert len(rendered.wire_bytes) <= 3000
    assert len(original.lines) == 20  # callback/render must not mutate its input


def test_nested_trace_lines_count_towards_physical_cap():
    groups = []
    for group in range(100):
        start = group * 6 + 1
        groups.append(
            ErrorGroup(
                signature=f"synthetic-{group}",
                level="ERROR",
                first_in_coverage=LogLine(line_no=start, byte_offset=start, text="first"),
                occurrence_count_in_coverage=1,
                trace=[
                    LogLine(line_no=start + i, byte_offset=start + i, text="trace")
                    for i in range(1, 6)
                ],
            )
        )
    result = ToolEnvelope(ok=True, source_id="web", generation_id="g", groups=groups)
    rendered = OutputBudget().render(result, 1)
    assert not rendered.envelope.ok
    assert rendered.envelope.groups == []
    assert rendered.envelope.error.code == ErrorCode.LIMIT_EXCEEDED


def test_500_tiny_lines_can_still_exceed_independent_wire_cap():
    rows = [LogLine(line_no=i + 1, byte_offset=i, text="x") for i in range(500)]
    result = evidence(rows)
    # The full-frame byte cap is independent from the 500-line cap.
    rendered = OutputBudget().render(result, 1)
    assert len(rendered.wire_bytes) <= 32768
    assert not rendered.envelope.ok


def test_huge_metadata_and_surrogate_content_fall_closed_without_echo():
    huge = ToolEnvelope(ok=True, warnings=["untrusted-sentinel-" * 10000])
    rendered = OutputBudget().render(huge, 1)
    assert not rendered.envelope.ok
    assert b"untrusted-sentinel" not in rendered.wire_bytes
    with pytest.raises(ValidationError):
        LogLine(line_no=1, byte_offset=0, text="\ud800")
    # Defense in depth if trusted Python code bypasses the validated boundary.
    invalid_utf8 = evidence([LogLine.model_construct(line_no=1, byte_offset=0, text="\ud800")])
    rejected = OutputBudget().render(invalid_utf8, 1)
    assert not rejected.envelope.ok


def test_tightened_physical_line_boundary_includes_nested_trace():
    """Catch counting only top-level rows, or treating two views of a row as two lines."""
    first = LogLine(line_no=1, byte_offset=0, text="first")
    second = LogLine(line_no=2, byte_offset=6, text="second")
    result = ToolEnvelope(
        ok=True,
        source_id="web",
        generation_id="g",
        lines=[first],
        groups=[
            ErrorGroup(
                signature="s",
                level="ERROR",
                first_in_coverage=first,
                occurrence_count_in_coverage=1,
                trace=[second],
            )
        ],
    )
    assert OutputBudget(max_lines=2).render(result, 1).envelope.ok
    rejected = OutputBudget(max_lines=1).render(result, 1)
    assert not rejected.envelope.ok
    assert rejected.envelope.lines == [] and rejected.envelope.groups == []


def test_callback_failure_is_sanitized_and_no_text_prefix_is_returned():
    result = evidence([LogLine(line_no=1, byte_offset=0, text="x" * 30000)])

    def bad_callback(limit):
        raise ValueError("sensitive-sentinel-must-not-echo")

    rendered = OutputBudget().render(result, 1, bad_callback)
    assert not rendered.envelope.ok
    assert rendered.envelope.error.code == ErrorCode.INTERNAL_ERROR
    assert b"sensitive-sentinel" not in rendered.wire_bytes
    assert rendered.envelope.lines == []


def test_callback_cannot_silently_drop_continuation_or_exceed_unit_limit():
    result = evidence([LogLine(line_no=1, byte_offset=0, text="x" * 30000)])
    rendered = OutputBudget().render(result, 1, lambda limit: ToolEnvelope(ok=True))
    assert not rendered.envelope.ok
    assert rendered.envelope.error.code == ErrorCode.INTERNAL_ERROR
