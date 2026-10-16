"""Lower-only instance limits: strict configuration and real application mechanisms.

Memory/clock fixtures are not native filesystem, wire or hard-preemption proof.
"""

import asyncio
import json
from dataclasses import replace
from time import perf_counter

import pytest
from pydantic import ValidationError

from dev_logs_mcp.config import AppConfig, ToolLimits, parse_config
from dev_logs_mcp.index import ReadBudget
from dev_logs_mcp.query import LogEngine
from dev_logs_mcp.server import CallGate
from dev_logs_mcp.shared.mcpkit.bounded_output import OutputBudget
from dev_logs_mcp.shared.mcpkit.errors import MAX_READ_BYTES
from dev_logs_mcp.shared.mcpkit.models import LogLine, ToolEnvelope
from dev_logs_mcp.sources import SourceCatalog
from tests.test_query import FakeCatalog


@pytest.mark.parametrize(
    "field,value",
    [
        ("read_bytes", True),
        ("read_bytes", 0),
        ("read_bytes", 8388609),
        ("read_bytes", 10.5),
        ("read_bytes", "1024"),
        ("lines", False),
        ("lines", 0),
        ("lines", 501),
        ("lines", "10"),
        ("frame_bytes", True),
        ("frame_bytes", 8191),
        ("frame_bytes", 32769),
        ("seconds", True),
        ("seconds", 0.0),
        ("seconds", -1.0),
        ("seconds", 5.01),
        ("seconds", float("inf")),
        ("seconds", float("nan")),
        ("seconds", "1"),
        ("unknown", 1),
    ],
)
def test_config_cannot_widen_or_ambiguate_limits(field, value):
    """what_bug_this_catches: scalar coercion/NaN/unknown settings cannot widen authority."""
    with pytest.raises(ValidationError):
        ToolLimits.model_validate({field: value})


def test_default_and_toml_limits_are_frozen_and_hash_bound(tmp_path):
    base = 'allowed_roots=["logs"]\n[[sources]]\nid="web"\npath="logs/web.log"\n'
    default = parse_config(base)
    tightened = parse_config(
        base + "[tool_limits]\nread_bytes=65536\nlines=3\nframe_bytes=8192\nseconds=1.0\n"
    )
    assert default.tool_limits == ToolLimits()
    assert tightened.tool_limits == ToolLimits(
        read_bytes=65536, lines=3, frame_bytes=8192, seconds=1.0
    )
    assert (
        SourceCatalog(default, tmp_path).config_hash
        != SourceCatalog(tightened, tmp_path).config_hash
    )
    with pytest.raises(ValidationError):
        tightened.tool_limits.read_bytes = MAX_READ_BYTES
    with pytest.raises(ValidationError):
        AppConfig.model_validate({**default.model_dump(), "tool_limits": {"seconds": False}})


def configured(data, **settings):
    catalog = FakeCatalog(data)
    catalog.tool_limits = ToolLimits(**settings)
    return LogEngine(catalog)


def test_lower_read_cap_refuses_before_body_and_external_budget_cannot_widen():
    """what_bug_this_catches: all auto-index/helper reads must share configured allowance."""
    subject = configured(b"INFO evidence\n" * 200, read_bytes=128)
    rendered = subject.call("tail", {"source_id": "web"}).render(1)
    assert not rendered.envelope.ok
    assert rendered.envelope.error.code.value == "INDEX_INCOMPLETE"
    assert rendered.envelope.coverage.bytes_read <= 128
    with pytest.raises(ValueError, match="configured read ceiling"):
        subject.call("tail", {"source_id": "web"}, budget=ReadBudget())
    # Explicit CLI preparation is separate, not a way an MCP request can widen this cap.
    assert subject.prepare("web").total_lines == 200


def test_render_limit_survives_caller_budget_and_error_paths():
    """what_bug_this_catches: an explicit caller renderer must not bypass instance caps."""
    data = (b"2026-01-01T00:00:00Z ERROR evidence " + b"x" * 500 + b"\n") * 100
    subject = configured(data, lines=3, frame_bytes=8192)
    result = subject.call("tail", {"source_id": "web"}).render(1, OutputBudget())
    assert result.envelope.ok and result.truncated
    assert len(result.envelope.lines) <= 3 and len(result.wire_bytes) <= 8192
    assert result.envelope.hint or result.envelope.next_cursor
    failed = subject.call("tail", {"source_id": "unknown"}).render(1, OutputBudget())
    assert not failed.envelope.ok and len(failed.wire_bytes) <= 8192
    assert failed.envelope.error.code.value == "UNKNOWN_SOURCE"
    assert json.loads(failed.wire_bytes)["result"]["isError"] is True


@pytest.mark.parametrize("limit", [1, 2, 3, 4])
@pytest.mark.parametrize("tool", ["tail", "read_range", "search"])
def test_small_line_limits_use_complete_allowance_before_shrinking(limit, tool):
    """what_bug_this_catches: halving first skipped one-line capacity and wasted small limits."""
    data = b"".join(f"2026-01-01T00:00:00Z INFO evidence {n}\n".encode() for n in range(1, 9))
    subject = configured(data, lines=limit, frame_bytes=8192)
    arguments = {"source_id": "web"}
    if tool == "tail":
        arguments["lines"] = 8
    elif tool == "read_range":
        arguments.update(start_line=1, end_line=8)
    else:
        arguments.update(pattern="evidence", context=0, direction="oldest_first")
    rendered = subject.call(tool, arguments).render(1)
    assert rendered.envelope.ok and rendered.truncated
    expected = list(range(9 - limit, 9)) if tool == "tail" else list(range(1, limit + 1))
    assert [row.line_no for row in rendered.envelope.lines] == expected
    assert len(rendered.wire_bytes) <= 8192
    assert rendered.envelope.next_cursor or rendered.envelope.hint


@pytest.mark.parametrize("direction", ["oldest_first", "newest_first"])
def test_context_unit_equal_to_line_limit_pages_without_losing_evidence(direction):
    """what_bug_this_catches: a complete three-line context unit was skipped at a three-line cap."""
    data = b"miss\nhit\nmiss\nmiss\nhit\nmiss\n"
    subject = configured(data, lines=3, frame_bytes=8192)
    args = {"source_id": "web", "pattern": "hit", "context": 1, "direction": direction}
    pages = []
    seen_cursors = set()
    for _ in range(3):
        rendered = subject.call("search", args).render(1)
        page = rendered.envelope
        assert page.ok and len(rendered.wire_bytes) <= 8192
        assert len(page.lines) == 3 and len(page.matches) == 1
        pages.append(([row.line_no for row in page.lines], page.matches[0].line_no))
        if page.next_cursor is None:
            break
        assert page.next_cursor not in seen_cursors
        seen_cursors.add(page.next_cursor)
        args = {**args, "cursor": page.next_cursor}
    else:
        pytest.fail("context pagination did not advance")
    expected = [([1, 2, 3], 2), ([4, 5, 6], 5)]
    assert pages == (expected if direction == "oldest_first" else expected[::-1])


@pytest.mark.parametrize("direction", ["oldest_first", "newest_first"])
def test_one_line_search_page_union_preserves_first_unreturned_match(direction):
    """what_bug_this_catches: one-line pages must advance without lost matches."""
    subject = configured(b"hit\n" * 8, lines=1, frame_bytes=8192)
    args = {"source_id": "web", "pattern": "hit", "context": 0, "direction": direction}
    matches = []
    seen_cursors = set()
    for _ in range(9):
        rendered = subject.call("search", args).render(1)
        page = rendered.envelope
        assert page.ok and len(rendered.wire_bytes) <= 8192
        assert len(page.lines) == len(page.matches) == 1
        matches.append(page.matches[0].line_no)
        if page.next_cursor is None:
            break
        assert page.next_cursor not in seen_cursors
        seen_cursors.add(page.next_cursor)
        args = {**args, "cursor": page.next_cursor}
    else:
        pytest.fail("one-line pagination did not advance")
    expected = list(range(1, 9))
    assert matches == (expected if direction == "oldest_first" else expected[::-1])


@pytest.mark.parametrize("frame_budget,width", [(8192, 600), (8192, 700), (6144, 400)])
@pytest.mark.parametrize("direction", ["oldest_first", "newest_first"])
def test_byte_pressure_preserves_complete_context_between_probe_limits(
    frame_budget, width, direction
):
    """what_bug_this_catches: probing4 then2 skipped a fitting complete3-line context."""
    data = b"".join(
        (
            f"2026-01-01T00:00:00Z INFO {'hit' if n in (2, 3, 6) else 'miss'} " + "x" * width + "\n"
        ).encode()
        for n in range(1, 8)
    )
    subject = configured(data, lines=4, frame_bytes=8192)
    args = {"source_id": "web", "pattern": "hit", "context": 1, "direction": direction}
    matches = []
    cursors = set()
    attempts_by_page = []
    byte_truncated = False
    previous = None
    for _ in range(4):
        query = subject.call("search", args)
        original_shrink = query.shrink
        attempts = []

        def counted(limit, *, calls=attempts, shrink=original_shrink):
            calls.append(limit)
            return shrink(limit)

        rendered = replace(query, shrink=counted).render(
            1, OutputBudget(max_wire_bytes=frame_budget)
        )
        page = rendered.envelope
        assert page.ok and len(rendered.wire_bytes) <= frame_budget
        anchors = [match.line_no for match in page.matches]
        assert anchors and len(anchors) == len(set(anchors))
        expected_lines = sorted({n for anchor in anchors for n in (anchor - 1, anchor, anchor + 1)})
        assert [line.line_no for line in page.lines] == expected_lines
        assert len(page.lines) <= 4
        assert all(line.context == (line.line_no not in anchors) for line in page.lines)
        if previous is not None:
            if direction == "oldest_first":
                assert min(anchors) > max(previous)
            else:
                assert max(anchors) < min(previous)
        previous = anchors
        assert len(attempts) <= 11
        attempts_by_page.append(attempts)
        byte_truncated |= page.truncation.output_bytes
        matches.extend(anchors)
        if page.next_cursor is None:
            break
        assert page.next_cursor not in cursors
        cursors.add(page.next_cursor)
        args = {**args, "cursor": page.next_cursor}
    else:
        pytest.fail("byte-limited context pagination did not advance")
    assert sorted(matches) == [2, 3, 6]
    if direction == "oldest_first":
        assert any(3 in attempts for attempts in attempts_by_page)
        assert byte_truncated


def test_line_limited_wire_boundary_does_not_admit_page_by_shortening_flags():
    """what_bug_this_catches: shortening flags admitted an oversized prefix."""
    rows = [LogLine(line_no=n, byte_offset=n, text='é🙂"\\' * 20) for n in range(1, 5)]
    original = ToolEnvelope(ok=True, source_id="web", generation_id="g", lines=rows)

    def shrink(limit):
        return original.model_copy(
            update={"lines": rows[:limit], "hint": f"continue at physical line {limit + 1}"}
        )

    first = OutputBudget(max_lines=1).render(original, "r", shrink)
    exact = len(first.wire_bytes)
    assert first.envelope.ok and len(first.envelope.lines) == 1
    accepted = OutputBudget(max_lines=1, max_wire_bytes=exact).render(original, "r", shrink)
    assert len(accepted.wire_bytes) == exact and len(accepted.envelope.lines) == 1
    refused = OutputBudget(max_lines=1, max_wire_bytes=exact - 1).render(original, "r", shrink)
    assert len(refused.wire_bytes) <= exact - 1 and not refused.envelope.lines


@pytest.mark.parametrize("wire_cap", [8192, 6144])
@pytest.mark.parametrize("occurrences", [2, 5, 99])
def test_grouped_errors_preserve_larger_complete_prefix_and_exact_cursor(wire_cap, occurrences):
    """what_bug_this_catches: coalesced groups hid a fitting larger raw-evidence prefix."""
    secret = b"grouped_synthetic_secret"
    alpha = b"2026-01-01T00:00:00Z ERROR alpha password=" + secret + b"\n"
    data = (
        b"2026-01-01T00:00:00Z ERROR bravo "
        + b"B" * 6000
        + b"\n"
        + alpha * occurrences
        + b"  "
        + b"T" * 4000
        + b"\n"
    )
    subject = configured(data, lines=occurrences + 2, frame_bytes=8192)
    query = subject.call("errors", {"source_id": "web"})
    original = query.envelope.model_dump()
    opened = subject.catalog.opened
    calls = []

    def counted(limit):
        calls.append(limit)
        return query.shrink(limit)

    rendered = replace(query, shrink=counted).render(
        1, OutputBudget(max_lines=occurrences + 2, max_wire_bytes=wire_cap)
    )
    page = rendered.envelope
    assert page.ok and len(rendered.wire_bytes) <= wire_cap
    assert secret not in rendered.wire_bytes and len(page.groups) == 1
    group = page.groups[0]
    assert group.first_in_coverage.line_no == 2
    assert group.occurrence_count_in_coverage == occurrences and not group.trace
    assert page.next_cursor and page.truncation.output_bytes
    assert query.envelope.model_dump() == original and subject.catalog.opened == opened
    assert len(calls) <= 99
    # Every proper prefix is declared in traversal order, including collapsed ones.
    assert query.prefix_limits == tuple(range(occurrences + 1, 1, -1))
    resumed = subject.call("errors", {"source_id": "web", "cursor": page.next_cursor}).envelope
    assert resumed.ok and len(resumed.groups) == 1 and resumed.next_cursor is None
    assert resumed.groups[0].first_in_coverage.line_no == 1
    assert resumed.groups[0].occurrence_count_in_coverage == 1


def test_errors_worst_case99_prefixes_preserve_deadline_and_do_not_reopen_source(record_property):
    """what_bug_this_catches: actual errors must bound all99 expensive nonfitting prefixes."""
    data = b"".join(
        (
            "2026-01-01T00:00:00Z ERROR issue "
            + chr(65 + n // 26)
            + chr(65 + n % 26)
            + " "
            + "X" * 2000
            + "\n"
        ).encode()
        for n in range(100)
    )
    subject = configured(data, lines=100, frame_bytes=8192)
    query = subject.call("errors", {"source_id": "web"})
    assert query.envelope.ok and query.prefix_limits == tuple(range(99, 0, -1))
    opened = subject.catalog.opened
    calls = []

    def counted(limit):
        calls.append(limit)
        return query.shrink(limit)

    started = perf_counter()
    rendered = replace(query, shrink=counted).render(1)
    elapsed = perf_counter() - started
    record_property("prefix_scan_seconds", elapsed)
    record_property("declared_callback_attempts", len(calls))
    record_property("captured_bytes_read", rendered.envelope.coverage.bytes_read)
    assert rendered.envelope.ok and len(rendered.envelope.groups) == 1
    assert len(rendered.wire_bytes) <= 8192 and calls == list(range(99, 0, -1))
    assert elapsed < 5.0 and subject.catalog.opened == opened
    assert rendered.envelope.next_cursor and query.render_budget.deadline < perf_counter() + 5.0


def test_grouped_error_rendering_uses_original_deadline_before_and_after_wire(monkeypatch):
    """what_bug_this_catches: rendering captured prefixes cannot renew or outlive the call."""
    clock = [0.0]
    subject = configured(b"2026-01-01T00:00:00Z ERROR small\n")
    read_budget = ReadBudget(clock=lambda: clock[0])
    query = subject.call("errors", {"source_id": "web"}, budget=read_budget)
    budget = OutputBudget()
    original_wire = OutputBudget._wire

    def slow_wire(selected, result, request_id):
        wire = original_wire(selected, result, request_id)
        clock[0] = 6.0
        return wire

    monkeypatch.setattr(OutputBudget, "_wire", slow_wire)
    result = query.render(1, budget).envelope
    assert not result.ok and result.error.code.value == "LIMIT_EXCEEDED"
    assert not result.groups
    # The same captured query also refuses before another serialization attempt.
    assert not query.render(1).envelope.ok


def test_grouped_error_prefix_expiry_stops_callbacks_without_partial_evidence():
    """what_bug_this_catches: expiry inside prefix assembly must stop and discard evidence."""
    clock = [0.0]
    budget = ReadBudget(clock=lambda: clock[0])
    subject = configured(
        b"2026-01-01T00:00:00Z ERROR bravo " + b"B" * 6000 + b"\n"
        b"2026-01-01T00:00:00Z ERROR alpha\n"
        b"2026-01-01T00:00:00Z ERROR alpha\n  " + b"T" * 4000 + b"\n",
        lines=4,
        frame_bytes=8192,
    )
    query = subject.call("errors", {"source_id": "web"}, budget=budget)
    opened = subject.catalog.opened
    calls = []

    def expired(limit):
        calls.append(limit)
        clock[0] = 6.0
        return query.shrink(limit)

    result = replace(query, shrink=expired).render(1).envelope
    assert calls == [3] and not result.ok and result.error.code.value == "LIMIT_EXCEEDED"
    assert not result.groups and not result.next_cursor and subject.catalog.opened == opened


def test_passed_deadline_is_clamped_to_original_start_not_reset():
    """what_bug_this_catches: admitting after queue time cannot reset a lower deadline."""
    now = [0.0]
    budget = ReadBudget(seconds=120, clock=lambda: now[0])
    now[0] = 2.0
    subject = configured(b"evidence\n", seconds=1.0)
    result = subject.call("tail", {"source_id": "web"}, budget=budget).envelope
    assert not result.ok and result.error.code.value == "LIMIT_EXCEEDED"
    assert budget.deadline == 1.0 and subject.catalog.opened == 0


def test_gate_budget_carries_configured_origin_read_and_time():
    async def exercise():
        gate = CallGate(ToolLimits(read_bytes=1234, seconds=0.1))
        async with gate.enter() as budget:
            assert budget.max_bytes == 1234
            assert budget.deadline - budget.started_at == pytest.approx(0.1)
            assert gate.active == 1
        assert gate.active == 0 and not gate.queue

    asyncio.run(exercise())
