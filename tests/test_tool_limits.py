"""Lower-only instance limits: strict configuration and real application mechanisms.

Memory/clock fixtures are not native filesystem, wire or hard-preemption proof.
"""

import asyncio
import json

import pytest
from pydantic import ValidationError

from dev_logs_mcp.config import AppConfig, ToolLimits, parse_config
from dev_logs_mcp.index import ReadBudget
from dev_logs_mcp.query import LogEngine
from dev_logs_mcp.server import CallGate
from dev_logs_mcp.shared.mcpkit.bounded_output import OutputBudget
from dev_logs_mcp.shared.mcpkit.errors import MAX_READ_BYTES
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
