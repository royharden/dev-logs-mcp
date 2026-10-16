"""Explicit preflight timing is separate from unchanged MCP call timing.

Injected memory/clock tests do not attest native throughput or hard preemption.
"""

import pytest

import dev_logs_mcp.query as query
from dev_logs_mcp.index import MAX_SOURCE_BYTES, ReadBudget, ReadFailure
from dev_logs_mcp.shared.mcpkit.errors import MAX_READ_BYTES
from tests.test_query import engine


def timing(monkeypatch, step, retry=False):
    clock = [0.0]
    budgets = []
    seen = []
    original = query.prepare_index

    def budget(max_bytes=MAX_READ_BYTES, seconds=5.0):
        value = ReadBudget(max_bytes, seconds, clock=lambda: clock[0])
        budgets.append(value)
        return value

    def prepare(*args, **kwargs):
        seen.append(args[4])
        clock[0] = step + len(seen) - 1
        if retry and len(seen) == 1:
            raise ReadFailure("SOURCE_CHANGED")
        return original(*args, **kwargs)

    monkeypatch.setattr(query, "ReadBudget", budget)
    monkeypatch.setattr(query, "prepare_index", prepare)
    return budgets, seen


def test_explicit_preflight_crosses_tool_deadline_but_shares_one_retry_budget(monkeypatch):
    """what_bug_this_catches: the five-second tool default made static100MB prep unavailable."""
    budgets, seen = timing(monkeypatch, 6.0, retry=True)
    subject = engine(b"2026-01-01T00:00:00Z INFO synthetic\n")
    result = subject.prepare("web")
    assert result.total_lines == 1
    assert len(budgets) == 1 and len(seen) == 2 and seen[0] is seen[1] is budgets[0]
    assert budgets[0].deadline == 120.0 and budgets[0].max_bytes == MAX_SOURCE_BYTES
    assert subject.catalog.opened == subject.catalog.closed == 2


def test_mcp_auto_index_keeps_five_second_and_eight_mib_ceiling(monkeypatch):
    """what_bug_this_catches: preflight timing must never widen a tool's hidden auto-index."""
    budgets, seen = timing(monkeypatch, 6.0)
    subject = engine(b"2026-01-01T00:00:00Z INFO synthetic\n")
    result = subject.call("tail", {"source_id": "web"}).envelope
    assert not result.ok and result.error.code.value == "INDEX_INCOMPLETE"
    assert budgets[0].deadline == 5.0 and budgets[0].max_bytes == MAX_READ_BYTES
    assert seen == budgets and not subject._indexes
    assert subject.catalog.opened == subject.catalog.closed == 1


def test_explicit_preflight_still_refuses_after_its_finite_deadline(monkeypatch):
    """what_bug_this_catches: separate preflight timing cannot become unbounded preparation."""
    budgets, seen = timing(monkeypatch, 121.0)
    subject = engine(b"2026-01-01T00:00:00Z INFO synthetic\n")
    with pytest.raises(ReadFailure) as error:
        subject.prepare("web")
    assert error.value.code == "INDEX_INCOMPLETE"
    assert len(budgets) == len(seen) == 1 and not subject._indexes
    assert subject.catalog.opened == subject.catalog.closed == 1
