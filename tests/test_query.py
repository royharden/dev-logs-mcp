"""Original synthetic query controls; no actual configured-file or MCP transport proof."""

from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from dev_logs_mcp.index import ReadBudget, ReadFailure
from dev_logs_mcp.query import Cursors, LogEngine
from dev_logs_mcp.shared.mcpkit.bounded_output import OutputBudget
from dev_logs_mcp.shared.mcpkit.models import SourceInfo
from dev_logs_mcp.shared.mcpkit.redact import Redactor
from tests.index.test_generation import MemoryHandle


class FakeCatalog:
    """Explicitly injected in-memory storage; production SourceCatalog is untouched."""

    config_hash = "a" * 64

    def __init__(self, data):
        self.data = data
        self.version = 4
        self.size_override = None
        self.opened = 0
        self.closed = 0
        self.source = SimpleNamespace(id="web", format="auto", timezone="UTC")

    def get(self, source_id):
        if source_id != "web":
            raise ReadFailure("UNKNOWN_SOURCE")
        return self.source

    @contextmanager
    def open(self, source_id):
        self.get(source_id)
        self.opened += 1
        handle = MemoryHandle(self.data)
        handle.identity = replace(
            handle.identity,
            change_time_ns=self.version,
            size_bytes=len(self.data) if self.size_override is None else self.size_override,
        )
        try:
            yield handle
        finally:
            self.closed += 1

    def infos(self, redactor, budget):
        return [
            SourceInfo(id="web", display_path="synthetic.log", size=len(self.data), readable=True)
        ]


def engine(data):
    return LogEngine(FakeCatalog(data), redactor=Redactor(b"q" * 32))


def test_five_tools_shape_and_source_handle_lifetime():
    subject = engine(b"2026-01-01T00:00:00Z ERROR failed\n  trace\n")
    arguments = {
        "list_sources": {},
        "tail": {"source_id": "web"},
        "search": {"source_id": "web", "pattern": "failed"},
        "read_range": {"source_id": "web", "start_line": 1, "end_line": 2},
        "errors": {"source_id": "web"},
    }
    for name, args in arguments.items():
        result = subject.call(name, args)
        assert result.envelope.ok, (name, result.envelope.error)
        assert len(result.render(1).wire_bytes) <= 32768
    assert subject.catalog.opened == subject.catalog.closed == 4


def test_search_is_redacted_only_and_returns_exact_physical_context():
    raw = (
        b"orphan\n2026-01-01T00:00:00Z ERROR failed password="
        + b"synthetic-sentinel"
        + b"\n  trace\nafter\n"
    )
    subject = engine(raw)
    query = {"source_id": "web", "pattern": "synthetic-sentinel", "context": 1}
    assert subject.call("search", query).envelope.matches == []
    page = subject.call("search", {**query, "pattern": "failed"}).envelope
    assert [line.line_no for line in page.lines] == [1, 2, 3]
    assert [line.context for line in page.lines] == [True, False, True]
    assert [match.line_no for match in page.matches] == [2]
    assert "synthetic-sentinel" not in page.model_dump_json()


@pytest.mark.parametrize("direction", ["newest_first", "oldest_first"])
def test_complete_paged_match_union_equals_simple_physical_oracle(direction):
    """what_bug_this_catches: first-unreturned positions cannot skip or repeat matches."""
    data = b"".join(
        f"2026-01-01T00:00:00Z INFO {'hit' if n % 3 == 0 else 'miss'} {n}\n".encode()
        for n in range(1, 401)
    )
    subject = engine(data)
    args = {
        "source_id": "web",
        "pattern": "hit",
        "context": 2,
        "max_matches": 7,
        "direction": direction,
    }
    seen = []
    cursors = set()
    for _ in range(100):
        page = subject.call("search", args).envelope
        assert page.ok
        seen.extend(match.line_no for match in page.matches)
        if page.next_cursor is None:
            break
        assert page.next_cursor not in cursors
        cursors.add(page.next_cursor)
        args = {**args, "cursor": page.next_cursor}
    else:
        pytest.fail("cursor did not finish")
    assert len(seen) == len(set(seen))
    assert sorted(seen) == list(range(3, 401, 3))


def test_serialized_budget_shrink_resumes_first_unreturned_match():
    data = b"".join(
        f"2026-01-01T00:00:00Z INFO hit {n} ".encode() + b"x" * 200 + b"\n" for n in range(1, 41)
    )
    subject = engine(data)
    args = {
        "source_id": "web",
        "pattern": "hit",
        "context": 0,
        "max_matches": 40,
        "direction": "oldest_first",
    }
    first = subject.call("search", args).render("request", OutputBudget(max_wire_bytes=6000))
    assert first.truncated and first.envelope.ok
    accepted = [match.line_no for match in first.envelope.matches]
    assert accepted and len(accepted) < 40
    assert first.envelope.truncation.output_bytes and first.envelope.next_cursor
    second = subject.call("search", {**args, "cursor": first.envelope.next_cursor}).envelope
    assert min(match.line_no for match in second.matches) == max(accepted) + 1
    assert len(first.wire_bytes) <= 6000


@pytest.mark.parametrize(
    "mutation", ["pattern", "context", "direction", "tool", "tamper", "generation", "process"]
)
def test_cursor_binding_rejects_other_query_generation_and_process(mutation):
    subject = engine(b"hit\nhit\nhit\n")
    args = {"source_id": "web", "pattern": "hit", "context": 0, "max_matches": 1}
    cursor = subject.call("search", args).envelope.next_cursor
    tool = "search"
    if mutation == "pattern":
        args["pattern"] = "other"
    elif mutation == "context":
        args["context"] = 1
    elif mutation == "direction":
        args["direction"] = "oldest_first"
    elif mutation == "tool":
        tool = "errors"
        args = {"source_id": "web"}
    elif mutation == "tamper":
        cursor = ("A" if cursor[0] != "A" else "B") + cursor[1:]
    elif mutation == "generation":
        subject.catalog.version += 1
    elif mutation == "process":
        subject.cursors = Cursors()
    page = subject.call(tool, {**args, "cursor": cursor}).envelope
    assert not page.ok and page.error.code == "INVALID_CURSOR"


def test_nonmonotonic_time_filters_inclusive_exclusive_and_orphans():
    data = (
        b"orphan hit\n2026-01-03T00:00:00Z INFO hit late\n"
        b"2026-01-01T00:00:00Z ERROR hit early\n  hit trace\n"
        b"2026-01-02T00:00:00Z INFO hit end\n"
    )
    subject = engine(data)
    result = subject.call(
        "search",
        {
            "source_id": "web",
            "pattern": "hit",
            "context": 0,
            "since": "2026-01-01T00:00:00Z",
            "until": "2026-01-02T00:00:00Z",
        },
    ).envelope
    assert result.ok and [match.line_no for match in result.matches] == [3, 4]
    assert result.coverage.excluded_untimestamped == 1 and result.coverage.complete


def test_fractional_time_uses_datetime_order_not_variable_length_lexicographic_order():
    subject = engine(
        b"2026-01-01T00:00:00Z INFO hit zero\n2026-01-01T00:00:00.100Z INFO hit fractional\n"
    )
    result = subject.call(
        "search",
        {"source_id": "web", "pattern": "hit", "context": 0, "since": "2026-01-01T00:00:00.050Z"},
    ).envelope
    assert [match.line_no for match in result.matches] == [2]


def test_errors_count_headers_only_group_volatile_ids_and_trace():
    subject = engine(
        b"2026-01-01T00:00:00Z ERROR fail request 123\n  trace ERROR not occurrence\n"
        b'2026-01-01T00:00:01Z ERROR fail request 456\n{"message":"ERROR unknown"}\n'
    )
    page = subject.call("errors", {"source_id": "web"}).envelope
    assert page.ok and len(page.groups) == 1
    assert page.groups[0].occurrence_count_in_coverage == 2
    assert page.groups[0].first_in_coverage.line_no == 1
    assert [line.line_no for line in page.groups[0].trace] == [2]


def test_large_cold_source_refused_before_any_data_read():
    subject = engine(b"not actually large")
    subject.catalog.size_override = 6 * 1024 * 1024 + 1
    result = subject.call("tail", {"source_id": "web"}).envelope
    assert not result.ok and result.error.code == "INDEX_REQUIRED"
    assert result.coverage.bytes_read == 0


def test_cold_small_budget_failure_returns_no_partial_index_or_evidence():
    subject = engine(b"hit\n" * 50)
    result = subject.call(
        "search", {"source_id": "web", "pattern": "hit"}, budget=ReadBudget(100)
    ).envelope
    assert not result.ok and result.error.code == "INDEX_INCOMPLETE"
    assert not result.lines and not subject._indexes


def test_context_line_cap_pages_progress_without_skipping_anchor():
    """what_bug_this_catches: disjoint context windows cannot exceed500 physical rows."""
    data = b"".join((b"hit" if n % 11 == 0 else b"context") + b"\n" for n in range(1, 1101))
    subject = engine(data)
    args = {
        "source_id": "web",
        "pattern": "hit",
        "context": 5,
        "max_matches": 100,
        "direction": "oldest_first",
    }
    first = subject.call("search", args).envelope
    assert first.ok and len(first.lines) <= 500 and first.next_cursor
    second = subject.call("search", {**args, "cursor": first.next_cursor}).envelope
    assert min(match.line_no for match in second.matches) > max(
        match.line_no for match in first.matches
    )


def test_output_shrink_error_group_counts_only_accepted_occurrence_prefix():
    data = b"".join(
        f"2026-01-01T00:00:{n % 60:02}Z ERROR issue {'alpha' if n % 2 else 'bravo'} ".encode()
        + b"x" * 2000
        + b"\n"
        for n in range(80)
    )
    subject = engine(data)
    args = {"source_id": "web"}
    query = subject.call("errors", args)
    full = query.render(1)
    one = OutputBudget().render(query.shrink(1), 1)
    limit = len(one.wire_bytes) + 20
    assert limit < len(full.wire_bytes)
    result = query.render(1, OutputBudget(max_wire_bytes=limit))
    assert result.truncated and result.envelope.ok and result.envelope.next_cursor
    first_count = sum(group.occurrence_count_in_coverage for group in result.envelope.groups)
    assert first_count == 1
    rest = subject.call("errors", {**args, "cursor": result.envelope.next_cursor}).envelope
    assert rest.ok
    assert first_count + sum(group.occurrence_count_in_coverage for group in rest.groups) == 80


def test_partial_deadline_returns_complete_redacted_units_and_advancing_cursor(monkeypatch):
    subject = engine(b"hit\n" * 300)
    subject.prepare("web")
    now = [0.0]
    budget = ReadBudget(clock=lambda: now[0])
    from dev_logs_mcp.reader import VerifiedWindow

    original = VerifiedWindow.lines
    calls = [0]

    def stop_after_some(window, *args, **kwargs):
        rows = original(window, *args, **kwargs)
        calls[0] += 1
        if calls[0] == 4:
            now[0] = 6.0
        return rows

    monkeypatch.setattr(VerifiedWindow, "lines", stop_after_some)
    page = subject.call(
        "search", {"source_id": "web", "pattern": "hit", "context": 0}, budget=budget
    ).envelope
    assert page.ok and page.matches and page.next_cursor
    assert page.truncation.input_window and not page.coverage.complete


def test_explicit_prepare_retries_at_most_twice_and_closes_each_handle(monkeypatch):
    subject = engine(b"line\n")
    calls = []

    def unstable(*args, **kwargs):
        calls.append(1)
        raise ReadFailure("SOURCE_CHANGED")

    monkeypatch.setattr("dev_logs_mcp.query.prepare_index", unstable)
    with pytest.raises(ReadFailure):
        subject.prepare("web")
    assert len(calls) == 2 and subject.catalog.closed == subject.catalog.opened == 2


def test_large_changed_generation_returns_stale_no_evidence():
    subject = engine(b"line\n")
    subject.prepare("web")
    subject.catalog.size_override = 7 * 1024 * 1024
    subject.catalog.version += 1
    page = subject.call("tail", {"source_id": "web"}).envelope
    assert not page.ok and page.error.code == "INDEX_STALE" and not page.lines


def test_configured_custom_detector_is_enabled_before_search_and_defaults_remain():
    from dev_logs_mcp.shared.mcpkit.redact import CustomRule

    catalog = FakeCatalog(b"TICKET_12345 password=synthetic-password\n")
    catalog.custom_rules = (CustomRule("BUSINESS_ID", r"TICKET_[0-9]+"),)
    subject = LogEngine(catalog)
    args = {"source_id": "web", "pattern": "TICKET_12345", "context": 0}
    assert subject.call("search", args).envelope.matches == []
    page = subject.call("read_range", {"source_id": "web", "start_line": 1, "end_line": 1}).envelope
    assert page.ok and "BUSINESS_ID" in page.lines[0].text
    assert "synthetic-password" not in page.model_dump_json()


def test_single_oversize_wire_unit_is_explicit_error_not_nonprogress_cursor():
    subject = engine(b"hit " + b"x" * 20000 + b"\n")
    result = subject.call("search", {"source_id": "web", "pattern": "hit", "context": 0}).render(1)
    assert not result.envelope.ok and result.envelope.error.code == "LIMIT_EXCEEDED"
    assert result.envelope.next_cursor is None


@pytest.mark.parametrize(
    "tool,args",
    [
        ("unknown", {}),
        ("tail", {"source_id": "web", "lines": True}),
        ("read_range", {"source_id": "unknown", "start_line": 1, "end_line": 1}),
        ("search", {"source_id": "web", "pattern": "(?=private-marker)"}),
    ],
)
def test_failures_are_sanitized(tool, args):
    subject = engine(b"private-marker\n")
    result = subject.call(tool, args).envelope
    assert not result.ok and "private-marker" not in result.model_dump_json()
