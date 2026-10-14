"""Memory storage windows; not Windows OS tests despite the window-oriented name."""

import pytest

from dev_logs_mcp.index import ReadBudget, ReadFailure
from dev_logs_mcp.reader import VerifiedWindow
from tests.index.test_generation import make_index


def test_exact_utf8_crlf_coordinates_and_redaction_before_query():
    data = "2026-01-01T00:00:00Z ERROR échec\r\n  trace password=sentinel-control\n".encode()
    handle, index, redactor, _ = make_index(data)
    budget = ReadBudget()
    lines = VerifiedWindow(handle, index, budget).lines(1, 2, redactor)
    assert lines[1].line.byte_offset == len(data.splitlines(keepends=True)[0])
    assert lines[1].line.line_no == 2 and lines[1].line.level_inherited
    assert "sentinel-control" not in lines[1].line.text
    assert lines[0].line.text.endswith("échec")
    assert budget.bytes_read == len(data)


def test_checkpoint_continuation_and_pem_state_arbitrary_window():
    """what_bug_this_catches: a range inside a long key must not expose its body."""
    data = (
        b"2026-01-01T00:00:00Z ERROR root\n-----BEGIN PRIVATE KEY-----\n"
        + b"synthetic-body\n" * 600
        + b"-----END PRIVATE KEY-----\nnormal\n"
    )
    handle, index, redactor, _ = make_index(data)
    assert len(index.checkpoints) >= 3
    lines = VerifiedWindow(handle, index, ReadBudget()).lines(510, 605, redactor)
    assert "synthetic-body" not in repr([line.line for line in lines])
    assert lines[0].line.omitted == "private_key"
    assert lines[0].line.level == "ERROR" and lines[0].line.level_inherited
    assert lines[-1].line.text == "normal"


def test_overlong_body_omission_carries_pem_uncertainty_until_end():
    data = b"x" * 65537 + b"\nbody\n-----END PRIVATE KEY-----\nafter\n"
    handle, index, redactor, _ = make_index(data)
    lines = VerifiedWindow(handle, index, ReadBudget()).lines(1, 4, redactor)
    assert lines[0].line.omitted == "overlong_line"
    assert lines[1].line.omitted == "private_key"
    assert lines[-1].line.text == "after"


def test_guard_bytes_count_towards_same_budget_as_index_load():
    data = b"normal\n" * 100
    handle, index, redactor, _ = make_index(data)
    budget = ReadBudget(len(data) + 9)
    budget.charge(10)  # Simulated actual cache bytes already consumed by the caller.
    with pytest.raises(ReadFailure) as error:
        VerifiedWindow(handle, index, budget).lines(1, 1, redactor)
    assert error.value.code == "LIMIT_EXCEEDED" and budget.bytes_read == 10


def test_evidence_is_not_returned_after_final_generation_change():
    handle, index, redactor, _ = make_index(b"line\n")
    window = VerifiedWindow(handle, index, ReadBudget())
    window.lines(1, 1, redactor)
    handle.identity = type(handle.identity)(1, 99, 5, 3, 4)
    with pytest.raises(ReadFailure) as error:
        window.finish()
    assert error.value.code == "INDEX_STALE"


def test_range_rejects_boolean_and_excessive_lines_and_handles_eof():
    handle, index, redactor, _ = make_index(b"line\n")
    window = VerifiedWindow(handle, index, ReadBudget())
    for start, end in [(True, 1), (0, 1), (1, 501), (2, 1)]:
        with pytest.raises(ReadFailure):
            window.lines(start, end, redactor)
    assert window.lines(2, 3, redactor) == []


def test_window_memo_reuses_complete_rows_without_cross_pipeline_state(monkeypatch):
    handle, index, redactor, _ = make_index(b"normal\ntrace\n")
    window = VerifiedWindow(handle, index, ReadBudget())
    initial = window.lines(1, 2, redactor)
    calls = handle.calls

    def forbidden(*args, **kwargs):
        raise AssertionError("redacted row should be memoized")

    monkeypatch.setattr(redactor, "redact", forbidden)
    assert window.lines(2, 2, redactor) == initial[1:]
    assert handle.calls == calls
    with pytest.raises(ReadFailure):
        window.lines(2, 2, redactor, format="plain")


def test_window_memo_has_fixed_row_and_byte_bounds():
    handle, index, redactor, _ = make_index(b"normal\n" * 600)
    window = VerifiedWindow(handle, index, ReadBudget())
    window.lines(1, 500, redactor)
    window.lines(501, 600, redactor)
    assert len(window._memo) <= 512 and window._memo_bytes <= 2 * 1024 * 1024
