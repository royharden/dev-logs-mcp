"""Benchmark generator/measurement oracles, not 100-MB/native performance proof."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

from dev_logs_mcp.contracts import validate_request
from dev_logs_mcp.index import ReadFailure

SPEC = importlib.util.spec_from_file_location(
    "owned_bench", Path(__file__).resolve().parents[1] / "scripts/bench.py"
)
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


@pytest.mark.parametrize("kind", ["plain_iso", "jsonl"])
@pytest.mark.parametrize("size", [256, 1024, 2500])
def test_exact_size_generator_keeps_complete_physical_records(tmp_path, kind, size):
    """what_bug_this_catches: decimal byte counts cannot leave a partial JSONL tail."""
    path = tmp_path / "synthetic.log"
    manifest = bench.generate(path, kind, size)
    raw = path.read_bytes()
    assert len(raw) == manifest["bytes"] == size and raw.endswith(b"\n")
    assert len(raw.splitlines()) == manifest["lines"] == max(1, size // 1024)
    if kind == "jsonl":
        rows = [json.loads(line) for line in raw.splitlines()]
        assert all(row["timestamp"] == "2026-01-01T00:00:00Z" for row in rows)
        assert all(row["message"].startswith("bench event ") for row in rows)
    else:
        assert all(line.startswith(b"2026-01-01T00:00:00Z ") for line in raw.splitlines())
    with pytest.raises(FileExistsError):
        bench.generate(path, kind, size)


@pytest.mark.parametrize("args", [("other", 1, 1024), ("jsonl", 257, 10)])
def test_generator_refuses_unknown_or_truncated_record(args):
    with pytest.raises(ValueError):
        bench.record_bytes(*args)


def test_sparse_match_oracle_uses_physical_record_number():
    """what_bug_this_catches: equal aggregate counts cannot hide wrong line coordinates."""
    matched = json.loads(bench.record_bytes("jsonl", 97, 1024))
    other = json.loads(bench.record_bytes("jsonl", 98, 1024))
    assert "needle_hit" in matched["message"]
    assert "needle_hit" not in other["message"]


def test_failed_latency_samples_remain_in_percentiles_and_unknowns_stay_null():
    """what_bug_this_catches: dropping failed slow calls creates a false fast p95."""
    rows = [
        dict(duration_ms=duration, ok=ok, os_read_bytes=read, rendered_frame_bytes=frame)
        for duration, ok, read, frame in [
            (1, True, 3, 10),
            (2, True, 4, 20),
            (1000, False, 5, None),
        ]
    ]
    actual = bench.summary(rows)
    assert actual == dict(
        calls=3,
        failed=1,
        p50_ms_all_calls=2,
        p95_ms_all_calls=1000,
        max_os_read_bytes=5,
        max_rendered_frame_bytes=20,
    )
    assert bench.summary([]) == dict(
        calls=0,
        failed=0,
        p50_ms_all_calls=None,
        p95_ms_all_calls=None,
        max_os_read_bytes=None,
        max_rendered_frame_bytes=None,
    )


def test_actual_read_observer_restores_function_even_when_operation_fails():
    """what_bug_this_catches: instrumentation cannot leak into later app operations."""
    original = os.read
    reader, writer = os.pipe()
    try:
        os.write(writer, b"evidence")
        value, observation = bench.measure(lambda: os.read(reader, 8))
        assert value == b"evidence" and observation["os_read_bytes"] == 8
        assert observation["os_read_calls"] == 1 and os.read is original

        def refused():
            raise ReadFailure("SOURCE_CHANGED")

        value, observation = bench.measure(refused)
        assert value is None and observation["exception_code"] == "SOURCE_CHANGED"
        assert os.read is original
        with pytest.raises(ValueError), bench.observed_reads():
            raise ValueError("synthetic exception")
        assert os.read is original
    finally:
        os.close(reader)
        os.close(writer)


def test_process_io_unavailable_is_unknown_with_reason_not_zero(tmp_path):
    path = tmp_path / "owned-missing-io"
    counters, error = bench.process_io_counters(path)
    assert counters is None and error["reason"] == "FileNotFoundError"
    assert error["errno"] is not None
    path.write_text("rchar: malformed\n")
    counters, error = bench.process_io_counters(path)
    assert counters is None and error == {"reason": "ValueError", "errno": None}


def test_process_io_raw_zero_is_distinct_from_missing(tmp_path):
    path = tmp_path / "owned-io"
    path.write_text("rchar: 31\nwchar: 7\nread_bytes: 0\n")
    counters, error = bench.process_io_counters(path)
    assert counters == {"rchar": 31, "wchar": 7, "read_bytes": 0}
    assert error is None


def test_request_profiles_are_real_contracts_with_fixed_tools_identical():
    normal = bench.requests("default_request", 1000)
    maximum = bench.requests("maximum_request", 1000)
    assert set(normal) == set(maximum) == set(bench.TOOLS)
    for mapping in (normal, maximum):
        for tool, arguments in mapping.items():
            validate_request(tool, arguments)
    assert validate_request("tail", normal["tail"]).lines == 200
    assert maximum["tail"]["lines"] == 500
    assert maximum["read_range"]["end_line"] == 500
    assert validate_request("search", normal["search"]).context == 2
    assert maximum["search"]["context"] == 5
    assert normal["list_sources"] == maximum["list_sources"]
    assert normal["errors"] == maximum["errors"]
