"""Real configured Linux file/stdio limits; no Windows or whole-process I/O claim."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dev_logs_mcp.config import AppConfig, ToolLimits
from dev_logs_mcp.index import PrivateIndexCache, ReadBudget
from dev_logs_mcp.query import LogEngine
from dev_logs_mcp.shared.mcpkit.safe_path import AuthorizedReadHandle
from dev_logs_mcp.sources import SourceCatalog
from tests.transport.wire_client import WireClient

pytestmark = pytest.mark.skipif(os.name != "posix", reason="required configured-file Linux profile")


def configuration(root, limits):
    return AppConfig.model_validate(
        {
            "allowed_roots": [str(root)],
            "sources": [{"id": "web", "path": str(root / "web.log")}],
            "tool_limits": limits.model_dump(),
        }
    )


def test_native_lower_read_cap_and_mutation_control(tmp_path, monkeypatch, record_property):
    """what_bug_this_catches: removing configured read admission must fail the same oracle."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "web.log").write_text("2026-01-01T00:00:00Z INFO evidence\n" * 500)
    limits = ToolLimits(read_bytes=128, lines=3, frame_bytes=8192, seconds=1.0)
    subject = LogEngine(SourceCatalog(configuration(root, limits), tmp_path))
    original = AuthorizedReadHandle.read
    reads = []

    def counted(handle, size):
        body = original(handle, size)
        reads.append(len(body))
        return body

    monkeypatch.setattr(AuthorizedReadHandle, "read", counted)
    baseline = subject.call("tail", {"source_id": "web"}).render(1)
    assert not baseline.envelope.ok and sum(reads) == 0
    assert len(baseline.wire_bytes) <= 8192
    # Change only the in-process configured-read admission; containment stays real.
    subject.tool_limits = limits.model_copy(update={"read_bytes": 8388608})
    mutant = subject.call("tail", {"source_id": "web"}).render(1)
    assert mutant.envelope.ok and sum(reads) > 128
    record_property("scope", "native authorized-file reads; configured inprocess engine guard only")
    record_property("baseline_source_body_bytes", 0)
    record_property("mutant_source_body_bytes", sum(reads))


def test_native_limit_config_binds_cache_generation_and_cursor(tmp_path):
    """what_bug_this_catches: changing limits cannot reuse an old namespace or cursor binding."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "web.log").write_text("2026-01-01T00:00:00Z INFO evidence\n" * 40)
    cache_path = tmp_path / "cache"
    cache_path.mkdir(mode=0o700)
    cache = PrivateIndexCache(cache_path)
    before_catalog = SourceCatalog(configuration(root, ToolLimits()), tmp_path)
    after_catalog = SourceCatalog(
        configuration(root, ToolLimits(read_bytes=2097152, seconds=1.0)), tmp_path
    )
    before = LogEngine(before_catalog, cache=cache)
    before_index = before.prepare("web")
    page = before.call(
        "search", {"source_id": "web", "pattern": "evidence", "max_matches": 1, "context": 0}
    )
    assert page.envelope.next_cursor
    assert cache.load("web", after_catalog.config_hash, ReadBudget()) is None
    after = LogEngine(after_catalog, cache=cache)
    # Test-only equal key: rejection must still follow changed configuration binding.
    after.cursors = before.cursors
    current = after.call("search", {"source_id": "web", "pattern": "evidence", "context": 0})
    assert current.envelope.ok and current.envelope.generation_id != before_index.generation_id
    refused = after.call(
        "search",
        {
            "source_id": "web",
            "pattern": "evidence",
            "max_matches": 1,
            "context": 0,
            "cursor": page.envelope.next_cursor,
        },
    )
    assert not refused.envelope.ok and refused.envelope.error.code.value == "INVALID_CURSOR"


@pytest.mark.parametrize("kind", ["plain_iso", "jsonl"])
def test_native_configured_cli_five_tools_captured_wire(tmp_path, kind, record_property):
    """what_bug_this_catches: CLI configuration must reach engine, renderer and final SDK wire."""
    root = tmp_path / "logs"
    root.mkdir()
    message = "evidence password=synthetic-native-limit-canary " + "x" * 500
    if kind == "jsonl":
        line = json.dumps(
            {"timestamp": "2026-01-01T00:00:00Z", "level": "ERROR", "message": message}
        )
    else:
        line = "2026-01-01T00:00:00Z ERROR " + message
    (root / "web.log").write_text((line + "\n") * 100)
    config = tmp_path / "sources.toml"
    config.write_text(
        'allowed_roots=["logs"]\n[[sources]]\nid="web"\npath="logs/web.log"\n'
        f'format="{kind}"\n[tool_limits]\nread_bytes=2097152\nlines=3\n'
        "frame_bytes=8192\nseconds=1.0\n"
    )
    with WireClient([sys.executable, "-m", "dev_logs_mcp", "serve", str(config)]) as wire:
        wire.handshake()
        catalog_raw, catalog = wire.request(2, "tools/list", {})
        assert len(catalog["result"]["tools"]) == 5 and 8192 < len(catalog_raw) <= 32768
        operations = {
            "list_sources": {},
            "tail": {"source_id": "web"},
            "search": {"source_id": "web", "pattern": "evidence", "context": 0},
            "read_range": {"source_id": "web", "start_line": 1, "end_line": 100},
            "errors": {"source_id": "web"},
        }
        tool_frames = []
        for request_id, (tool, arguments) in enumerate(operations.items(), 3):
            raw, frame = wire.request(
                request_id, "tools/call", {"name": tool, "arguments": arguments}
            )
            assert len(raw) <= 8192 and "error" not in frame
            result = frame["result"]
            envelope = result["structuredContent"]
            assert envelope["ok"] and not result.get("isError", False)
            assert json.loads(result["content"][0]["text"]) == envelope
            physical = {row["line_no"] for row in envelope.get("lines", [])}
            physical.update(row["line_no"] for row in envelope.get("matches", []))
            for group in envelope.get("groups", []):
                physical.add(group["first_in_coverage"]["line_no"])
                physical.update(row["line_no"] for row in group["trace"])
            assert len(physical) <= 3 and envelope["coverage"]["bytes_read"] <= 2097152
            tool_frames.append(len(raw))
        raw, refused = wire.request(
            8, "tools/call", {"name": "tail", "arguments": {"source_id": "unknown"}}
        )
        assert (
            len(raw) <= 8192
            and refused["result"]["structuredContent"]["error"]["code"] == "UNKNOWN_SOURCE"
        )
        assert b"synthetic-native-limit-canary" not in b"".join(wire.captures)
        record_property(
            "scope", "native configured synthetic file; actual captured modern SDK stdio"
        )
        record_property("format", kind)
        record_property("five_tool_frame_bytes", json.dumps(tool_frames))
        record_property("catalog_frame_bytes", len(catalog_raw))


def test_native_small_benchmark_emits_final_workload_snapshot(tmp_path):
    """what_bug_this_catches: later sweeps must not be omitted from final memory sampling."""
    output = tmp_path / "small-benchmark.jsonl"
    script = Path(__file__).resolve().parents[2] / "scripts/bench.py"
    run = subprocess.run(
        [
            sys.executable,
            str(script),
            "--size-bytes",
            "65536",
            "--repeats",
            "1",
            "--max-seconds",
            "30",
            "--output",
            str(output),
        ],
        capture_output=True,
        timeout=40,
    )
    assert run.returncode == 0
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    final = rows[-1]
    assert final["phase"] == "result" and final["status"] == "completed_observations"
    assert not final["required_size_and_repeats"] and not final["qualification"]
    assert len([row for row in rows if row["phase"] == "warm_call"]) == 20
    assert len([row for row in rows if row["phase"] == "full_source_sweep"]) == 4
    snapshot = final["final_workload_observation"]
    assert snapshot["peak_rss_bytes"] > 0
    if snapshot["process_io"] is None:
        assert snapshot["process_io_unavailable"]["reason"]
    assert "After all benchmark workloads" in final["final_snapshot_scope"]
