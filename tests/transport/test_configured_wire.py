"""Real SDK stdio bytes over synthetic memory, not native source authorization."""

import json
import sys
from pathlib import Path

import pytest

from tests.transport.wire_client import WireClient


@pytest.mark.parametrize("modern", [False, True], ids=["legacy", "modern"])
def test_real_sdk_wire_enforces_tool_limits_without_shrinking_catalog(modern, record_property):
    """what_bug_this_catches: final SDK serialization must honor explicit tool limits."""
    with WireClient(
        [sys.executable, str(Path(__file__).with_name("limited_memory_server.py"))], modern=modern
    ) as wire:
        wire.handshake()
        raw, catalog = wire.request(2, "tools/list", {})
        assert len(catalog["result"]["tools"]) == 5
        assert 8192 < len(raw) <= 32768  # Explicit catalog/control versus tool-result ceilings.
        operations = {
            "list_sources": {},
            "tail": {"source_id": "web"},
            "search": {"source_id": "web", "pattern": "evidence", "context": 0},
            "read_range": {"source_id": "web", "start_line": 1, "end_line": 100},
            "errors": {"source_id": "web"},
        }
        for request_id, (name, arguments) in enumerate(operations.items(), 3):
            raw, frame = wire.request(
                request_id, "tools/call", {"name": name, "arguments": arguments}
            )
            assert len(raw) <= 8192 and "error" not in frame
            result = frame["result"]
            envelope = result["structuredContent"]
            assert envelope["ok"] and result.get("isError", False) is False
            assert json.loads(result["content"][0]["text"]) == envelope
            physical = {row["line_no"] for row in envelope.get("lines", [])}
            physical.update(row["line_no"] for row in envelope.get("matches", []))
            for group in envelope.get("groups", []):
                physical.add(group["first_in_coverage"]["line_no"])
                physical.update(row["line_no"] for row in group["trace"])
            assert len(physical) <= 3 and envelope["coverage"]["bytes_read"] <= 2 * 1024 * 1024
        raw, unknown = wire.request(
            8, "tools/call", {"name": "tail", "arguments": {"source_id": "unknown"}}
        )
        assert (
            len(raw) <= 8192
            and unknown["result"]["structuredContent"]["error"]["code"] == "UNKNOWN_SOURCE"
        )
        # Worst escaping inside an otherwise bounded request ID must also fit real SDK output.
        raw, escaped = wire.request(
            "z\n" * 128, "tools/call", {"name": "tail", "arguments": {"source_id": "web"}}
        )
        assert len(raw) <= 8192 and escaped["result"]["structuredContent"]["ok"]
        raw, invalid = wire.request(
            9, "tools/call", {"name": "tail", "arguments": {"source_id": "web", "lines": True}}
        )
        assert len(raw) <= 8192 and invalid["error"]["code"] == -32602
        assert "data" not in invalid["error"]
        assert b"synthetic-limit-canary" not in b"".join(wire.captures)
        record_property("scope", "real SDK captured stdio; explicit synthetic-memory catalog")
        record_property("captured_frames", len(wire.captures))
        record_property("largest_frame_bytes", max(map(len, wire.captures)))
        record_property("tool_frame_ceiling", 8192)
        record_property("catalog_control_ceiling", 32768)
