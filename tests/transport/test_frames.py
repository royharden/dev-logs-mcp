"""Exact final SDK serialization guards with bounded in-memory protocol buffers."""

import asyncio
import io
import json

import pytest

from dev_logs_mcp.server import MAX_INPUT_FRAME_BYTES, _BoundedInput, _BoundedOutput, exported_tools
from dev_logs_mcp.shared.mcpkit.bounded_output import ProtocolBudgetError


def emit(frame):
    output = io.BytesIO()

    async def exercise():
        writer = _BoundedOutput(output)
        await writer.write(json.dumps(frame, ensure_ascii=False, separators=(",", ":")) + "\n")
        await writer.flush()

    asyncio.run(exercise())
    return output.getvalue()


def test_complete_catalog_with_maximum_id_and_modern_stamp_fits_wire():
    frame = {
        "jsonrpc": "2.0",
        "id": "x" * 256,
        "result": {
            "tools": exported_tools(),
            "resultType": "complete",
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {"name": "dev-logs-mcp", "version": "0.1.0"}
            },
        },
    }
    raw = emit(frame)
    assert len(raw) <= 32768 and len(json.loads(raw)["result"]["tools"]) == 5


def test_exact_outgoing_guard_refuses_oversize_without_fragmenting_body():
    raw = emit({"jsonrpc": "2.0", "id": 1, "result": {"body": "sentinel" * 10000}})
    assert len(raw) <= 32768 and "error" in json.loads(raw)
    assert b"sentinel" not in raw


def test_protocol_errors_never_echo_sdk_validation_data_or_messages():
    raw = emit(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32602,
                "message": "private-marker",
                "data": {"raw": "private-marker"},
            },
        }
    )
    assert b"private-marker" not in raw and json.loads(raw)["error"]["code"] == -32602


def test_unbounded_id_is_closed_without_echoing():
    with pytest.raises(ProtocolBudgetError):
        emit({"jsonrpc": "2.0", "id": "x" * 257, "result": {}})


@pytest.mark.parametrize(
    "data",
    [b"x" * (MAX_INPUT_FRAME_BYTES + 1), b"{\xff}\n", b"missing-newline"],
    ids=["oversized-frame", "invalid-utf8", "unterminated-frame"],
)
def test_input_reader_is_bounded_and_uses_strict_utf8(data):
    async def exercise():
        with pytest.raises(ProtocolBudgetError):
            await _BoundedInput(io.BytesIO(data)).__anext__()

    asyncio.run(exercise())
