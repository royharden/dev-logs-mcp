"""Real SDK transport controls; synthetic memory and native refusal are distinct."""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import Client, ClientSession, StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

from dev_logs_mcp.config import ToolLimits
from dev_logs_mcp.server import CallGate, exported_tools
from dev_logs_mcp.shared.mcpkit.tools_json import ANNOTATIONS


def test_actual_sdk_stdio_all_five_tools_with_explicit_synthetic_memory():
    async def exercise():
        params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).with_name("memory_server.py"))]
        )
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=30) as client:
                await client.initialize()
                tools = await client.list_tools()
                actual = [
                    tool.model_dump(
                        mode="json", by_alias=True, exclude_none=True, exclude_unset=True
                    )
                    for tool in tools.tools
                ]
                assert actual == exported_tools()
                assert all(item["annotations"] == ANNOTATIONS for item in actual)
                arguments = {
                    "list_sources": {},
                    "tail": {"source_id": "web"},
                    "search": {"source_id": "web", "pattern": "failed"},
                    "read_range": {"source_id": "web", "start_line": 1, "end_line": 2},
                    "errors": {"source_id": "web"},
                }
                for name, args in arguments.items():
                    result = await client.call_tool(name, args)
                    payload = result.structured_content
                    assert payload["ok"] and not result.is_error
                    assert payload["content_trust"] == "untrusted_log_data"
                    assert json.loads(result.content[0].text) == payload
                    assert "synthetic-sentinel" not in json.dumps(payload)
                concurrent = await asyncio.gather(
                    *(client.call_tool("tail", {"source_id": "web", "lines": 1}) for _ in range(20))
                )
                assert len(concurrent) == 20 and all(not result.is_error for result in concurrent)
                bad = await client.call_tool(
                    "search", {"source_id": "web", "pattern": "(?=private-marker)"}
                )
                assert bad.is_error and bad.structured_content["error"]["code"] == "INVALID_PATTERN"
                with pytest.raises(MCPError):
                    await client.call_tool("tail", {"source_id": "web", "lines": True})

    asyncio.run(exercise())


def test_actual_modern_sdk_stdio_fixed_result_metadata_and_five_tools():
    async def exercise():
        params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).with_name("memory_server.py"))]
        )
        async with Client(params, mode="2026-07-28", read_timeout_seconds=30, cache=None) as client:
            tools = await client.list_tools()
            assert len(tools.tools) == 5
            for name, args in {
                "list_sources": {},
                "tail": {"source_id": "web"},
                "search": {"source_id": "web", "pattern": "failed"},
                "read_range": {"source_id": "web", "start_line": 1, "end_line": 2},
                "errors": {"source_id": "web"},
            }.items():
                result = await client.call_tool(name, args)
                assert not result.is_error and result.structured_content["ok"]
                assert result.result_type == "complete"

    asyncio.run(exercise())


@pytest.mark.skipif(os.name != "nt", reason="Windows failclosed stdio check only")
def test_actual_windows_cli_stdio_refuses_data_without_fallback(tmp_path):
    (tmp_path / "synthetic.log").write_text("synthetic-content-must-not-be-read\n")
    config = tmp_path / "config.toml"
    config.write_text('allowed_roots=["."]\n[[sources]]\nid="web"\npath="synthetic.log"\n')

    async def exercise():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "dev_logs_mcp", "serve", str(config)]
        )
        async with stdio_client(params) as (reader, writer):
            # Cold `import mcp.server.stdio` was 14s before stdin is read, and
            # the whole test then took 44s to 57s. 15s flakes. 120s still fails a hang.
            async with ClientSession(reader, writer, read_timeout_seconds=120) as client:
                await client.initialize()
                listed = await client.call_tool("list_sources", {})
                assert listed.structured_content["sources"][0]["readable"] is False
                for name, args in {
                    "tail": {},
                    "search": {"pattern": "synthetic"},
                    "read_range": {"start_line": 1, "end_line": 1},
                    "errors": {},
                }.items():
                    result = await client.call_tool(name, {"source_id": "web", **args})
                    assert (
                        result.is_error
                        and result.structured_content["error"]["code"] == "SOURCE_NOT_LOCAL"
                    )
                    assert "synthetic-content-must-not-be-read" not in json.dumps(
                        result.structured_content
                    )

    asyncio.run(exercise())


def test_queue_four_active_sixteen_fifo_and_twenty_first_busy():
    async def exercise():
        gate = CallGate()
        release = asyncio.Event()
        admitted = []

        async def call(number):
            async with gate.enter():
                admitted.append(number)
                if number < 4:
                    await release.wait()

        jobs = [asyncio.create_task(call(number)) for number in range(20)]
        for _ in range(100):
            if gate.active == 4 and len(gate.queue) == 16:
                break
            await asyncio.sleep(0)
        assert gate.active == 4 and len(gate.queue) == 16
        from dev_logs_mcp.index import ReadFailure

        with pytest.raises(ReadFailure) as error:
            async with gate.enter():
                pass
        assert error.value.code == "BUSY"
        release.set()
        await asyncio.gather(*jobs)
        assert admitted == list(range(20)) and gate.active == 0 and not gate.queue

    asyncio.run(exercise())


def test_cancelled_queued_call_does_not_leak_ticket():
    async def exercise():
        gate = CallGate()
        release = asyncio.Event()

        async def call():
            async with gate.enter():
                await release.wait()

        active = [asyncio.create_task(call()) for _ in range(4)]
        for _ in range(20):
            await asyncio.sleep(0)
        queued = asyncio.create_task(call())
        for _ in range(20):
            await asyncio.sleep(0)
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
        assert len(gate.queue) == 0 and gate.active == 4
        release.set()
        await asyncio.gather(*active)
        assert gate.active == 0

    asyncio.run(exercise())


def test_queue_expiry_returns_busy_without_leaking_admission():
    from dev_logs_mcp.index import ReadFailure

    async def exercise():
        gate = CallGate(ToolLimits(seconds=0.02))
        release = asyncio.Event()

        async def held():
            async with gate.enter():
                await release.wait()

        jobs = [asyncio.create_task(held()) for _ in range(4)]
        for _ in range(20):
            await asyncio.sleep(0)
        with pytest.raises(ReadFailure) as error:
            async with gate.enter():
                pass
        assert error.value.code == "BUSY" and gate.active == 4 and not gate.queue
        release.set()
        await asyncio.gather(*jobs)

    asyncio.run(exercise())
