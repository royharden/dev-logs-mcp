"""Small SDK/RE2 feasibility checks, not the product stdio conformance suite."""

import asyncio
import importlib.metadata

import re2
from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from dev_logs_mcp.contracts import TailRequest, ToolEnvelope


def test_locked_sdk_structured_contract_in_process():
    """Catch SDK class/schema/annotation drift before building product wiring."""
    assert importlib.metadata.version("mcp") == "2.3.0"
    server = MCPServer("contract-bootstrap")

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        )
    )
    def validate_tail(source_id: str, lines: int = 200) -> ToolEnvelope:
        """Validate a request without any filesystem access."""
        request = TailRequest(source_id=source_id, lines=lines)
        return ToolEnvelope(ok=True, source_id=request.source_id)

    async def exercise():
        tools = await server.list_tools()
        assert len(tools) == 1
        advertised = tools[0].model_dump(mode="json", by_alias=True, exclude_none=True)
        assert advertised["name"] == "validate_tail"
        assert advertised["annotations"]["readOnlyHint"] is True
        assert advertised["annotations"]["openWorldHint"] is False
        assert advertised["outputSchema"]["properties"]["schema_version"]["const"] == 1
        result = await server.call_tool("validate_tail", {"source_id": "web", "lines": 2})
        wire = result.model_dump(mode="json", by_alias=True, exclude_none=True)
        assert wire["structuredContent"]["source_id"] == "web"
        assert wire["structuredContent"]["content_trust"] == "untrusted_log_data"
        assert any(block["type"] == "text" for block in wire["content"])

    asyncio.run(exercise())


def test_re2_available_and_unsupported_pattern_refused():
    assert importlib.metadata.version("google-re2") == "1.1.20251105"
    options = re2.Options()
    options.log_errors = False
    options.max_mem = 1024 * 1024
    assert re2.compile("failure", options=options).search("synthetic failure")
    try:
        re2.compile(r"(x)\1", options=options)
    except re2.error:
        pass
    else:
        raise AssertionError("RE2 unexpectedly accepted an unsupported backreference")
