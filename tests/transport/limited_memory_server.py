"""TEST ONLY: configured limits with actual SDK, explicit synthetic memory storage.

No product flag, environment switch, configured-file authorization or model call.
"""

import sys
from pathlib import Path

import anyio

sys.path.insert(0, str(Path(__file__).parents[2]))
from dev_logs_mcp.config import ToolLimits
from dev_logs_mcp.query import LogEngine
from dev_logs_mcp.server import serve
from tests.test_query import FakeCatalog

line = (
    b"2026-01-01T00:00:00Z ERROR evidence password="
    + b"synthetic-limit-canary "
    + b"x" * 500
    + b"\n"
)
catalog = FakeCatalog(line * 100)
catalog.tool_limits = ToolLimits(read_bytes=2 * 1024 * 1024, lines=3, frame_bytes=8192, seconds=1.0)
anyio.run(serve, LogEngine(catalog))
