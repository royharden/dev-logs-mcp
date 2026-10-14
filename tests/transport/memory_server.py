"""TEST ONLY: real SDK stdio with explicit in-memory synthetic storage.

Not configured-file authorization or native filesystem evidence. No product CLI
flag can choose this catalog. No environment/configuration data is consumed.
"""

import sys
from pathlib import Path

import anyio

sys.path.insert(0, str(Path(__file__).parents[2]))
from dev_logs_mcp.query import LogEngine
from dev_logs_mcp.server import serve
from tests.test_query import FakeCatalog

data = b"2026-01-01T00:00:00Z ERROR failed password=" + b"synthetic-sentinel" + b"\n  trace\n"
anyio.run(serve, LogEngine(FakeCatalog(data)))
