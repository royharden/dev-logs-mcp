"""Real configured-file workflow must preserve platform failures and refusals."""

import json
import os
import subprocess
import sys
from pathlib import Path


def test_seeded_demo_uses_actual_cli_and_keeps_required_failures():
    """Catches reporting synthetic transport success while native reads fail."""
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "demo.py"), "--mode", "mock"],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    report = json.loads(result.stdout)
    assert report["transport"] == "real_cli_stdio"
    assert report["model_calls"] == 0
    assert {call["tool"] for call in report["calls"]} == {
        "list_sources",
        "tail",
        "search",
        "read_range",
        "errors",
    }
    assert {check.get("check") for check in report["checks"]} >= {
        "unknown_source",
        "outside_root_configuration",
    }
    assert all(call["result_bytes"] < 32768 for call in report["calls"])
    assert all(call["bytes_read"] <= 8 * 1024 * 1024 for call in report["calls"])
    if os.name == "nt":
        assert result.returncode == 3
        assert report["status"] == "unsupported_required"
        assert report["normal_journey"] == "failed"
        assert report["required_failures"] == ["SOURCE_NOT_LOCAL"]
        assert not any(check.get("stable_redaction") for check in report["checks"])
    else:
        assert result.returncode == 0
        assert report["status"] == report["normal_journey"] == "passed"
        assert {check.get("source") for check in report["checks"]} >= {"plain", "jsonl"}
    assert "sentinel_123456789" not in result.stdout + result.stderr
