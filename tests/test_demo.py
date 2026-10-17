"""Real configured-file workflow must preserve platform failures and refusals."""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def demo_module(monkeypatch, tmp_path):
    path = Path(__file__).resolve().parents[1] / "scripts" / "demo.py"
    spec = importlib.util.spec_from_file_location("configured_demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "REPO", tmp_path)
    monkeypatch.setattr(sys, "argv", [str(path), "--mode", "mock"])
    return module


@pytest.mark.parametrize("failure", [TimeoutError, RuntimeError])
def test_demo_exception_report_keeps_workflow_context(demo_module, monkeypatch, capsys, failure):
    """what_bug_this_catches: initialization errors must not erase the demo report schema."""

    async def fail(_root, *_args):
        raise failure("synthetic-private-exception-body")

    monkeypatch.setattr(demo_module, "exercise", fail)
    assert demo_module.main() == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["schema_version"] == 1
    assert report["mode"] == "mock" and report["transport"] == "real_cli_stdio"
    assert report["sources"] == "generated_plain_and_jsonl" and report["model_calls"] == 0
    assert report["status"] == report["normal_journey"] == "failed"
    assert report["checks"] == report["calls"] == []
    assert report["failure_codes"] == [failure.__name__]
    assert report["limits"]
    assert "synthetic-private-exception-body" not in captured.out + captured.err


def test_demo_exception_report_keeps_completed_checks(demo_module, monkeypatch, capsys):
    """what_bug_this_catches: a later exception must retain observed calls and required failures."""
    call = {"tool": "tail", "ok": False, "error_code": "SOURCE_NOT_LOCAL"}
    check = {"check": "unknown_source", "refused": True, "code": "UNKNOWN_SOURCE"}

    async def fail(_root, report=None):
        if report is not None:
            report["calls"].append(call)
            report["checks"].append(check)
            report["required_failures"].append("SOURCE_NOT_LOCAL")
        raise ExceptionGroup("synthetic-private-group-body", [TimeoutError("private-child-body")])

    monkeypatch.setattr(demo_module, "exercise", fail)
    assert demo_module.main() == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["calls"] == [call] and report["checks"] == [check]
    assert report["required_failures"] == ["SOURCE_NOT_LOCAL"]
    assert report["status"] == report["normal_journey"] == "failed"
    assert report["failure_codes"] == ["TimeoutError"]
    assert "private-group-body" not in captured.out + captured.err
    assert "private-child-body" not in captured.out + captured.err


def test_demo_fixture_setup_error_keeps_failed_report(demo_module, monkeypatch, capsys):
    """what_bug_this_catches: fixture-directory setup failures must use the same safe report."""

    def fail(*_args, **_kwargs):
        raise OSError("synthetic-private-path")

    monkeypatch.setattr(demo_module.Path, "mkdir", fail)
    assert demo_module.main() == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["transport"] == "real_cli_stdio" and report["model_calls"] == 0
    assert report["status"] == report["normal_journey"] == "failed"
    assert report["failure_codes"] == ["OSError"]
    assert report["checks"] == report["calls"] == []
    assert "synthetic-private-path" not in captured.out + captured.err


@pytest.mark.parametrize(
    ("status", "normal_journey", "exit_code"),
    [
        ("passed", "passed", 0),
        ("unsupported_required", "failed", 3),
        ("required_failure", "failed", 3),
    ],
)
def test_demo_completed_report_keeps_exit_semantics(
    demo_module, monkeypatch, capsys, status, normal_journey, exit_code
):
    """what_bug_this_catches: reporting repair must never turn a native refusal into success."""
    observed = {
        "status": status,
        "normal_journey": normal_journey,
        "required_failures": [] if status == "passed" else ["SOURCE_NOT_LOCAL"],
    }

    async def complete(_root, *_args):
        return observed

    monkeypatch.setattr(demo_module, "exercise", complete)
    assert demo_module.main() == exit_code
    assert json.loads(capsys.readouterr().out) == observed


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
