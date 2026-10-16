"""Fail-closed scanner controls; these fakes do not establish vendor integration."""

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/security_scan.py"
SPEC = importlib.util.spec_from_file_location("owned_security_scan", SCRIPT)
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


@dataclass
class FakeFinding:
    severity: str = "LOW"
    summary: str = "Synthetic finding"
    analyzer: str = "test"
    threat_category: str = "test"
    details: dict | None = None


class FakeAnalyzer:
    def __init__(self, name, *, raises=False, findings=False):
        self.name = name
        self.raises = raises
        self.findings = findings

    async def analyze(self, content, context=None):
        if self.raises:
            raise RuntimeError("synthetic failure")
        return [FakeFinding()] if self.findings else []


class CatchingStatic:
    """Reproduce the verified vendor behavior: caught errors still say completed."""

    def __init__(self, analyzer, *, skip_parameters=False):
        self.analyzer = analyzer
        self.skip_parameters = skip_parameters

    async def scan_tools_file(self, path):
        results = []
        for tool in json.loads(path.read_text())["tools"]:
            for part in ("description", "parameters"):
                if self.skip_parameters and part == "parameters":
                    continue
                try:
                    await self.analyzer.analyze(
                        "synthetic", {"tool_name": tool["name"], "content_type": part}
                    )
                except RuntimeError:
                    pass
            results.append({"tool_name": tool["name"], "status": "completed", "findings": []})
        return results


def tools():
    return [
        {"name": name, "description": "Synthetic tool", "inputSchema": {"type": "object"}}
        for name in sorted(scan.TOOL_NAMES)
    ]


def execute(tmp_path, *, raises=False, skip_parameters=False, findings=False):
    yara = scan.CountedAnalyzer(FakeAnalyzer("YARA", raises=raises))
    readiness = scan.CountedAnalyzer(FakeAnalyzer("READINESS", findings=findings))
    defense = scan.CountedAnalyzer(FakeAnalyzer("PromptDefense"))
    return asyncio.run(
        scan.candidate_scan(
            tools(),
            tmp_path / "input.json",
            CatchingStatic(yara, skip_parameters=skip_parameters),
            yara,
            readiness,
            defense,
        )
    )


def test_caught_analyzer_failure_cannot_report_scan_completed(tmp_path):
    """what_bug_this_catches: vendor completed labels must not hide analyzer exceptions."""
    with pytest.raises(scan.IncompleteScan, match="coverage is incomplete"):
        execute(tmp_path, raises=True)


def test_missing_parameter_coverage_is_incomplete(tmp_path):
    with pytest.raises(scan.IncompleteScan, match="coverage is incomplete"):
        execute(tmp_path, skip_parameters=True)


def test_findings_are_preserved_separately_from_completion(tmp_path):
    report = execute(tmp_path, findings=True)
    assert report["scan_completed"] and report["findings_require_disposition"]
    assert report["finding_count"] == 5
    assert [row["completed"] for row in report["coverage"]] == [10, 5, 5]
    assert {
        tool["name"] for tool in json.loads((tmp_path / "input.json").read_text())["tools"]
    } == scan.TOOL_NAMES


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "schema", "description"])
def test_incomplete_or_wrong_specification_refuses_before_scanner(mutation):
    data = tools()
    if mutation == "missing":
        data.pop()
    elif mutation == "duplicate":
        data[-1] = data[0]
    else:
        data[0]["inputSchema" if mutation == "schema" else "description"] = None
    with pytest.raises(scan.IncompleteScan):
        scan.load_tools(json.dumps(data).encode())


def test_offline_guard_rejects_network_and_process_before_os_action():
    code = (
        "import importlib.util,json,socket,subprocess,sys;"
        "s=importlib.util.spec_from_file_location('scan_guard',sys.argv[1]);"
        "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
        "events=m.install_offline_guard();"
        "\nfor action in [lambda: socket.create_connection(('127.0.0.1',9)),"
        "lambda: subprocess.Popen(['missing-executable'])]:"
        "\n try: action()"
        "\n except PermissionError: pass"
        "\n else: raise AssertionError('offline guard missed operation')"
        "\nprint(json.dumps(events))"
    )
    env = {
        key: os.environ[key]
        for key in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP")
        if key in os.environ
    }
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ["socket.getaddrinfo", "subprocess.Popen"]
