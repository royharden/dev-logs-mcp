"""Exercise the real configured-file stdio server with temporary synthetic logs.

Mock means generated inputs and no model calls. It never substitutes the source
catalog, filesystem policy, query engine or transport. Exit 3 retains a required
platform limitation; it is not a successful normal journey.
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

from dev_logs_mcp.shared.mcpkit.errors import MAX_FRAME_BYTES, MAX_LINES, MAX_READ_BYTES
from dev_logs_mcp.shared.mcpkit.models import ToolEnvelope

REPO = Path(__file__).resolve().parents[1]
PLACEHOLDER = re.compile(r"\[BEARER:[0-9]+:[0-9a-f]{4}\]")
TOOLS = {"list_sources", "tail", "search", "read_range", "errors"}


class DemoFailure(ValueError):
    """Only fixed, value-free diagnostics may leave this workflow."""


def failure_codes(error: BaseException) -> list[str]:
    if isinstance(error, BaseExceptionGroup):
        return [code for child in error.exceptions for code in failure_codes(child)]
    if isinstance(error, DemoFailure):
        return [str(error)]
    return [type(error).__name__]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DemoFailure(message)


def generate(root: Path) -> tuple[Path, str]:
    logs = root / "logs"
    logs.mkdir()
    # Synthetic shapes are assembled at runtime and never written to reports.
    secret = "".join(("synthetic", "_", "demo", "_", "sentinel", "_", "123456789"))
    for source, suffix in (("plain", ".log"), ("jsonl", ".jsonl")):
        messages = [
            ("INFO", "DEMO_STARTED"),
            ("ERROR", f"DEMO_DATABASE_FAILURE Authorization: Bearer {secret}"),
            ("ERROR", "DEMO_STACK database.py line 7"),
            *(("INFO", f"DEMO_PADDING {number:04d}") for number in range(520)),
        ]
        rows = []
        for level, message in messages:
            if source == "jsonl":
                rows.append(
                    json.dumps(
                        {"timestamp": "2026-01-01T00:00:00Z", "level": level, "message": message}
                    )
                )
            else:
                rows.append(f"2026-01-01T00:00:00Z {level} {message}")
        (logs / f"{source}{suffix}").write_text("\n".join(rows) + "\n", encoding="utf-8")
    config = root / "sources.toml"
    config.write_text(
        'allowed_roots=["logs"]\n'
        '[[sources]]\nid="plain"\npath="logs/plain.log"\nformat="plain_iso"\n'
        '[[sources]]\nid="jsonl"\npath="logs/jsonl.jsonl"\nformat="jsonl"\n',
        encoding="utf-8",
    )
    return config, secret


def validate_result(result, secret: str) -> tuple[dict, int]:
    """Validate both actual SDK channels; never include failed payloads in errors."""
    serialized = result.model_dump_json(by_alias=True, exclude_none=True)
    require(secret not in serialized, "Raw synthetic secret reached a tool response")
    result_bytes = len(serialized.encode("utf-8"))
    require(result_bytes < MAX_FRAME_BYTES, "Tool result exceeds response ceiling")
    payload = result.structured_content
    require(isinstance(payload, dict), "Structured result is missing")
    # Transport dictionaries carry JSON enum strings, not Python Enum instances.
    ToolEnvelope.model_validate_json(json.dumps(payload))
    require(len(result.content) == 1, "Expected one compatible text channel")
    require(json.loads(result.content[0].text) == payload, "Response channels disagree")
    require(result.is_error == (not payload["ok"]), "Error status disagrees")
    require(len(payload.get("lines", [])) <= MAX_LINES, "Physical line ceiling exceeded")
    require(payload["coverage"]["bytes_read"] <= MAX_READ_BYTES, "Read ceiling exceeded")
    return payload, result_bytes


def outside_root_refusal(root: Path, secret: str) -> dict:
    (root / "outside.log").write_text(secret, encoding="utf-8")
    config = root / "forbidden.toml"
    config.write_text(
        'allowed_roots=["logs"]\n[[sources]]\nid="outside"\npath="outside.log"\n',
        encoding="utf-8",
    )
    process = subprocess.run(
        [sys.executable, "-m", "dev_logs_mcp", "serve", str(config)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
        check=False,
    )
    output = process.stdout + process.stderr
    require(secret.encode() not in output, "Outside-root body reached diagnostics")
    require(
        process.returncode == 2 and not process.stdout,
        "Outside-root configuration did not refuse before transport",
    )
    require(
        process.stderr.startswith(b"CONFIG_INVALID:"),
        "Outside-root refusal has an unexpected diagnostic",
    )
    return {"check": "outside_root_configuration", "refused": True, "code": "CONFIG_INVALID"}


def initial_report() -> dict:
    return {
        "schema_version": 1,
        "mode": "mock",
        "transport": "real_cli_stdio",
        "sources": "generated_plain_and_jsonl",
        "model_calls": 0,
        "normal_journey": "pending",
        "checks": [],
        "calls": [],
        "required_failures": [],
        "limits": [
            "Result sizes exclude the JSON-RPC wrapper; full-wire guards have separate tests.",
            "Synthetic demonstration is not platform qualification or release acceptance.",
        ],
    }


async def exercise(root: Path, report: dict) -> dict:
    config, secret = generate(root)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "dev_logs_mcp", "serve", str(config)],
    )
    failures = report["required_failures"]
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
        async with stdio_client(params, errlog=stderr) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=15) as client:
                await client.initialize()
                catalog = await client.list_tools()
                require(
                    {tool.name for tool in catalog.tools} == TOOLS,
                    "Actual catalog does not contain the five required tools",
                )

                async def call(name: str, arguments: dict) -> dict:
                    result = await client.call_tool(name, arguments)
                    payload, result_bytes = validate_result(result, secret)
                    report["calls"].append(
                        {
                            "tool": name,
                            "source_id": arguments.get("source_id"),
                            "ok": payload["ok"],
                            "result_bytes": result_bytes,
                            "bytes_read": payload["coverage"]["bytes_read"],
                            "returned_lines": len(payload.get("lines", [])),
                            "error_code": payload.get("error", {}).get("code"),
                        }
                    )
                    return payload

                listed = await call("list_sources", {})
                require(
                    listed["ok"] and {s["id"] for s in listed["sources"]} == {"plain", "jsonl"},
                    "Configured sources were not listed",
                )
                for source in ("plain", "jsonl"):
                    responses = {}
                    for name, arguments in (
                        ("errors", {}),
                        ("search", {"pattern": "DEMO_DATABASE_FAILURE", "context": 1}),
                        ("read_range", {"start_line": 2, "end_line": 3}),
                        ("tail", {"lines": 500}),
                    ):
                        responses[name] = await call(name, {"source_id": source, **arguments})
                        if not responses[name]["ok"]:
                            failures.append(responses[name]["error"]["code"])
                    if any(not response["ok"] for response in responses.values()):
                        continue
                    for name in ("errors", "search", "read_range"):
                        require(
                            "DEMO_DATABASE_FAILURE" in json.dumps(responses[name]),
                            "Planted incident was not located",
                        )
                    signatures = [
                        set(PLACEHOLDER.findall(json.dumps(responses[name])))
                        for name in ("errors", "search", "read_range")
                    ]
                    require(
                        len(signatures[0]) == 1 and all(s == signatures[0] for s in signatures),
                        "Stable redaction differs across tools",
                    )
                    require(
                        responses["search"]["matches"][0]["line_no"] == 2,
                        "Search evidence lost its physical coordinate",
                    )
                    require(
                        responses["read_range"]["lines"][0]["line_no"] == 2,
                        "Range evidence lost its physical coordinate",
                    )
                    suffix = ".log" if source == "plain" else ".jsonl"
                    appended = "2026-01-01T00:00:01Z INFO DEMO_REFRESHED\n"
                    if source == "jsonl":
                        appended = (
                            json.dumps(
                                {
                                    "timestamp": "2026-01-01T00:00:01Z",
                                    "level": "INFO",
                                    "message": "DEMO_REFRESHED",
                                }
                            )
                            + "\n"
                        )
                    with (root / "logs" / f"{source}{suffix}").open("a", encoding="utf-8") as log:
                        log.write(appended)
                    refreshed = await call("tail", {"source_id": source, "lines": 1})
                    require(
                        refreshed["ok"]
                        and len(refreshed["lines"]) == 1
                        and "DEMO_REFRESHED" in refreshed["lines"][0]["text"],
                        "Tail did not refresh the appended generation",
                    )
                    require(
                        refreshed["generation_id"] != responses["tail"]["generation_id"],
                        "Append did not invalidate the prior generation",
                    )
                    report["checks"].append(
                        {
                            "source": source,
                            "incident_line": 2,
                            "stable_redaction": True,
                            "tail_refresh": True,
                        }
                    )
                unknown = await call("tail", {"source_id": "not_configured"})
                require(
                    not unknown["ok"] and unknown["error"]["code"] == "UNKNOWN_SOURCE",
                    "Unknown source did not refuse",
                )
                report["checks"].append(
                    {"check": "unknown_source", "refused": True, "code": "UNKNOWN_SOURCE"}
                )
        stderr.seek(0)
        require(secret not in stderr.read(), "Raw synthetic secret reached server stderr")
    report["checks"].append(outside_root_refusal(root, secret))
    report["required_failures"] = sorted(set(failures))
    report["normal_journey"] = "passed" if not failures else "failed"
    report["status"] = "passed" if not failures else "required_failure"
    if os.name == "nt" and failures and set(failures) == {"SOURCE_NOT_LOCAL"}:
        report["status"] = "unsupported_required"
        report["limits"].append("Windows data/no-recall remains closed and unqualified.")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["mock"], default="mock")
    parser.parse_args()
    report = initial_report()
    generated = REPO / "fixtures" / "generated" / "demos"
    try:
        generated.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="stdio-", dir=generated) as directory:
            report = asyncio.run(exercise(Path(directory), report))
    except Exception as error:
        # SDK exception groups/validation reprs may contain raw tool data.
        report.update(
            status="failed",
            normal_journey="failed",
            error="Configured-source demo could not complete safely",
            failure_codes=failure_codes(error),
        )
        print(json.dumps(report, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 3


if __name__ == "__main__":
    raise SystemExit(main())
