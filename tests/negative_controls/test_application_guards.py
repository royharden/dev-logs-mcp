"""Mutate real application guards over native synthetic files, never fabricated frames.

These are in-process application results serialized by the real renderer, not
captured SDK stdio. Unknown-ID controls do not disable root containment, and the
read control uses a reduced per-call budget, not a whole-process 8-MiB benchmark.
"""

import asyncio
import json
import os

import pytest

from dev_logs_mcp.config import AppConfig
from dev_logs_mcp.index import ReadBudget
from dev_logs_mcp.query import LogEngine
from dev_logs_mcp.shared.mcpkit.bounded_output import OutputBudget
from dev_logs_mcp.shared.mcpkit.conformance.cases import Case, Observation
from dev_logs_mcp.shared.mcpkit.conformance.runner import run
from dev_logs_mcp.shared.mcpkit.errors import MAX_FRAME_BYTES, MAX_READ_BYTES
from dev_logs_mcp.shared.mcpkit.models import ToolEnvelope
from dev_logs_mcp.shared.mcpkit.redact import Redactor
from dev_logs_mcp.shared.mcpkit.safe_path import AuthorizedReadHandle
from dev_logs_mcp.sources import SourceCatalog

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="required native Linux application controls; Windows unavailable"
)


@pytest.mark.parametrize("guard", ["allowlist", "redaction", "frame_cap", "read_cap"])
def test_conformance_detects_actual_application_guard_sabotage(
    guard, tmp_path, monkeypatch, record_property
):
    """what_bug_this_catches: production guard removal must fail the unchanged oracle."""
    marker = "synthetic-" + "sabotage-password"
    text = (
        f"2026-01-01T00:00:00Z ERROR password={marker}\n"
        if guard == "redaction"
        else "2026-01-01T00:00:00Z INFO evidence " + "x" * 3900 + "\n"
    )
    root = tmp_path / "logs"
    root.mkdir()
    source = root / "web.log"
    source.write_text(text * (6 if guard == "frame_cap" else 2), encoding="utf-8")
    config = AppConfig.model_validate(
        {"allowed_roots": [str(root)], "sources": [{"id": "web", "path": str(source)}]}
    )
    subject = LogEngine(SourceCatalog(config, tmp_path), redactor=Redactor(b"n" * 32))
    subject.prepare("web")
    assert subject.call("tail", {"source_id": "web"}).envelope.ok

    actual_reads = []
    native_read = AuthorizedReadHandle.read

    def counted_read(handle, size):
        data = native_read(handle, size)
        actual_reads.append(len(data))
        return data

    monkeypatch.setattr(AuthorizedReadHandle, "read", counted_read)

    class NativeAdapter:
        platform = "posix"
        execution_kind = "native_platform"
        unavailable_capabilities = frozenset()

        async def call(self, tool, arguments):
            actual_reads.clear()
            budget = ReadBudget(4096 if guard == "read_cap" else MAX_READ_BYTES)
            result = subject.call(tool, arguments, budget=budget).render(1)
            return Observation(
                frame=result.wire_bytes,
                frame_origin="adapter_serialization",
                request_id=1,
                measured_read_bytes=sum(actual_reads),
            )

    case = Case(
        case_id=f"application_{guard}",
        tool="tail",
        arguments={"source_id": "unknown" if guard == "allowlist" else "web"},
        expect_error=(
            "UNKNOWN_SOURCE"
            if guard == "allowlist"
            else "LIMIT_EXCEEDED"
            if guard == "read_cap"
            else None
        ),
        forbidden_literals=(marker,),
        require_native=True,
        require_measured_reads=True,
        max_read_bytes=4096 if guard == "read_cap" else MAX_READ_BYTES,
        what_bug_this_catches=f"actual application {guard} removal must fail unchanged conformance",
    )

    def validate(_case, envelope):
        ToolEnvelope.model_validate_json(json.dumps(envelope))

    baseline = asyncio.run(run(NativeAdapter(), (case,), validate))
    assert baseline.complete_pass, baseline.model_dump_json()
    with monkeypatch.context() as sabotage:
        if guard == "allowlist":
            configured = subject.catalog.get("web")
            sabotage.setattr(subject.catalog, "get", lambda _source_id: configured)
        elif guard == "redaction":
            # Disable actual default detectors; keep parser/rendering/search unchanged.
            sabotage.setattr(subject.redactor, "_Redactor__rules", ())
        elif guard == "frame_cap":
            original = OutputBudget._wire

            def uncapped_wire(budget, envelope, request_id):
                prior = budget.max_wire_bytes
                budget.max_wire_bytes = 2 * MAX_FRAME_BYTES
                try:
                    return original(budget, envelope, request_id)
                finally:
                    budget.max_wire_bytes = prior

            sabotage.setattr(OutputBudget, "_wire", uncapped_wire)
        else:
            # Remove the actual remaining-byte reservation/read guard. Native
            # handle accounting remains outside the mutated ReadBudget counter.
            sabotage.setattr(ReadBudget, "remaining", property(lambda _budget: MAX_READ_BYTES))
        mutated = asyncio.run(run(NativeAdapter(), (case,), validate))

    expected_reason = {
        "allowlist": "unexpected_status",
        "redaction": "private_marker_leaked",
        "frame_cap": "frame_limit",
        "read_cap": "read_limit",
    }[guard]
    assert mutated.counts["failed"] == 1 and not mutated.complete_pass
    assert mutated.results[0].reason == expected_reason, mutated.model_dump_json()
    assert marker not in baseline.model_dump_json() + mutated.model_dump_json()
    record_property("what_bug_this_catches", case.what_bug_this_catches)
    record_property("baseline", baseline.model_dump_json())
    record_property("sabotaged", mutated.model_dump_json())
    record_property("scope", "native configured file; actual app mutation; adapter serialization")
