"""Actual in-memory query adapter; no native filesystem or captured SDK-wire proof."""

import asyncio
import json

from dev_logs_mcp.shared.mcpkit.conformance.cases import Case, Observation
from dev_logs_mcp.shared.mcpkit.conformance.runner import run
from dev_logs_mcp.shared.mcpkit.models import ToolEnvelope
from tests.test_query import engine


def test_five_tool_profile_and_private_marker_oracle():
    secret = "synthetic-" + "conformance-password"
    subject = engine(
        ("2026-01-01T00:00:00Z ERROR failure password=" + secret + "\n  trace\n").encode()
    )

    class Adapter:
        platform = "nt"
        execution_kind = "in_memory_synthetic"
        unavailable_capabilities = frozenset()

        async def call(self, name, arguments):
            return Observation(
                frame=subject.call(name, arguments).render(1).wire_bytes,
                frame_origin="adapter_serialization",
                request_id=1,
            )

    specs = (
        ("list", "list_sources", {}),
        ("tail", "tail", {"source_id": "web"}),
        ("search", "search", {"source_id": "web", "pattern": "failure"}),
        ("range", "read_range", {"source_id": "web", "start_line": 1, "end_line": 2}),
        ("errors", "errors", {"source_id": "web"}),
        ("secret_oracle", "search", {"source_id": "web", "pattern": secret}),
    )
    cases = tuple(
        Case(
            case_id=key,
            tool=name,
            arguments=args,
            forbidden_literals=(secret,),
            what_bug_this_catches="five-tool strict envelope, redaction and private-match oracle",
        )
        for key, name, args in specs
    )
    cases += (
        Case(
            case_id="unknown",
            tool="tail",
            arguments={"source_id": "unknown"},
            expect_error="UNKNOWN_SOURCE",
            what_bug_this_catches="configured IDs only",
        ),
        Case(
            case_id="boolean_limit",
            tool="tail",
            arguments={"source_id": "web", "lines": True},
            expect_error="INVALID_ARGUMENT",
            what_bug_this_catches="booleans are not line counts",
        ),
    )

    def validate(case, envelope):
        parsed = ToolEnvelope.model_validate_json(json.dumps(envelope))
        if case.case_id == "secret_oracle":
            assert not parsed.matches

    report = asyncio.run(run(Adapter(), cases, validate))
    assert report.complete_pass and report.counts["passed"] == 8
    assert secret not in report.model_dump_json()
