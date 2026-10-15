"""Portable runner controls; synthetic transport faults are not actual app mutations."""

import asyncio
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from dev_logs_mcp.shared.mcpkit.conformance import cases as case_module
from dev_logs_mcp.shared.mcpkit.conformance.cases import Case, Observation, Report, Result
from dev_logs_mcp.shared.mcpkit.conformance.runner import inspect, run


def case(**kwargs):
    return Case(
        case_id="synthetic",
        tool="tail",
        what_bug_this_catches="synthetic contract defect",
        **kwargs,
    )


def frame(envelope=None, **updates):
    envelope = {"ok": True} if envelope is None else envelope
    result = {
        "structuredContent": envelope,
        "content": [{"type": "text", "text": json.dumps(envelope)}],
        "isError": not envelope["ok"],
    }
    result.update(updates)
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()


def observation(raw=None, **kwargs):
    return Observation(
        frame=frame() if raw is None else raw, frame_origin="adapter_serialization", **kwargs
    )


def valid(_case, _value):
    pass


class Profile:
    platform = "nt"
    execution_kind = "in_memory_synthetic"
    unavailable_capabilities = frozenset()

    def __init__(self, value=None):
        self.value = observation() if value is None else value
        self.calls = 0

    async def call(self, tool, arguments):
        self.calls += 1
        return self.value


@pytest.mark.parametrize(
    "update",
    [
        {"max_read_bytes": True},
        {"max_frame_bytes": 32769},
        {"timeout_seconds": 6.0},
        {"platforms": ()},
        {"platforms": ("nt", "nt")},
        {"forbidden_literals": ("",)},
        {"expect_error": "BAD", "expect_protocol_error": -32602},
        {"arguments": {"text": "x" * 16384}},
    ],
    ids=[
        "bool-read",
        "frame-widen",
        "deadline-widen",
        "no-os",
        "duplicate-os",
        "empty-marker",
        "two-errors",
        "arg-cap",
    ],
)
def test_strict_case_cannot_relax_or_ambiguate_bounds(update):
    """what_bug_this_catches: caller-controlled case metadata cannot widen hard ceilings."""
    with pytest.raises((ValidationError, ValueError)):
        case(**update)


def test_empty_duplicate_or_all_nonapplicable_never_green():
    with pytest.raises(ValueError):
        asyncio.run(run(Profile(), (), valid))
    with pytest.raises(ValueError):
        asyncio.run(run(Profile(), (case(), case()), valid))
    report = asyncio.run(run(Profile(), (case(platforms=("posix",)),), valid))
    assert not report.complete_pass and report.counts["not_applicable"] == 1


@pytest.mark.parametrize("update", [{"require_native": True}, {"required_capability": "missing"}])
def test_missing_native_or_required_capability_is_not_skipped_to_green(update):
    profile = Profile()
    profile.unavailable_capabilities = frozenset({"missing"})
    report = asyncio.run(run(profile, (case(**update),), valid))
    assert report.counts["unsupported_required"] == 1 and not report.complete_pass
    assert profile.calls == 0


@pytest.mark.parametrize(
    "update", [{"require_captured_wire": True}, {"require_measured_reads": True}]
)
def test_adapter_serialization_and_missing_io_not_native_wire_or_read_proof(update):
    report = asyncio.run(run(Profile(), (case(**update),), valid))
    assert report.counts["unsupported_required"] == 1 and not report.complete_pass


@pytest.mark.parametrize("sabotage", ["allowlist", "redaction", "caps"])
def test_three_synthetic_sabotage_controls_are_detected(sabotage):
    """what_bug_this_catches: unsafe injected transport outputs must fail conformance."""
    secret = "synthetic-" + "private-marker"
    target = (
        case(expect_error="UNKNOWN_SOURCE")
        if sabotage == "allowlist"
        else case(forbidden_literals=(secret,))
    )
    raw = frame()
    if sabotage == "redaction":
        raw = frame({"ok": True, "text": secret})
    elif sabotage == "caps":
        raw += b" " * 32768
    report = asyncio.run(run(Profile(observation(raw)), (target,), valid))
    assert report.counts["failed"] == 1 and not report.complete_pass
    assert secret not in report.model_dump_json()


def test_measured_io_cap_and_unreported_exception_are_value_free():
    raw = observation(measured_read_bytes=8 * 1024 * 1024 + 1)
    assert inspect(case(), raw, valid) == "read_limit"

    class Broken(Profile):
        async def call(self, *args):
            raise ValueError("private-exception-marker")

    report = asyncio.run(run(Broken(), (case(),), valid))
    assert report.results[0].reason == "transport_failure"
    assert "private-exception-marker" not in report.model_dump_json()


@pytest.mark.parametrize(
    "mutation", ["mirror", "iserror", "missing", "utf16", "nonfinite", "idbool"]
)
def test_invalid_wire_or_mirror_or_status_fails(mutation):
    raw = frame()
    if mutation == "mirror":
        raw = frame(content=[{"type": "text", "text": "{}"}])
    elif mutation == "iserror":
        raw = frame(isError=True)
    elif mutation == "missing":
        raw = b'{"jsonrpc":"2.0","id":1}'
    elif mutation == "utf16":
        raw = raw.decode().encode("utf-16")
    elif mutation == "nonfinite":
        raw = frame({"ok": True, "measurement": float("nan")})
    elif mutation == "idbool":
        raw = raw.replace(b'"id": 1', b'"id": true')
    assert inspect(case(), observation(raw), valid) != "ok"


def test_protocol_domain_error_and_schema_failure_channels_distinct():
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "invalid"}}
    ).encode()
    assert inspect(case(expect_protocol_error=-32602), observation(raw), valid) == "ok"
    assert (
        inspect(case(expect_error="UNKNOWN_SOURCE"), observation(raw), valid)
        == "tool_result_missing"
    )
    raw = frame({"ok": False, "error": {"code": "UNKNOWN_SOURCE"}})
    assert inspect(case(expect_error="UNKNOWN_SOURCE"), observation(raw), valid) == "ok"

    def invalid(*args):
        raise ValueError("private-schema-value")

    assert inspect(case(), observation(), invalid) == "invalid_frame_or_schema"


def test_escaped_private_marker_is_detected_and_never_serialized():
    secret = "synthetic-" + "é-private"
    raw = frame({"ok": True, "text": secret})
    assert (
        inspect(case(forbidden_literals=(secret,)), observation(raw), valid)
        == "private_marker_leaked"
    )


def test_deadline_returns_no_transport_exception_or_frame():
    class Slow(Profile):
        async def call(self, *args):
            await asyncio.sleep(1)

    report = asyncio.run(run(Slow(), (case(timeout_seconds=0.001),), valid))
    assert report.results[0].reason == "deadline_exceeded" and report.results[0].frame_bytes is None


def test_report_denominators_and_private_representations():
    report = Report(
        platform="nt",
        execution_kind="in_memory_synthetic",
        results=(
            Result(case_id="a", status="passed", reason="ok"),
            Result(case_id="b", status="unsupported_required", reason="missing"),
        ),
    )
    assert report.counts == {
        "passed": 1,
        "failed": 0,
        "not_applicable": 0,
        "unsupported_required": 1,
    }
    assert not report.complete_pass and "private" not in repr(observation(b"private"))


def test_nested_arguments_are_not_mutated_by_injected_profile():
    """what_bug_this_catches: a transport must not silently change the frozen next-run inputs."""

    class Mutating(Profile):
        async def call(self, tool, arguments):
            arguments["nested"]["value"] = "changed"
            return observation()

    target = case(arguments={"nested": {"value": "original"}})
    report = asyncio.run(run(Mutating(), (target,), valid))
    assert report.complete_pass and target.arguments["nested"]["value"] == "original"


def test_nonpreemptible_slow_callback_is_recorded_as_deadline_failure():
    """what_bug_this_catches: a blocking result beyond its deadline must fail."""
    import time

    class Blocking(Profile):
        async def call(self, *args):
            time.sleep(0.02)
            return observation()

    report = asyncio.run(run(Blocking(), (case(timeout_seconds=0.001),), valid))
    assert report.results[0].reason == "deadline_exceeded"


def test_unknown_execution_kind_refuses_before_transport():
    profile = Profile()
    profile.execution_kind = "unverified"
    with pytest.raises(ValueError):
        asyncio.run(run(profile, (case(),), valid))
    assert profile.calls == 0


def test_exported_case_schema_matches_runtime_contract():
    """what_bug_this_catches: detached case authors must not receive a stale exported schema."""
    exported = Path(case_module.__file__).with_name("case.schema.json")
    assert json.loads(exported.read_text(encoding="utf-8")) == Case.model_json_schema()


def test_wire_requires_request_correlation_and_exact_matching_identity():
    """what_bug_this_catches: a different/stale RPC response cannot certify the requested call."""
    target = case(require_captured_wire=True, require_measured_reads=True)
    raw = Observation(frame=frame(), frame_origin="captured_wire", measured_read_bytes=1)
    assert inspect(target, raw, valid) == "request_correlation_unavailable"
    matched = raw.model_copy(update={"request_id": 1})
    assert inspect(target, matched, valid) == "ok"
    assert (
        inspect(target, matched.model_copy(update={"request_id": 2}), valid)
        == "request_id_mismatch"
    )
    assert (
        inspect(case(), observation(frame().replace(b'"id": 1', b'"id": null')), valid)
        == "invalid_frame"
    )
    with pytest.raises(ValidationError):
        Observation(frame=frame(), frame_origin="captured_wire", request_id=True)
