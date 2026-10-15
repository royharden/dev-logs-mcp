"""Run exact case IDs and return value-free outcomes, never raw frames/exceptions.

Profiles own actual transport/capture/I-O instrumentation and process cleanup.
Declared profile capabilities are not independent proof of native or wire execution.
"""

import asyncio
import json
from collections.abc import Callable
from time import monotonic
from typing import Protocol

from .cases import Case, Observation, Report, Result


class Profile(Protocol):
    platform: str
    execution_kind: str
    unavailable_capabilities: frozenset[str]

    async def call(self, tool: str, arguments: dict) -> Observation: ...


def _contains(value: object, markers: tuple[str, ...]) -> bool:
    pending = [value]
    visited = 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > 32768:
            raise ValueError("frame traversal bound")
        if isinstance(item, str):
            if any(marker in item for marker in markers):
                return True
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def inspect(case: Case, observation: Observation, validate: Callable[[Case, dict], None]) -> str:
    """Return a closed reason code. Inspect the full frame and compatible text mirror."""
    raw = observation.frame
    if len(raw) > case.max_frame_bytes:
        return "frame_limit"
    if case.require_captured_wire and observation.frame_origin != "captured_wire":
        return "wire_capture_unavailable"
    if case.require_captured_wire and observation.request_id is None:
        return "request_correlation_unavailable"
    if case.require_measured_reads and observation.measured_read_bytes is None:
        return "read_measurement_unavailable"
    if (
        observation.measured_read_bytes is not None
        and observation.measured_read_bytes > case.max_read_bytes
    ):
        return "read_limit"
    try:

        def invalid_constant(_value):
            raise ValueError("nonfinite JSON")

        frame = json.loads(raw.decode("utf-8"), parse_constant=invalid_constant)
        if (
            not isinstance(frame, dict)
            or frame.get("jsonrpc") != "2.0"
            or "id" not in frame
            or type(frame["id"]) not in (int, str, type(None))
        ):
            return "invalid_frame"
        if frame["id"] is None and case.expect_protocol_error is None:
            return "invalid_frame"
        if observation.request_id is not None and frame["id"] != observation.request_id:
            return "request_id_mismatch"
        if _contains(frame, case.forbidden_literals):
            return "private_marker_leaked"
        if case.expect_protocol_error is not None:
            error = frame.get("error")
            if not isinstance(error, dict) or type(error.get("code")) is not int:
                return "protocol_error_missing"
            return (
                "ok"
                if error["code"] == case.expect_protocol_error and "result" not in frame
                else "protocol_error_mismatch"
            )
        result = frame.get("result")
        if not isinstance(result, dict) or "error" in frame:
            return "tool_result_missing"
        envelope = result.get("structuredContent")
        content = result.get("content")
        if not isinstance(envelope, dict) or not isinstance(content, list) or len(content) != 1:
            return "structured_mirror_missing"
        if content[0].get("type") != "text" or json.loads(content[0]["text"]) != envelope:
            return "structured_mirror_mismatch"
        validate(case, envelope)
        expected_ok = case.expect_error is None
        if type(envelope.get("ok")) is not bool or envelope["ok"] != expected_ok:
            return "unexpected_status"
        if result.get("isError", False) is not (not expected_ok):
            return "iserror_mismatch"
        if not expected_ok and (
            not isinstance(envelope.get("error"), dict)
            or envelope["error"].get("code") != case.expect_error
        ):
            return "domain_error_mismatch"
        return "ok"
    except Exception:
        return "invalid_frame_or_schema"


async def run(
    profile: Profile, cases: tuple[Case, ...], validate: Callable[[Case, dict], None]
) -> Report:
    if not cases or len(cases) > 1000 or len({case.case_id for case in cases}) != len(cases):
        raise ValueError("bounded distinct nonempty case set required")
    if profile.platform not in {"nt", "posix"}:
        raise ValueError("explicit platform required")
    if profile.execution_kind not in {"in_memory_synthetic", "local_adapter", "native_platform"}:
        raise ValueError("explicit execution kind required")
    results = []
    for case in cases:
        if profile.platform not in case.platforms:
            results.append(
                Result(case_id=case.case_id, status="not_applicable", reason="different_platform")
            )
            continue
        if (case.require_native and profile.execution_kind != "native_platform") or (
            case.required_capability in profile.unavailable_capabilities
        ):
            results.append(
                Result(
                    case_id=case.case_id,
                    status="unsupported_required",
                    reason="capability_unavailable",
                )
            )
            continue
        start = monotonic()
        observation = None
        try:
            arguments = json.loads(json.dumps(case.arguments, allow_nan=False))
            observation = await asyncio.wait_for(
                profile.call(case.tool, arguments), case.timeout_seconds
            )
            if not isinstance(observation, Observation):
                raise ValueError
            reason = inspect(case, observation, validate)
            if monotonic() - start > case.timeout_seconds:
                reason = "deadline_exceeded"
        except TimeoutError:
            reason = "deadline_exceeded"
        except Exception:
            reason = "transport_failure"
        status = "passed" if reason == "ok" else "failed"
        if reason in {
            "wire_capture_unavailable",
            "request_correlation_unavailable",
            "read_measurement_unavailable",
        }:
            status = "unsupported_required"
        results.append(
            Result(
                case_id=case.case_id,
                status=status,
                reason=reason,
                duration_ms=max(0, int((monotonic() - start) * 1000)),
                frame_bytes=len(observation.frame) if observation else None,
                measured_read_bytes=observation.measured_read_bytes if observation else None,
            )
        )
    return Report(
        platform=profile.platform, execution_kind=profile.execution_kind, results=tuple(results)
    )
