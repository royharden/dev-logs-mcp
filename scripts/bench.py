"""Native source-profile benchmark; JSONL observations, never inferred performance.

Runs actual in-process application calls and renderer, not captured MCP stdio.
Generated logs/cache are private disposable synthetic inputs. Process I/O includes
observer overhead; source/index os.read counts are separate from process counters.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from dev_logs_mcp.config import AppConfig
from dev_logs_mcp.contracts import AUTO_INDEX_BYTES
from dev_logs_mcp.index import PrivateIndexCache, ReadFailure
from dev_logs_mcp.query import LogEngine
from dev_logs_mcp.shared.mcpkit.errors import MAX_FRAME_BYTES, MAX_READ_BYTES
from dev_logs_mcp.shared.mcpkit.safe_path import PathPolicyError
from dev_logs_mcp.sources import SourceCatalog

REPO = Path(__file__).resolve().parents[1]
TOOLS = ("list_sources", "tail", "search", "read_range", "errors")


def record_bytes(kind, number, length):
    """A valid ASCII record with exact length, including LF; no partial JSON tail."""
    message = f"bench event {'needle_hit' if number % 97 == 0 else 'regular'} id={number:010} "
    if number % 257 == 0:
        message += "password=synthetic-" + f"benchmark-{number:010} "
    level = "ERROR" if number % 11 == 0 else "INFO"
    if kind == "jsonl":
        prefix = json.dumps(
            {"timestamp": "2026-01-01T00:00:00Z", "level": level, "message": message},
            separators=(",", ":"),
        )
        # Padding goes inside the final message string, before its closing quote.
        prefix, suffix = prefix[:-2], '"}\n'
    elif kind == "plain_iso":
        prefix, suffix = f"2026-01-01T00:00:00Z {level} {message}", "\n"
    else:
        raise ValueError("unknown benchmark format")
    padding = length - len(prefix.encode()) - len(suffix.encode())
    if padding < 0:
        raise ValueError("benchmark record too small")
    return (prefix + "x" * padding + suffix).encode("ascii")


def generate(path, kind, size):
    if type(size) is not int or not 256 <= size <= 1024 * 1024 * 1024:
        raise ValueError("bounded benchmark size required")
    count = max(1, size // 1024)
    digest = hashlib.sha256()
    with path.open("xb") as stream:
        for number in range(1, count + 1):
            length = 1024 if number < count else size - 1024 * (count - 1)
            body = record_bytes(kind, number, length)
            stream.write(body)
            digest.update(body)
    assert path.stat().st_size == size
    return {"bytes": size, "lines": count, "sha256": digest.hexdigest(), "format": kind}


def process_observation():
    if os.name != "posix":
        return {"process_io": None, "peak_rss_bytes": None, "cgroup_peak_bytes": None}
    import resource

    counters = None
    try:
        counters = {
            key: int(value)
            for key, value in (
                line.split(":", 1) for line in Path("/proc/self/io").read_text().splitlines()
            )
        }
    except (OSError, ValueError):
        pass
    peak = None
    try:
        peak = int(Path("/sys/fs/cgroup/memory.peak").read_text())
    except (OSError, ValueError):
        pass
    return {
        "process_io": counters,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "cgroup_peak_bytes": peak,
    }


@contextmanager
def observed_reads():
    """Observe actual os.read returns without changing bounds, arguments or data."""
    original = os.read
    state = {"os_read_bytes": 0, "os_read_calls": 0}

    def counted(fd, size):
        data = original(fd, size)
        state["os_read_bytes"] += len(data)
        state["os_read_calls"] += 1
        return data

    os.read = counted
    try:
        yield state
    finally:
        os.read = original


def measure(action):
    before = process_observation()
    start = time.perf_counter()
    result, failure = None, None
    with observed_reads() as reads:
        try:
            result = action()
        except (ReadFailure, PathPolicyError) as error:
            failure = error.code
    elapsed = (time.perf_counter() - start) * 1000
    after = process_observation()
    old, new = before["process_io"], after["process_io"]
    delta = {key: new[key] - old[key] for key in old.keys() & new.keys()} if old and new else None
    return result, {
        "duration_ms": elapsed,
        **reads,
        "exception_code": failure,
        "process_io_delta_including_observer_overhead": delta,
        "process_peak_rss_bytes_so_far": after["peak_rss_bytes"],
        "cgroup_peak_bytes_so_far": after["cgroup_peak_bytes"],
    }


def summary(samples):
    """Nearest-rank percentiles retain failed-call durations in the denominator."""
    times = sorted(row["duration_ms"] for row in samples)
    return {
        "calls": len(samples),
        "failed": sum(not row["ok"] for row in samples),
        "p50_ms_all_calls": times[math.ceil(0.50 * len(times)) - 1] if times else None,
        "p95_ms_all_calls": times[math.ceil(0.95 * len(times)) - 1] if times else None,
        "max_os_read_bytes": max((row["os_read_bytes"] for row in samples), default=None),
        "max_rendered_frame_bytes": max(
            (
                row["rendered_frame_bytes"]
                for row in samples
                if row["rendered_frame_bytes"] is not None
            ),
            default=None,
        ),
    }


def requests(profile, total_lines):
    maximum = profile == "maximum_request"
    return {
        "list_sources": {},
        "tail": {"source_id": "web", **({"lines": 500} if maximum else {})},
        "search": {"source_id": "web", "pattern": "bench", **({"context": 5} if maximum else {})},
        "read_range": {
            "source_id": "web",
            "start_line": 1,
            "end_line": min(total_lines, 500 if maximum else 200),
        },
        "errors": {"source_id": "web"},
    }


def call(engine, tool, arguments, request_id):
    result, observation = measure(lambda: engine.call(tool, arguments).render(request_id))
    envelope = result.envelope if result else None
    observation.update(
        ok=bool(envelope and envelope.ok),
        code=envelope.error.code.value
        if envelope and envelope.error
        else observation["exception_code"],
        rendered_frame_bytes=len(result.wire_bytes) if result else None,
        reported_read_bytes=envelope.coverage.bytes_read if envelope else None,
        matches=len(envelope.matches) if envelope else 0,
        complete=envelope.coverage.complete if envelope else False,
        output_truncated=bool(
            envelope and (envelope.truncation.output_lines or envelope.truncation.output_bytes)
        ),
    )
    observed = observation["os_read_bytes"]
    observation["read_cap_respected"] = observed <= MAX_READ_BYTES
    observation["frame_cap_respected"] = bool(result and len(result.wire_bytes) <= MAX_FRAME_BYTES)
    return envelope, observation


def benchmark(directory, size, repeats, emit, deadline):
    failures = []
    for kind in ("plain_iso", "jsonl"):
        root = directory / kind
        root.mkdir(mode=0o700)
        path = root / "synthetic.log"
        fixture = generate(path, kind, size)
        emit({"phase": "fixture", **fixture})
        cache = root / "cache"
        cache.mkdir(mode=0o700)
        config = AppConfig.model_validate(
            {
                "allowed_roots": [str(root)],
                "sources": [{"id": "web", "path": str(path), "format": kind}],
            }
        )
        engine = LogEngine(SourceCatalog(config, root), cache=PrivateIndexCache(cache))
        _, cold = call(engine, "tail", {"source_id": "web"}, 1)
        cold["expected_cold_refusal"] = "INDEX_REQUIRED" if size > AUTO_INDEX_BYTES else None
        if size > AUTO_INDEX_BYTES and cold["code"] != "INDEX_REQUIRED":
            failures.append({"format": kind, "phase": "cold", "code": "COLD_REFUSAL"})
        emit({"phase": "cold", "format": kind, **cold})
        _, preparation = measure(lambda target=engine: target.prepare("web"))
        preparation["cache_bytes"] = sum(
            item.stat().st_size for item in cache.iterdir() if item.is_file()
        )
        emit({"phase": "prepare", "format": kind, **preparation})
        if preparation["exception_code"]:
            failures.append(
                {"format": kind, "phase": "prepare", "code": preparation["exception_code"]}
            )
            emit(
                {
                    "phase": "warm_and_sweeps",
                    "format": kind,
                    "status": "not-executed-preparation-failed",
                }
            )
            continue
        for profile in ("default_request", "maximum_request"):
            for tool, arguments in requests(profile, fixture["lines"]).items():
                samples = []
                for repeat in range(repeats):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("benchmark aggregate budget")
                    _, sample = call(engine, tool, arguments, repeat + 2)
                    sample["less_than_full_source"] = sample["os_read_bytes"] < size
                    emit(
                        {
                            "phase": "warm_call",
                            "format": kind,
                            "profile": profile,
                            "tool": tool,
                            "repeat": repeat,
                            **sample,
                        }
                    )
                    samples.append(sample)
                    if (
                        not sample["ok"]
                        or not sample["read_cap_respected"]
                        or not sample["frame_cap_respected"]
                        or (
                            size > AUTO_INDEX_BYTES
                            and tool in ("tail", "search")
                            and not sample["less_than_full_source"]
                        )
                    ):
                        failures.append(
                            {
                                "format": kind,
                                "profile": profile,
                                "tool": tool,
                                "repeat": repeat,
                                "code": sample["code"] or "BOUND_FAILURE",
                            }
                        )
                totals = summary(samples)
                target = 250 if tool == "tail" else 1000 if tool == "search" else None
                emit(
                    {
                        "phase": "warm_summary",
                        "format": kind,
                        "profile": profile,
                        "tool": tool,
                        "soft_target_ms": target,
                        "soft_target_met": totals["p95_ms_all_calls"] <= target if target else None,
                        **totals,
                    }
                )
        for label, pattern in (
            ("match", "needle_hit"),
            ("no_match", "not_present_in_generated_data"),
        ):
            pages = matches = actual_bytes = reported_bytes = 0
            seen = set()
            cursor = None
            status = "page-bound-reached"
            sweep_start = time.perf_counter()
            for page in range(10000):
                if time.monotonic() >= deadline:
                    raise TimeoutError("benchmark aggregate budget")
                args = {
                    "source_id": "web",
                    "pattern": pattern,
                    "context": 0,
                    **({"cursor": cursor} if cursor else {}),
                }
                envelope, observed = call(engine, "search", args, page + 1000)
                pages += 1
                actual_bytes += observed["os_read_bytes"]
                reported_bytes += observed["reported_read_bytes"] or 0
                matches += observed["matches"]
                if (
                    not observed["ok"]
                    or not observed["read_cap_respected"]
                    or not observed["frame_cap_respected"]
                    or (size > AUTO_INDEX_BYTES and observed["os_read_bytes"] >= size)
                ):
                    status = observed["code"] or "BOUND_FAILURE"
                    break
                cursor = envelope.next_cursor
                if cursor is None:
                    status = "completed"
                    break
                if cursor in seen:
                    status = "cursor-cycle"
                    break
                seen.add(cursor)
            emit(
                {
                    "phase": "full_source_sweep",
                    "format": kind,
                    "kind": label,
                    "status": status,
                    "pages": pages,
                    "matches": matches,
                    "os_read_bytes": actual_bytes,
                    "reported_read_bytes": reported_bytes,
                    "duration_ms": (time.perf_counter() - sweep_start) * 1000,
                }
            )
            if status != "completed" or matches != (
                fixture["lines"] // 97 if label == "match" else 0
            ):
                failures.append(
                    {
                        "format": kind,
                        "sweep": label,
                        "code": status if status != "completed" else "MATCH_DENOMINATOR",
                    }
                )
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-bytes", type=int, default=100_000_000)
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--max-seconds", type=int, default=600)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New JSONL observation file outside source inputs",
    )
    args = parser.parse_args()
    if (
        not 256 <= args.size_bytes <= 1024 * 1024 * 1024
        or not 1 <= args.repeats <= 1000
        or not 1 <= args.max_seconds <= 600
    ):
        parser.error("benchmark bounds exceeded")
    with args.output.open("x", encoding="utf-8") as output:

        def emit(row):
            output.write(json.dumps(row, allow_nan=False, separators=(",", ":")) + "\n")
            output.flush()

        emit(
            {
                "phase": "scope",
                "python": platform.python_version(),
                "libc": platform.libc_ver(),
                "platform": platform.platform(),
                "machine": platform.machine(),
                "size_bytes_per_format": args.size_bytes,
                "repeats": args.repeats,
                "model_calls": 0,
                "mode": "native-source-inprocess-renderer-not-SDK-wire",
                "ceilings": {"read_bytes": MAX_READ_BYTES, "frame_bytes": MAX_FRAME_BYTES},
                "configuration_grid": (
                    "Fixed application ceilings; default/maximum request parameters only. "
                    "Configurable lower ceilings not implemented/qualified."
                ),
                "measurement_limits": (
                    "os.read observes actual source/index/cache Python reads, "
                    "not all native-library I/O. "
                    "/proc/self/io raw deltas include observer overhead; RSS/cgroup peaks are "
                    "process/job high-water marks, not per-call allocations."
                ),
            }
        )
        if os.name != "posix" or platform.system() != "Linux":
            emit(
                {
                    "phase": "result",
                    "status": "unsupported_required",
                    "reason": "native-Linux-benchmark-profile-only",
                    "qualification": False,
                }
            )
            return 3
        generated = REPO / "fixtures/generated/bench"
        generated.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + args.max_seconds
        try:
            with tempfile.TemporaryDirectory(prefix="run-", dir=generated) as directory:
                failures = benchmark(Path(directory), args.size_bytes, args.repeats, emit, deadline)
        except TimeoutError:
            emit(
                {
                    "phase": "result",
                    "status": "incomplete",
                    "reason": "aggregate-budget",
                    "qualification": False,
                }
            )
            return 2
        except Exception as error:
            emit(
                {
                    "phase": "result",
                    "status": "incomplete",
                    "reason": type(error).__name__,
                    "qualification": False,
                }
            )
            return 2
        emit(
            {
                "phase": "result",
                "status": "completed_with_failures" if failures else "completed_observations",
                "failures": failures,
                "required_size_and_repeats": args.size_bytes == 100_000_000 and args.repeats == 30,
                "configuration_tightening_qualified": False,
                "qualification": False,
                "whole_app_accepted": False,
            }
        )
        return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
