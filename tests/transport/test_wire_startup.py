"""Test-only startup timing: deterministic mechanisms and real stdio are separate."""

import io
import json
import queue
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.transport import wire_client
from tests.transport.wire_client import WireClient


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class DelayedFrames:
    """Simulated response readiness; no sleeping, process or native latency claim."""

    def __init__(self, clock, frames):
        self.clock = clock
        ready = clock.now
        self.frames = []
        for delay, request_id in frames:
            ready += delay
            raw = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {}}).encode() + b"\n"
            self.frames.append((ready, raw))

    def get(self, *, timeout):
        if not self.frames or self.frames[0][0] - self.clock.now > timeout:
            self.clock.now += timeout
            raise queue.Empty
        ready, raw = self.frames.pop(0)
        self.clock.now = max(self.clock.now, ready)
        return raw


def simulated(monkeypatch, frames, *, modern=False):
    clock = Clock()
    monkeypatch.setattr(wire_client, "monotonic", clock, raising=False)
    client = WireClient(["synthetic-process"], modern=modern)
    client.process = SimpleNamespace(stdin=io.BytesIO(), poll=lambda: None)
    client.events = DelayedFrames(clock, frames)
    return client, clock


@pytest.mark.parametrize("modern", [False, True])
def test_first_handshake_allows_twenty_second_simulated_startup(monkeypatch, modern):
    """what_bug_this_catches: a bounded initialization can outlast the ordinary15s response wait."""
    client, clock = simulated(monkeypatch, [(20, 1)], modern=modern)
    client.handshake()
    assert clock.now == client.startup_handshake_seconds == 20


def test_first_business_request_cannot_use_or_preserve_startup_allowance(monkeypatch):
    """what_bug_this_catches: business calls cannot gain or renew the startup wait."""
    client, clock = simulated(monkeypatch, [(20, 2), (20, 3)])
    with pytest.raises(AssertionError, match="wire timeout"):
        client.request(2, "tools/list", {})
    assert clock.now == 15
    with pytest.raises(AssertionError, match="wire timeout"):
        client.request(3, "initialize", {})
    assert clock.now == 30


@pytest.mark.parametrize("modern", [False, True])
def test_successful_startup_keeps_twenty_second_tool_response_refused(monkeypatch, modern):
    """what_bug_this_catches: accepting startup must not widen subsequent tool timing."""
    client, clock = simulated(monkeypatch, [(20, 1), (20, 2)], modern=modern)
    client.handshake()
    with pytest.raises(AssertionError, match="wire timeout"):
        client.request(2, "tools/list", {})
    assert clock.now == 35


def test_timed_out_startup_is_bounded_and_cannot_be_renewed(monkeypatch):
    """what_bug_this_catches: failed initialization must consume its one30s chance."""
    client, clock = simulated(monkeypatch, [(35, 1), (20, 2)])
    with pytest.raises(AssertionError, match="wire timeout"):
        client.handshake()
    assert clock.now == 30
    with pytest.raises(AssertionError, match="wire timeout"):
        client.request(2, "initialize", {})
    assert clock.now == 45


def test_uncorrelated_frame_does_not_restart_startup_deadline(monkeypatch):
    """what_bug_this_catches: unrelated frames cannot repeatedly renew a startup wait."""
    client, clock = simulated(monkeypatch, [(20, "other-request"), (20, 1)])
    with pytest.raises(AssertionError, match="wire timeout"):
        client.handshake()
    assert clock.now == 30


def test_send_failure_also_consumes_startup_allowance(monkeypatch):
    """what_bug_this_catches: a write failure cannot reset the first-handshake timing grant."""
    client, clock = simulated(monkeypatch, [(20, 1)])

    class BrokenInput:
        def write(self, value):
            raise OSError("synthetic write failure")

    client.process.stdin = BrokenInput()
    with pytest.raises(OSError, match="synthetic write failure"):
        client.handshake()
    client.process.stdin = io.BytesIO()
    with pytest.raises(AssertionError, match="wire timeout"):
        client.handshake()
    assert clock.now == 15


def test_new_process_gets_its_own_single_startup_allowance(monkeypatch):
    """what_bug_this_catches: each new process needs its own single startup allowance."""
    client, clock = simulated(monkeypatch, [(20, 2)])
    with pytest.raises(AssertionError, match="wire timeout"):
        client.request(2, "tools/list", {})
    monkeypatch.setattr(
        wire_client.subprocess,
        "Popen",
        lambda *a, **kw: SimpleNamespace(stdin=io.BytesIO(), poll=lambda: None),
    )
    monkeypatch.setattr(
        wire_client.threading, "Thread", lambda **kw: SimpleNamespace(start=lambda: None)
    )
    client.__enter__()  # Explicitly mocked process/thread startup; no OS process starts.
    client.events = DelayedFrames(clock, [(20, 1)])
    client.handshake()
    assert clock.now == 35


@pytest.mark.parametrize("modern", [False, True], ids=["legacy", "modern"])
def test_real_process_first_handshake_timing_and_catalog(modern, record_property):
    """what_bug_this_catches: real SDK startup must work within the declared test-only profile."""
    with WireClient(
        [sys.executable, str(Path(__file__).with_name("limited_memory_server.py"))], modern=modern
    ) as wire:
        wire.handshake()
        assert 0 <= wire.startup_handshake_seconds <= 30
        raw, reply = wire.request(2, "tools/list", {})
        assert len(reply["result"]["tools"]) == 5 and len(raw) <= 32768
        record_property("first_handshake_response_wait_seconds", wire.startup_handshake_seconds)
        record_property("startup_wait_limit_seconds", 30)
        record_property("later_response_wait_limit_seconds", 15)
        record_property("scope", "real SDK over synthetic memory; no native log authorization")
