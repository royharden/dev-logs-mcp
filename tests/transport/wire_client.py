"""TEST ONLY: one bounded stdio child and exact response bytes, no network client."""

import contextlib
import json
import queue
import subprocess
import threading

from mcp_types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)
from mcp_types.version import LATEST_HANDSHAKE_VERSION, LATEST_MODERN_VERSION


class WireClient:
    def __init__(self, command, *, modern=True):
        self.command = command
        self.modern = modern
        self.captures = []
        self.events = queue.Queue(maxsize=32)
        self.errors = bytearray()

    def __enter__(self):
        self.process = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.readers = [
            threading.Thread(target=fn, daemon=True) for fn in (self._stdout, self._stderr)
        ]
        for reader in self.readers:
            reader.start()
        return self

    def _stdout(self):
        while True:
            line = self.process.stdout.readline(65537)
            try:
                self.events.put(line, timeout=1)
            except queue.Full:
                return
            if not line or len(line) > 65536:
                return

    def _stderr(self):
        while body := self.process.stderr.read1(4096):
            if len(self.errors) < 65536:
                self.errors.extend(body[: 65536 - len(self.errors)])

    def send(self, message):
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        self.process.stdin.flush()

    def request(self, request_id, method, params):
        if self.modern:
            params = {
                **params,
                "_meta": {
                    PROTOCOL_VERSION_META_KEY: LATEST_MODERN_VERSION,
                    CLIENT_INFO_META_KEY: {"name": "configured-wire-control", "version": "1"},
                    CLIENT_CAPABILITIES_META_KEY: {},
                },
            }
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        for _ in range(16):
            try:
                raw = self.events.get(timeout=15)
            except queue.Empty:
                raise AssertionError(
                    f"bounded wire timeout; child_exit={self.process.poll()}, "
                    f"stderr_bytes={len(self.errors)}"
                ) from None
            assert raw and raw.endswith(b"\n") and len(raw) <= 32768
            self.captures.append(raw)
            frame = json.loads(raw)
            if frame.get("id") == request_id:
                return raw, frame
        raise AssertionError("correlated bounded response missing")

    def handshake(self):
        if self.modern:
            _, reply = self.request(1, "server/discover", {})
        else:
            _, reply = self.request(
                1,
                "initialize",
                {
                    "protocolVersion": LATEST_HANDSHAKE_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "configured-wire-control", "version": "1"},
                },
            )
        assert "result" in reply
        if not self.modern:
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def __exit__(self, *_args):
        with contextlib.suppress(OSError):
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        for reader in self.readers:
            reader.join(timeout=2)
        self.process.stdout.close()
        self.process.stderr.close()
        assert self.process.poll() is not None and not any(r.is_alive() for r in self.readers)
