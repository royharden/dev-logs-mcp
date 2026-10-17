"""Stable generation indexes; cache contains only offsets, hashes and finite state.

Callers obtain descriptors from SafePathPolicy. Test doubles are not authorization.
Explicit preparation can read a whole source; tool-call budgets are separate and
must include index loading, guards and evidence reads in the SAME ReadBudget.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from time import monotonic
from typing import Protocol

from .parse import ParseState, normalize_time, parse_line
from .shared.mcpkit.errors import MAX_PHYSICAL_LINE_BYTES, MAX_READ_BYTES
from .shared.mcpkit.redact import RedactionState, Redactor
from .shared.mcpkit.safe_path import FileIdentity

CHUNK_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_INDEX_LINES = 262144
MAX_CACHE_BYTES = 4 * 1024 * 1024
# Version1 checkpoints may inherit prior event metadata across invalid plain dates.
INDEX_SCHEMA_VERSION = 2
_LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "CRITICAL"}
_HEX = frozenset("0123456789abcdef")


class ReadFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__("Bounded source operation failed")
        self.__suppress_context__ = True


class _BudgetExhausted(ReadFailure):
    def __init__(self):
        super().__init__("LIMIT_EXCEEDED")


class ReadHandle(Protocol):
    def read(self, size: int) -> bytes: ...
    def seek(self, offset: int, whence: int = 0) -> int: ...
    def metadata(self) -> FileIdentity: ...


class ReadBudget:
    def __init__(
        self,
        max_bytes: int = MAX_READ_BYTES,
        seconds: float = 5.0,
        *,
        clock: Callable[[], float] = monotonic,
    ):
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SOURCE_BYTES:
            raise ValueError("invalid read budget")
        if type(seconds) not in (int, float) or not 0 < seconds <= 120:
            raise ValueError("invalid deadline")
        self.max_bytes = max_bytes
        self.bytes_read = 0
        self.clock = clock
        self.started_at = clock()
        self.deadline = self.started_at + seconds

    @property
    def remaining(self) -> int:
        return self.max_bytes - self.bytes_read

    def check(self) -> None:
        if self.clock() >= self.deadline:
            raise _BudgetExhausted()

    def charge(self, size: int) -> None:
        self.check()
        if type(size) is not int or size < 0 or size > self.remaining:
            raise _BudgetExhausted()
        self.bytes_read += size

    def read(self, handle: ReadHandle, size: int) -> bytes:
        self.check()
        if type(size) is not int or size < 1 or size > self.remaining:
            raise _BudgetExhausted()
        data = handle.read(min(size, 65536))
        if type(data) is not bytes or len(data) > min(size, 65536):
            raise ReadFailure("SOURCE_CHANGED")
        self.bytes_read += len(data)
        self.check()
        return data


@dataclass(frozen=True, slots=True)
class Checkpoint:
    line_no: int
    parse: ParseState
    pem_active: bool


def _hash(value: object) -> str:
    return hashlib.sha256(_json(value)).hexdigest()


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
        "ascii"
    )


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _HEX


@dataclass(frozen=True, slots=True, repr=False)
class GenerationIndex:
    source_id: str
    config_hash: str
    identity: FileIdentity
    source_hash: str
    offsets: tuple[int, ...]
    chunk_hashes: tuple[str, ...]
    checkpoints: tuple[Checkpoint, ...]

    @property
    def total_lines(self) -> int:
        return len(self.offsets) - 1

    @property
    def generation_id(self) -> str:
        return _hash([self.config_hash, asdict(self.identity), self.source_hash])

    def __repr__(self) -> str:
        return f"GenerationIndex(total_lines={self.total_lines})"

    def checkpoint(self, line_no: int) -> Checkpoint:
        numbers = [item.line_no for item in self.checkpoints]
        return self.checkpoints[bisect_right(numbers, line_no) - 1]

    def assert_current(self, handle: ReadHandle) -> None:
        if self.identity.change_time_ns is None:
            raise ReadFailure("SOURCE_NOT_LOCAL")
        if handle.metadata() != self.identity:
            raise ReadFailure("INDEX_STALE")

    def encode(self) -> bytes:
        body = {
            "schema": INDEX_SCHEMA_VERSION,
            "source_id": self.source_id,
            "config_hash": self.config_hash,
            "identity": asdict(self.identity),
            "source_hash": self.source_hash,
            "offsets": self.offsets,
            "chunk_hashes": self.chunk_hashes,
            "checkpoints": [asdict(item) for item in self.checkpoints],
        }
        result = _json({"sha256": _hash(body), "index": body})
        if len(result) > MAX_CACHE_BYTES:
            raise ReadFailure("LIMIT_EXCEEDED")
        return result

    @classmethod
    def decode(cls, data: bytes, source_id: str, config_hash: str) -> GenerationIndex:
        """Validate private-cache shape/integrity; never trust an unchecked offset."""
        try:
            if type(data) is not bytes or len(data) > MAX_CACHE_BYTES:
                raise ValueError
            wrapper = json.loads(data)
            if set(wrapper) != {"sha256", "index"}:
                raise ValueError
            body = wrapper["index"]
            if not hmac.compare_digest(_hash(body), wrapper["sha256"]):
                raise ValueError
            if (
                set(body)
                != {
                    "schema",
                    "source_id",
                    "config_hash",
                    "identity",
                    "source_hash",
                    "offsets",
                    "chunk_hashes",
                    "checkpoints",
                }
                or type(body["schema"]) is not int
                or body["schema"] != INDEX_SCHEMA_VERSION
            ):
                raise ValueError
            if body["source_id"] != source_id or body["config_hash"] != config_hash:
                raise ValueError
            if not _digest(config_hash) or not _digest(body["source_hash"]):
                raise ValueError
            identity = body["identity"]
            if set(identity) != set(FileIdentity.__dataclass_fields__):
                raise ValueError
            if any(type(value) is not int or value < 0 for value in identity.values()):
                raise ValueError
            identity = FileIdentity(**identity)
            if identity.size_bytes > MAX_SOURCE_BYTES:
                raise ValueError
            offsets = body["offsets"]
            if (
                type(offsets) is not list
                or not 1 <= len(offsets) <= MAX_INDEX_LINES + 1
                or any(type(item) is not int or item < 0 for item in offsets)
                or offsets[0] != 0
                or offsets[-1] != identity.size_bytes
                or any(a >= b for a, b in zip(offsets, offsets[1:], strict=False))
            ):
                raise ValueError
            hashes = body["chunk_hashes"]
            if (
                type(hashes) is not list
                or len(hashes) != (identity.size_bytes + CHUNK_BYTES - 1) // CHUNK_BYTES
                or not all(_digest(item) for item in hashes)
            ):
                raise ValueError
            points = []
            for value in body["checkpoints"]:
                if set(value) != {"line_no", "parse", "pem_active"}:
                    raise ValueError
                if type(value["pem_active"]) is not bool or type(value["line_no"]) is not int:
                    raise ValueError
                if set(value["parse"]) != {"timestamp", "level"}:
                    raise ValueError
                stamp, level = value["parse"]["timestamp"], value["parse"]["level"]
                if stamp is not None and normalize_time(stamp) != stamp:
                    raise ValueError
                if level is not None and level not in _LEVELS:
                    raise ValueError
                if not 1 <= value["line_no"] <= max(1, len(offsets) - 1):
                    raise ValueError
                if points and value["line_no"] <= points[-1].line_no:
                    raise ValueError
                points.append(
                    Checkpoint(value["line_no"], ParseState(stamp, level), value["pem_active"])
                )
            if not points or points[0] != Checkpoint(1, ParseState(), False):
                raise ValueError
            if any(b.line_no - a.line_no > 256 for a, b in zip(points, points[1:], strict=False)):
                raise ValueError
            if max(1, len(offsets) - 1) - points[-1].line_no > 255:
                raise ValueError
            return cls(
                source_id,
                config_hash,
                identity,
                body["source_hash"],
                tuple(offsets),
                tuple(hashes),
                tuple(points),
            )
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            raise ReadFailure("INDEX_STALE") from None


def decode_line(data: bytes, *, first: bool) -> str:
    if first and data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ReadFailure("UNSUPPORTED_ENCODING")
    if b"\x00" in data:
        raise ReadFailure("BINARY_CONTENT")
    try:
        return data.decode("utf-8-sig" if first else "utf-8").removesuffix("\n").removesuffix("\r")
    except UnicodeError:
        raise ReadFailure("UNSUPPORTED_ENCODING") from None


def prepare_index(
    handle: ReadHandle,
    source_id: str,
    config_hash: str,
    redactor: Redactor,
    budget: ReadBudget,
    *,
    format: str = "auto",
    timezone: str = "UTC",
) -> GenerationIndex:
    """One stable attempt; caller may reopen/retry at most twice, never append-classify."""
    initial = handle.metadata()
    if initial.change_time_ns is None:
        raise ReadFailure("SOURCE_NOT_LOCAL")
    if initial.size_bytes > MAX_SOURCE_BYTES:
        raise ReadFailure("LIMIT_EXCEEDED")
    if not _digest(config_hash):
        raise ReadFailure("CONFIG_INVALID")
    handle.seek(0)
    offsets = [0]
    points = [Checkpoint(1, ParseState(), False)]
    hashes = []
    full_hash = hashlib.sha256()
    chunk_hash = hashlib.sha256()
    chunk_size = consumed = 0
    line = bytearray()
    oversized = False
    parse_state = ParseState()
    redact_state = RedactionState()
    checkpoint_offset = 0

    def finish_line(end: int) -> None:
        nonlocal parse_state, redact_state, oversized, checkpoint_offset
        if len(offsets) > MAX_INDEX_LINES:
            raise ReadFailure("LIMIT_EXCEEDED")
        if oversized:
            parse_state = ParseState()
            redact_state = redactor.omit_unread(redact_state).state
        else:
            text = decode_line(bytes(line), first=offsets[-1] == 0)
            parsed = parse_line(text, parse_state, format=format, timezone=timezone)
            parse_state = parsed.state
            redact_state = redactor.redact(parsed.text, redact_state).state
        offsets.append(end)
        line.clear()
        oversized = False
        if end < initial.size_bytes and (
            (len(offsets) - 1) % 256 == 0 or end - checkpoint_offset >= CHUNK_BYTES
        ):
            points.append(Checkpoint(len(offsets), parse_state, redact_state.pem_active))
            checkpoint_offset = end

    try:
        while consumed < initial.size_bytes:
            data = budget.read(handle, min(65536, initial.size_bytes - consumed))
            if not data:
                raise ReadFailure("SOURCE_CHANGED")
            if consumed == 0 and data.startswith((b"\xff\xfe", b"\xfe\xff")):
                raise ReadFailure("UNSUPPORTED_ENCODING")
            if b"\x00" in data:
                raise ReadFailure("BINARY_CONTENT")
            full_hash.update(data)
            position = 0
            while position < len(data):
                amount = min(CHUNK_BYTES - chunk_size, len(data) - position)
                chunk_hash.update(data[position : position + amount])
                chunk_size += amount
                position += amount
                if chunk_size == CHUNK_BYTES:
                    hashes.append(chunk_hash.hexdigest())
                    chunk_hash, chunk_size = hashlib.sha256(), 0
            start = 0
            while start < len(data):
                found = data.find(b"\n", start)
                end = len(data) if found < 0 else found + 1
                piece = data[start:end]
                if not oversized and len(line) + len(piece) <= MAX_PHYSICAL_LINE_BYTES:
                    line.extend(piece)
                else:
                    oversized = True
                    line.clear()
                if found >= 0:
                    finish_line(consumed + end)
                start = end
            consumed += len(data)
        if offsets[-1] < consumed:
            finish_line(consumed)
        if chunk_size:
            hashes.append(chunk_hash.hexdigest())
        budget.check()
        if handle.metadata() != initial:
            raise ReadFailure("SOURCE_CHANGED")
        index = GenerationIndex(
            source_id,
            config_hash,
            initial,
            full_hash.hexdigest(),
            tuple(offsets),
            tuple(hashes),
            tuple(points),
        )
        index.encode()  # Enforce persistence allocation bound before publishing anything.
        return index
    except _BudgetExhausted:
        raise ReadFailure("INDEX_INCOMPLETE") from None


class PrivateIndexCache:
    """Owner-only POSIX cache with descriptor-relative no-follow operations.

    Windows ACL/atomic private-cache authorization is unsupported-required here;
    callers must not substitute ordinary Path.write_text as a fallback.
    """

    def __init__(self, directory: Path):
        self._directory = directory

    def _open(self) -> int:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise ReadFailure("SOURCE_NOT_LOCAL")
        try:
            if not self._directory.is_absolute() or ".." in self._directory.parts:
                raise ValueError
            fd = os.open(self._directory.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                for part in self._directory.parts[1:]:
                    next_fd = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
                    )
                    os.close(fd)
                    fd = next_fd
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError
                return fd
            except BaseException:
                os.close(fd)
                raise
        except (OSError, ValueError):
            raise ReadFailure("PATH_FORBIDDEN") from None

    @staticmethod
    def _name(source_id: str, config_hash: str) -> str:
        return _hash([source_id, config_hash]) + ".json"

    def load(self, source_id: str, config_hash: str, budget: ReadBudget) -> GenerationIndex | None:
        directory = self._open()
        fd = None
        try:
            try:
                fd = os.open(
                    self._name(source_id, config_hash),
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=directory,
                )
            except FileNotFoundError:
                return None
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > MAX_CACHE_BYTES
            ):
                raise ReadFailure("INDEX_STALE")
            raw = bytearray()
            while len(raw) < before.st_size:
                amount = min(65536, before.st_size - len(raw))
                budget.check()
                if amount > budget.remaining:
                    raise ReadFailure("LIMIT_EXCEEDED")
                data = os.read(fd, amount)
                budget.charge(len(data))
                if not data:
                    raise ReadFailure("INDEX_STALE")
                raw.extend(data)
            after = os.fstat(fd)
            if any(
                getattr(after, name) != getattr(before, name)
                for name in (
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                    "st_mode",
                    "st_nlink",
                    "st_uid",
                )
            ):
                raise ReadFailure("INDEX_STALE")
            return GenerationIndex.decode(bytes(raw), source_id, config_hash)
        except OSError:
            raise ReadFailure("INDEX_STALE") from None
        finally:
            self._cleanup(fd, directory)

    @staticmethod
    def _cleanup(fd: int | None, directory: int, pending: str | None = None) -> None:
        failed = False
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                failed = True
        if pending is not None:
            try:
                os.unlink(pending, dir_fd=directory)
            except OSError:
                failed = True
        try:
            os.close(directory)
        except OSError:
            failed = True
        if failed:
            raise ReadFailure("INDEX_STALE") from None

    def save(self, index: GenerationIndex) -> None:
        payload = index.encode()
        directory = self._open()
        name = ".pending-" + secrets.token_hex(16)
        fd = None
        created = False
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            created = True
            os.fchmod(fd, 0o600)
            view = memoryview(payload)
            while view:
                size = os.write(fd, view)
                if size <= 0:
                    raise OSError
                view = view[size:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(
                name,
                self._name(index.source_id, index.config_hash),
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            created = False
            os.fsync(directory)
        except OSError:
            raise ReadFailure("INDEX_STALE") from None
        finally:
            self._cleanup(fd, directory, name if created else None)
