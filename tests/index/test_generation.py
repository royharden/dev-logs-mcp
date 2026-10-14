"""Memory descriptor controls; these do not establish native path authorization."""

import hashlib
import json
from dataclasses import replace

import pytest

from dev_logs_mcp.index import (
    CHUNK_BYTES,
    GenerationIndex,
    PrivateIndexCache,
    ReadBudget,
    ReadFailure,
    prepare_index,
)
from dev_logs_mcp.reader import VerifiedWindow
from dev_logs_mcp.shared.mcpkit.redact import Redactor
from dev_logs_mcp.shared.mcpkit.safe_path import FileIdentity

CONFIG = "a" * 64


class MemoryHandle:
    """Synthetic storage; no OS descriptor or configured-file authorization."""

    def __init__(self, data, *, read_size=65536):
        self.data = data
        self.position = 0
        self.read_size = read_size
        self.calls = self.actual_read_bytes = 0
        self.identity = FileIdentity(1, 2, len(data), 3, 4)

    def metadata(self):
        return self.identity

    def seek(self, offset, whence=0):
        assert whence == 0
        self.position = offset
        return offset

    def read(self, size):
        self.calls += 1
        result = self.data[self.position : self.position + min(size, self.read_size)]
        self.position += len(result)
        self.actual_read_bytes += len(result)
        return result


def make_index(data, **kwargs):
    handle = MemoryHandle(data, **kwargs)
    redactor = Redactor(b"i" * 32)
    budget = ReadBudget(max(1, len(data)))
    index = prepare_index(handle, "web", CONFIG, redactor, budget)
    return handle, index, redactor, budget


@pytest.mark.parametrize(
    "data,offsets",
    [
        (b"", (0,)),
        (b"a", (0, 1)),
        (b"a\n", (0, 2)),
        (b"a\r\nb\nlast", (0, 3, 5, 9)),
        (b"\n\n", (0, 1, 2)),
    ],
)
def test_exact_physical_offsets_and_serialization(data, offsets):
    """what_bug_this_catches: CRLF/final newline never create a phantom extra line."""
    handle, index, _, budget = make_index(data)
    assert index.offsets == offsets
    assert budget.bytes_read == handle.actual_read_bytes == len(data)
    assert GenerationIndex.decode(index.encode(), "web", CONFIG) == index
    assert index.source_hash == hashlib.sha256(data).hexdigest()


def test_short_reads_still_hash_exact_one_mib_chunks():
    data = b"x" * (CHUNK_BYTES + 163) + b"\n"
    _, index, _, _ = make_index(data, read_size=997)
    assert index.chunk_hashes == tuple(
        hashlib.sha256(data[i : i + CHUNK_BYTES]).hexdigest()
        for i in range(0, len(data), CHUNK_BYTES)
    )


@pytest.mark.parametrize(
    "field", ["size_bytes", "mtime_ns", "change_time_ns", "file_id", "volume_id"]
)
def test_every_generation_identity_change_invalidates(field):
    """what_bug_this_catches: every edit/rotation invalidates; no append classifier."""
    handle, index, _, _ = make_index(b"2026-01-01T00:00:00Z ERROR fail\n")
    handle.identity = replace(handle.identity, **{field: getattr(handle.identity, field) + 1})
    with pytest.raises(ReadFailure) as error:
        index.assert_current(handle)
    assert error.value.code == "INDEX_STALE"


def test_accessed_chunk_rewrite_even_unchanged_metadata_is_rejected():
    handle, index, redactor, _ = make_index(b"normal one\nnormal two\n")
    handle.data = b"EVIL!! one\nnormal two\n"
    with pytest.raises(ReadFailure) as error:
        VerifiedWindow(handle, index, ReadBudget()).lines(1, 1, redactor)
    assert error.value.code == "SOURCE_CHANGED"


def test_prepare_changed_before_publish_returns_no_index():
    handle = MemoryHandle(b"normal\n")
    original_read = handle.read

    def mutate(size):
        data = original_read(size)
        handle.identity = replace(handle.identity, change_time_ns=99)
        return data

    handle.read = mutate
    with pytest.raises(ReadFailure) as error:
        prepare_index(handle, "web", CONFIG, Redactor(), ReadBudget())
    assert error.value.code == "SOURCE_CHANGED"


@pytest.mark.parametrize(
    "data,code",
    [
        (b"\xff\xfea\x00", "UNSUPPORTED_ENCODING"),
        (b"\xfe\xff", "UNSUPPORTED_ENCODING"),
        (b"normal\nzero\x00", "BINARY_CONTENT"),
        (b"\xff\n", "UNSUPPORTED_ENCODING"),
    ],
)
def test_binary_and_unsupported_encodings(data, code):
    with pytest.raises(ReadFailure) as error:
        make_index(data)
    assert error.value.code == code
    assert repr(data) not in str(error.value)


def test_prepare_budget_stops_before_extra_read():
    handle = MemoryHandle(b"a" * 100)
    budget = ReadBudget(50)
    with pytest.raises(ReadFailure) as error:
        prepare_index(handle, "web", CONFIG, Redactor(), budget)
    assert error.value.code == "INDEX_INCOMPLETE"
    assert handle.calls == 0 and budget.bytes_read == 0


def test_deadline_is_checked_after_read_and_before_publish():
    now = [0.0]
    handle = MemoryHandle(b"line\n")
    read = handle.read

    def delayed(size):
        data = read(size)
        now[0] = 6.0
        return data

    handle.read = delayed
    budget = ReadBudget(clock=lambda: now[0])
    with pytest.raises(ReadFailure) as error:
        prepare_index(handle, "web", CONFIG, Redactor(), budget)
    assert error.value.code == "INDEX_INCOMPLETE"
    assert budget.bytes_read == 5


def test_no_change_time_is_required_unavailable():
    handle = MemoryHandle(b"line\n")
    handle.identity = replace(handle.identity, change_time_ns=None)
    with pytest.raises(ReadFailure) as error:
        prepare_index(handle, "web", CONFIG, Redactor(), ReadBudget())
    assert error.value.code == "SOURCE_NOT_LOCAL" and handle.calls == 0


@pytest.mark.parametrize(
    "mutation",
    [
        "checksum",
        "offsetbool",
        "offsetorder",
        "badstate",
        "badversion",
        "extra",
        "wrongconfig",
        "badchunk",
        "firststate",
    ],
)
def test_corrupt_or_malformed_cache_is_rejected(mutation):
    _, index, _, _ = make_index(b"one\ntwo\n")
    value = json.loads(index.encode())
    body = value["index"]
    if mutation == "checksum":
        value["sha256"] = "0" * 64
    elif mutation == "offsetbool":
        body["offsets"][1] = True
    elif mutation == "offsetorder":
        body["offsets"][1] = 99
    elif mutation == "badstate":
        body["checkpoints"][0]["parse"]["level"] = "private-marker"
    elif mutation == "badversion":
        body["schema"] = True
    elif mutation == "extra":
        body["secret"] = "private-marker"
    elif mutation == "wrongconfig":
        body["config_hash"] = "b" * 64
    elif mutation == "badchunk":
        body["chunk_hashes"] = ["not-a-hash"]
    elif mutation == "firststate":
        body["checkpoints"][0]["pem_active"] = True
    if mutation != "checksum":
        value["sha256"] = hashlib.sha256(
            json.dumps(body, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
    with pytest.raises(ReadFailure) as error:
        GenerationIndex.decode(json.dumps(value).encode(), "web", CONFIG)
    assert error.value.code == "INDEX_STALE"
    assert "private-marker" not in str(error.value)


def test_cache_has_no_raw_secret_or_path_and_generation_binds_config():
    raw = b"password=" + b"synthetic" + b"-marker\n"
    _, index, _, _ = make_index(raw)
    encoded = index.encode()
    assert b"synthetic-marker" not in encoded and b"password=" not in encoded
    assert b"path" not in encoded
    assert replace(index, config_hash="b" * 64).generation_id != index.generation_id


def test_index_line_allocation_ceiling_is_enforced(monkeypatch):
    monkeypatch.setattr("dev_logs_mcp.index.MAX_INDEX_LINES", 3)
    with pytest.raises(ReadFailure) as error:
        make_index(b"\n" * 4)
    assert error.value.code == "LIMIT_EXCEEDED"


def test_cache_windows_does_not_fallback_to_ordinary_path_io(tmp_path, monkeypatch):
    monkeypatch.setattr("dev_logs_mcp.index.os.name", "nt")
    cache = PrivateIndexCache(tmp_path / "not-created")
    with pytest.raises(ReadFailure) as error:
        cache.load("web", CONFIG, ReadBudget())
    assert error.value.code == "SOURCE_NOT_LOCAL"
    assert not (tmp_path / "not-created").exists()
