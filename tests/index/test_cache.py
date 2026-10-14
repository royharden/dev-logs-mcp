"""Mock POSIX cache controls, with real owner/mode/link checks pending Linux."""

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import dev_logs_mcp.index as module
from dev_logs_mcp.index import PrivateIndexCache, ReadBudget, ReadFailure
from tests.index.test_generation import CONFIG, make_index


def fake_cache(monkeypatch, *, mode=0o600, links=1, owner=1000, truncate=False):
    _, index, _, _ = make_index(b"line\n")
    payload = index.encode()
    cursor = [0]
    closed = []
    opens = []

    def open_file(name, flags, *args, **kwargs):
        opens.append((name, flags, kwargs))
        return 100 if str(name).endswith(".json") else 50 + len(opens)

    def info(fd):
        return SimpleNamespace(
            st_mode=stat.S_IFREG | mode,
            st_nlink=links,
            st_uid=owner,
            st_size=len(payload),
            st_dev=1,
            st_ino=2,
            st_mtime_ns=3,
            st_ctime_ns=4,
        )

    def read(fd, amount):
        if truncate:
            return b""
        data = payload[cursor[0] : cursor[0] + amount]
        cursor[0] += len(data)
        return data

    fake = SimpleNamespace(
        name="posix",
        O_NOFOLLOW=1,
        O_RDONLY=2,
        O_CLOEXEC=4,
        O_DIRECTORY=8,
        O_NONBLOCK=16,
        open=open_file,
        close=closed.append,
        fstat=info,
        getuid=lambda: 1000,
        read=read,
    )
    monkeypatch.setattr(module, "os", fake)
    cache = PrivateIndexCache(Path("/owned"))
    monkeypatch.setattr(cache, "_open", lambda: 99)
    return cache, index, payload, closed, opens


def test_mock_cache_load_is_bounded_and_no_follow(monkeypatch):
    cache, index, payload, closed, opens = fake_cache(monkeypatch)
    budget = ReadBudget()
    assert cache.load("web", CONFIG, budget) == index
    assert budget.bytes_read == len(payload)
    assert opens[0][1] & module.os.O_NOFOLLOW
    assert closed == [100, 99]


@pytest.mark.parametrize(
    "patch", [{"mode": 0o644}, {"links": 2}, {"owner": 999}, {"truncate": True}]
)
def test_mock_bad_cache_privacy_or_short_read_never_accepted(monkeypatch, patch):
    cache, _, _, closed, _ = fake_cache(monkeypatch, **patch)
    with pytest.raises(ReadFailure) as error:
        cache.load("web", CONFIG, ReadBudget())
    assert error.value.code == "INDEX_STALE" and closed == [100, 99]


def test_mock_cache_budget_includes_every_loaded_byte(monkeypatch):
    cache, _, _, closed, _ = fake_cache(monkeypatch)
    with pytest.raises(ReadFailure) as error:
        cache.load("web", CONFIG, ReadBudget(10))
    assert error.value.code == "LIMIT_EXCEEDED" and closed == [100, 99]


def test_mock_cleanup_attempts_both_handles_and_sanitizes(monkeypatch):
    calls = []

    def close(fd):
        calls.append(fd)
        raise OSError("sensitive-local-path")

    monkeypatch.setattr(module, "os", SimpleNamespace(close=close))
    with pytest.raises(ReadFailure) as error:
        PrivateIndexCache._cleanup(1, 2)
    assert calls == [1, 2]
    assert "sensitive" not in str(error.value)


@pytest.mark.skipif(
    os.name != "posix", reason="required POSIX cache native execution pending on Windows"
)
def test_native_posix_cache_private_atomic_roundtrip_and_link_rejection(tmp_path):
    """what_bug_this_catches: real descriptor/mode/atomic operations match mock assumptions."""
    directory = tmp_path / "index-cache"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    _, index, _, _ = make_index(b"line\n")
    cache = PrivateIndexCache(directory)
    cache.save(index)
    budget = ReadBudget()
    assert cache.load("web", CONFIG, budget) == index
    target = directory / cache._name("web", CONFIG)
    target.chmod(0o644)
    with pytest.raises(ReadFailure):
        cache.load("web", CONFIG, ReadBudget())
    target.chmod(0o600)
    os.link(target, directory / "linked")
    with pytest.raises(ReadFailure):
        cache.load("web", CONFIG, ReadBudget())
