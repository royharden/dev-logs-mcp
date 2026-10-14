"""Threat tests: mocked mechanisms and real platform proofs are separate cases."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from dev_logs_mcp.shared.mcpkit import safe_path as safe


@pytest.fixture(autouse=True)
def threat_receipt(request, record_property):
    """Record a reason and execution denominator for each independently collected case."""
    record_property("what_bug_this_catches", request.function.__doc__.strip())
    record_property(
        "execution_kind",
        "mocked-branch" if request.node.name.startswith("test_mock_") else "real-platform-or-pure",
    )


@pytest.fixture
def configured(tmp_path):
    """Use a newly created synthetic root, never project/user logs."""
    source = tmp_path / "synthetic.log"
    source.write_bytes(b"synthetic\nsecond\n")
    return safe.SafePathPolicy([tmp_path], {"build": source}), source


@pytest.mark.parametrize("source_id", ["unknown", "../build", "a/b", "C:\\x", "x\x00", "", None])
def test_unknown_id_has_no_source_io(configured, monkeypatch, source_id):
    """Unknown and path-like request IDs must fail before any source open or metadata."""
    policy, _ = configured

    def forbidden(*args, **kwargs):
        pytest.fail("unauthorized source I/O")

    monkeypatch.setattr(safe, "_posix_open", forbidden)
    monkeypatch.setattr(safe, "_windows_probe", forbidden)
    with pytest.raises(safe.PathPolicyError) as error:
        policy.open_source(source_id)
    assert error.value.code == "UNKNOWN_SOURCE"


@pytest.mark.parametrize(
    "value",
    [
        "relative.log",
        "C:relative.log",
        "C:\\",
        "/",
        "C:\\x\\..\\secret",
        "C:\\x\\file:stream",
        "\\\\server\\share\\file",
        "\\\\?\\C:\\file",
        "\\\\.\\NUL",
        "C:\\x\\CON.txt",
        "C:\\x\\LPT1",
        "C:\\x\\COM¹",
        "C:\\x\\CONOUT$",
        "C:\\x\\file.",
        "C:\\x\\file ",
        "C:\\x\\bad\x00name",
        "C:\\x\\bad\ud800name",
        "C:\\x\\*.log",
    ],
)
def test_lexical_config_refused(tmp_path, value):
    """NUL/traversal/device/UNC/ADS/broad or ambiguous configured paths cannot authorize reads."""
    with pytest.raises(safe.PathPolicyError) as error:
        safe.SafePathPolicy([value], {"build": tmp_path / "synthetic.log"})
    assert error.value.code == "CONFIG_INVALID"


@pytest.mark.parametrize("roots", [[], None, "relative", [Path.home()], [Path.home().parent]])
def test_broad_or_malformed_roots(roots):
    """An empty, malformed, home or home-ancestor root must never expand the read boundary."""
    with pytest.raises(safe.PathPolicyError) as error:
        safe.SafePathPolicy(roots, {})
    assert error.value.code == "CONFIG_INVALID"


@pytest.mark.parametrize("source_id", ["../build", "a.b", "", "x" * 65, True])
def test_bad_configured_ids(tmp_path, source_id):
    """Invalid configured identifiers must be rejected rather than becoming request paths."""
    with pytest.raises(safe.PathPolicyError):
        safe.SafePathPolicy([tmp_path], {source_id: tmp_path / "synthetic.log"})


@pytest.mark.parametrize("source_id", ["_build", "-build", "_", "-", "x" * 64])
def test_configured_id_matches_published_boundary(tmp_path, source_id):
    """IDs accepted by the published source schema must also be valid opaque policy keys."""
    from dev_logs_mcp.shared.mcpkit.models import SourceInfo

    SourceInfo(id=source_id, display_path="configured source", readable=False)
    policy = safe.SafePathPolicy([tmp_path], {source_id: tmp_path / "synthetic.log"})
    assert source_id in policy._sources


def test_outside_and_root_source(tmp_path):
    """Configured sources outside the exact root or equal to its directory are forbidden."""
    for source in (tmp_path.parent / "synthetic.log", tmp_path):
        with pytest.raises(safe.PathPolicyError):
            safe.SafePathPolicy([tmp_path], {"build": source})


def test_sanitized_representations(configured):
    """Public representations and failures must not reveal paths or raw OS errors."""
    policy, source = configured
    error = safe.PathPolicyError("untrusted-secret")
    assert error.code == "PATH_FORBIDDEN"
    for text in (str(error), repr(error), error.hint, repr(policy)):
        assert str(source) not in text
        assert "untrusted-secret" not in text


@pytest.mark.skipif(os.name != "nt", reason="Windows real-platform test")
def test_windows_failclosed_before_io(configured, monkeypatch):
    """Missing no-recall race proof must deny Windows reads without probing a source."""
    policy, _ = configured

    def forbidden(*args, **kwargs):
        pytest.fail("source I/O before required capability proof")

    monkeypatch.setattr(safe, "_windows_probe", forbidden)
    with pytest.raises(safe.PathPolicyError) as error:
        policy.open_source("build")
    assert error.value.code == "SOURCE_NOT_LOCAL"
    assert error.value.capability == "windows-no-recall-race"
    caps = policy.capabilities()
    assert caps["data_access_available"] is False
    assert caps["windows_no_recall_race_proven"] is False
    assert "windows-no-recall-race" in caps["unsupported_required"]


@pytest.mark.skipif(os.name != "nt", reason="Windows real-platform test")
def test_windows_native_identity_and_restored_mtime(configured, record_property):
    """Real native ChangeTime must observe a synthetic rewrite even when mtime is restored."""
    _, source = configured
    before, attrs, final = safe._windows_probe(source)
    original = source.stat()
    source.write_bytes(b"synthetic\nthird!\n")
    os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
    after, _, final_after = safe._windows_probe(source)
    assert (before.volume_id, before.file_id) == (after.volume_id, after.file_id)
    assert before.mtime_ns == after.mtime_ns
    assert after.change_time_ns > before.change_time_ns
    assert os.path.samefile(final, source) and os.path.samefile(final_after, source)
    assert attrs & (0x1000 | 0x40000 | 0x400000) == 0
    record_property("native_change_time_observed", "true")
    record_property("no_recall_race_status", "unsupported-required")
    assert safe.capabilities()["windows_metadata_observed"] is True
    assert safe.capabilities()["data_access_available"] is False


@pytest.fixture
def mock_handle(configured, monkeypatch):
    """Mechanism tests inject metadata/I/O; they never attest native OS support."""
    _, source = configured
    state = {"offset": 0, "data": b"synthetic\nsecond\n", "closed": 0, "ctime": 3}

    def info(*args, **kwargs):
        return SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=state.get("links", 1),
            st_dev=1,
            st_ino=state.get("inode", 2),
            st_size=len(state["data"]),
            st_mtime_ns=2,
            st_ctime_ns=state["ctime"],
        )

    def read(fd, size):
        data = state["data"][state["offset"] : state["offset"] + size]
        state["offset"] += len(data)
        if state.get("change_on_read"):
            state["ctime"] += 1
        return data

    def seek(fd, offset, whence):
        state["offset"] = offset + (state["offset"] if whence == 1 else 0)
        if whence == 2:
            state["offset"] += len(state["data"])
        return state["offset"]

    monkeypatch.setattr(
        safe,
        "os",
        SimpleNamespace(
            fstat=info,
            stat=info,
            readlink=lambda *a: str(state.get("final", source)),
            read=read,
            lseek=seek,
            close=lambda *a: state.update(closed=state["closed"] + 1),
        ),
    )
    monkeypatch.setattr(safe, "_posix_local", lambda *a: None)
    handle = safe.AuthorizedReadHandle(123, source, source.parent)
    return handle, state


def test_mock_bounded_read_close_and_counter(mock_handle):
    """Bounded reads, seeks, EOF and idempotent close must preserve the actual byte counter."""
    handle, state = mock_handle
    with handle:
        assert handle.read(4) == b"synt"
        assert handle.tell() == 4
        assert handle.seek(0) == 0
        assert handle.read(65536) == state["data"]
        assert handle.read(1) == b""
        assert handle.read_bytes == 4 + len(state["data"])
        assert handle.metadata().change_time_ns == 3
        assert not hasattr(handle, "fileno") and not hasattr(handle, "readall")
    handle.close()
    assert state["closed"] == 1
    with pytest.raises(safe.PathPolicyError):
        handle.read(1)


@pytest.mark.parametrize("size", [True, False, -1, 0, 65537, None, 1.0, "1"])
def test_mock_explicit_size_required(mock_handle, size):
    """Bool, missing, zero, negative, noninteger and oversized reads must not issue data I/O."""
    handle, _ = mock_handle
    with pytest.raises(safe.PathPolicyError):
        handle.read(size)
    assert handle.read_bytes == 0


def test_mock_read_without_size(mock_handle):
    """Omitting read size cannot accidentally request an unbounded read."""
    handle, _ = mock_handle
    with pytest.raises(TypeError):
        handle.read()


@pytest.mark.parametrize("offset,whence", [(True, 0), (0, True), (0, 3), (1.0, 0)])
def test_mock_seek_misuse(mock_handle, offset, whence):
    """Ambiguous seek offsets and whence values must not reach an OS seek."""
    handle, _ = mock_handle
    with pytest.raises(safe.PathPolicyError):
        handle.seek(offset, whence)


@pytest.mark.parametrize("change", ["ctime", "inode", "final", "links"])
def test_mock_changed_source_refused(mock_handle, change, tmp_path):
    """Changed identity, ChangeTime, moved path or hard link must invalidate a handle."""
    handle, state = mock_handle
    state[change] = tmp_path / "moved.log" if change == "final" else 9
    with pytest.raises(safe.PathPolicyError):
        handle.read(1)
    assert handle.read_bytes == 0


def test_mock_changed_during_read_counted_but_not_returned(mock_handle):
    """A read racing mutation must be charged to the byte budget even when evidence is withheld."""
    handle, state = mock_handle
    state["change_on_read"] = True
    with pytest.raises(safe.PathPolicyError) as error:
        handle.read(4)
    assert error.value.code == "SOURCE_CHANGED"
    assert handle.read_bytes == 4


def test_mock_os_error_sanitized(mock_handle, monkeypatch):
    """Unexpected OS errors must not expose paths or raw text in domain failures."""
    handle, _ = mock_handle

    def fail(*args):
        raise OSError("sensitive path and source text")

    monkeypatch.setattr(safe.os, "read", fail)
    with pytest.raises(safe.PathPolicyError) as error:
        handle.read(1)
    assert error.value.code == "SOURCE_CHANGED"
    assert "sensitive" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("mode", [stat.S_IFDIR, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK])
def test_mock_nonregular_handle_refused(configured, monkeypatch, mode):
    """A no-follow open is insufficient unless the actual opened object is a regular file."""
    _, source = configured
    monkeypatch.setattr(
        safe, "os", SimpleNamespace(fstat=lambda fd: SimpleNamespace(st_mode=mode, st_nlink=1))
    )
    with pytest.raises(safe.PathPolicyError) as error:
        safe.AuthorizedReadHandle(123, source, source.parent)
    assert error.value.code == "NOT_REGULAR_FILE"


@pytest.mark.parametrize("fs_type", ["nfs", "cifs", "fuse", "overlay"])
def test_mock_network_or_unproven_mount_refused(monkeypatch, fs_type):
    """Regular files on remote, FUSE or unproven overlay storage cannot imply locality."""

    def read_text(path):
        if str(path).endswith("/123") or str(path).endswith("\\123"):
            return "mnt_id: 5\n"
        return f"5 0 1:1 / / rw - {fs_type} synthetic rw\n"

    monkeypatch.setattr(safe.Path, "read_text", read_text)
    with pytest.raises(safe.PathPolicyError) as error:
        safe._posix_local(123)
    assert error.value.code == "SOURCE_NOT_LOCAL"
    assert error.value.capability == "local-filesystem"


def test_mock_missing_mount_proof_refused(monkeypatch):
    """Missing kernel mount metadata must fail closed rather than assume a local filesystem."""
    monkeypatch.setattr(safe.Path, "read_text", lambda path: "")
    with pytest.raises(safe.PathPolicyError) as error:
        safe._posix_local(123)
    assert error.value.code == "SOURCE_NOT_LOCAL"


@pytest.mark.skipif(os.name != "posix", reason="POSIX actual execution pending on Windows")
def test_posix_real_regular_read(configured):
    """Real Linux containment and bounded read must work on supported local storage."""
    policy, _ = configured
    with policy.open_source("build") as handle:
        assert handle.read(9) == b"synthetic"
        assert handle.read_bytes == 9
        assert handle.metadata().file_id > 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX actual execution pending on Windows")
def test_posix_real_symlink_and_nonregular(configured, tmp_path):
    """Real symlink, FIFO, directory and hard-link sources must not authorize source reads."""
    _, source = configured
    link = tmp_path / "link.log"
    link.symlink_to(source)
    fifo = tmp_path / "fifo.log"
    os.mkfifo(fifo)
    hard = tmp_path / "hard.log"
    os.link(source, hard)
    directory = tmp_path / "nested"
    directory.mkdir()
    for candidate in (link, fifo, hard, directory, tmp_path / "missing.log"):
        policy = safe.SafePathPolicy([tmp_path], {"build": candidate})
        with pytest.raises(safe.PathPolicyError):
            policy.open_source("build")


@pytest.mark.skipif(os.name != "posix", reason="POSIX actual execution pending on Windows")
def test_posix_real_ancestor_symlink_escape(tmp_path):
    """A source beneath a configured root with a symlink ancestor must never escape that root."""
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "synthetic.log").write_bytes(b"synthetic\n")
    (root / "jump").symlink_to(outside, target_is_directory=True)
    policy = safe.SafePathPolicy([root], {"build": root / "jump" / "synthetic.log"})
    with pytest.raises(safe.PathPolicyError):
        policy.open_source("build")


@pytest.mark.skipif(os.name != "posix", reason="POSIX actual execution pending on Windows")
def test_posix_real_path_swap(configured, tmp_path):
    """Renaming and replacing an opened source must invalidate the original handle."""
    policy, source = configured
    with policy.open_source("build") as handle:
        source.rename(tmp_path / "old.log")
        source.write_bytes(b"replacement\n")
        with pytest.raises(safe.PathPolicyError):
            handle.read(1)
