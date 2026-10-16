"""Threat tests: mocked mechanisms and real platform proofs are separate cases."""

from __future__ import annotations

import os
import stat
from dataclasses import replace
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


@pytest.mark.parametrize("magic", [0x6969, 0xFF534D42, 0x65735546, 0x794C7630, 0, -1])
def test_mock_network_or_unproven_mount_refused(monkeypatch, magic):
    """Regular files on remote, FUSE or unproven overlay storage cannot imply locality."""
    monkeypatch.setattr(safe, "_linux_fs_magic", lambda fd: magic)
    with pytest.raises(safe.PathPolicyError) as error:
        safe._posix_local(123)
    assert error.value.code == "SOURCE_NOT_LOCAL"
    assert error.value.capability == "local-filesystem"


def test_mock_missing_mount_proof_refused(monkeypatch):
    """Missing kernel mount metadata must fail closed rather than assume a local filesystem."""
    monkeypatch.setattr(safe, "_linux_lp64", lambda: False)
    with pytest.raises(safe.PathPolicyError) as error:
        safe._posix_local(123)
    assert error.value.code == "SOURCE_NOT_LOCAL"


def test_mock_unsupported_abi_has_no_native_call(monkeypatch):
    """Unsupported native word/pointer layouts must fail before a libc metadata call."""
    monkeypatch.setattr(safe, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        safe,
        "ctypes",
        SimpleNamespace(
            c_void_p=object(),
            c_long=object(),
            sizeof=lambda *a: 4,
            CDLL=lambda *a, **kw: pytest.fail("unsupported native call"),
        ),
    )
    assert not safe._linux_lp64()
    with pytest.raises(safe.PathPolicyError):
        safe._linux_fs_magic(123)


@pytest.mark.parametrize("magic", [0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x858458F6])
def test_mock_local_magic_has_no_proc_body_reads(monkeypatch, magic):
    """Guard locality checks must not consume uncharged proc-file bodies of arbitrary size."""
    monkeypatch.setattr(safe, "_linux_fs_magic", lambda fd: magic)
    monkeypatch.setattr(safe.Path, "read_text", lambda *a, **kw: pytest.fail("proc body read"))
    safe._posix_local(123)


@pytest.mark.parametrize("outcome", ["ok", "errno", "missing", "load-error"])
def test_mock_fstatfs_fixed_buffer_and_sanitized_errors(monkeypatch, outcome):
    """Native fstatfs must use one fixed aligned metadata buffer and sanitize unavailable APIs."""
    import ctypes

    seen = []

    class Function:
        def __call__(self, fd, buffer):
            seen.append((fd, ctypes.sizeof(buffer)))
            buffer[0] = 0x01021994
            return -1 if outcome == "errno" else 0

    function = Function()

    def load(*args, **kwargs):
        assert args == (None,) and kwargs == {"use_errno": True}
        if outcome == "load-error":
            raise OSError("sensitive native failure")
        return SimpleNamespace() if outcome == "missing" else SimpleNamespace(fstatfs=function)

    monkeypatch.setattr(safe, "_linux_lp64", lambda: True)
    # A fake Linux long width on Windows permits layout control without claiming
    # that Windows actually supplies Linux libc or ABI.
    monkeypatch.setattr(
        safe,
        "ctypes",
        SimpleNamespace(
            CDLL=load,
            c_int=ctypes.c_int32,
            c_long=ctypes.c_int64,
            POINTER=ctypes.POINTER,
        ),
    )
    if outcome == "ok":
        assert safe._linux_fs_magic(123) == 0x01021994
        assert seen == [(123, 512)]
    else:
        with pytest.raises(safe.PathPolicyError) as error:
            safe._linux_fs_magic(123)
        assert "sensitive" not in str(error.value)


@pytest.fixture
def mock_posix_open(monkeypatch):
    """Provide fake descriptor-level ordering and ownership, never native safety proof."""
    path = Path("/synthetic/source.log")
    calls, closed = [], []
    state = {
        "magic": 0x01021994,
        "mode": stat.S_IFREG,
        "links": 1,
        "swap": False,
        "named_swap": False,
        "final_swap": False,
        "open_error": False,
        "probe_close_error": False,
    }

    def info(fd=None, **kwargs):
        return SimpleNamespace(
            st_mode=state["mode"],
            st_nlink=state["links"],
            st_dev=1,
            st_ino=9 if (fd == 13 and state["swap"]) or (fd == path and state["named_swap"]) else 2,
            st_size=5,
            st_mtime_ns=3,
            st_ctime_ns=4,
        )

    def open_file(name, flags, **kwargs):
        calls.append(("open", str(name), flags))
        if str(name).startswith("/proc/self/fd/"):
            if state["open_error"]:
                raise OSError("sensitive open failure")
            return 13
        return {path.anchor: 10, "synthetic": 11, "source.log": 12}[str(name)]

    def close(fd):
        closed.append(fd)
        if fd == 12 and state["probe_close_error"]:
            raise OSError("sensitive close failure")

    def magic(fd):
        calls.append(("local", fd))
        return state["magic"]

    monkeypatch.setattr(safe, "_linux_lp64", lambda: True)
    monkeypatch.setattr(safe, "_linux_fs_magic", magic)
    monkeypatch.setattr(
        safe,
        "os",
        SimpleNamespace(
            O_PATH=0x200000,
            O_DIRECTORY=0x10000,
            O_CLOEXEC=0x80000,
            O_NOFOLLOW=0x20000,
            O_RDONLY=0,
            O_NONBLOCK=0x800,
            open=open_file,
            close=close,
            fstat=info,
            stat=info,
            readlink=lambda *a: "/elsewhere.log" if state["final_swap"] else str(path),
        ),
    )
    return path, calls, closed, state


def test_mock_locality_precedes_pinned_data_open(mock_posix_open):
    """Never open rejected storage for data before its metadata-only locality validation."""
    path, calls, closed, _ = mock_posix_open
    assert safe._posix_open(path) == 13
    assert calls[-2][0] == "local" and calls[-1][1] == "/proc/self/fd/12"
    assert all(
        call[2] & safe.os.O_PATH
        for call in calls
        if call[0] == "open" and not call[1].startswith("/proc/")
    )
    assert sorted(closed) == [10, 11, 12] and 13 not in closed


@pytest.mark.parametrize(
    "change",
    [
        "remote",
        "symlink",
        "links",
        "named_swap",
        "final_swap",
        "open_error",
        "swap",
        "probe_close_error",
    ],
)
def test_mock_rejected_probe_or_data_failure_closes_descriptors(mock_posix_open, change):
    """Policy failures and reopen/identity/close failures must close every owned descriptor."""
    path, calls, closed, state = mock_posix_open
    state.update(
        {
            "remote": {"magic": 0x65735546},
            "symlink": {"mode": stat.S_IFLNK},
            "links": {"links": 2},
        }.get(change, {change: True})
    )
    with pytest.raises((safe.PathPolicyError, OSError)):
        safe._posix_open(path)
    assert sorted(closed[:3]) == [10, 11, 12]
    data_calls = [call for call in calls if call[0] == "open" and call[1].startswith("/proc/")]
    if change in {"remote", "symlink", "links", "named_swap", "final_swap"}:
        assert not data_calls and 13 not in closed
    elif change != "open_error":
        assert 13 in closed


def test_mock_missing_O_PATH_never_opens(mock_posix_open, monkeypatch):
    """Metadata-only opening unavailable means no source or ancestor open may occur."""
    path, calls, closed, _ = mock_posix_open
    monkeypatch.delattr(safe.os, "O_PATH")
    with pytest.raises(safe.PathPolicyError):
        safe._posix_open(path)
    assert not calls and not closed


@pytest.mark.skipif(os.name != "posix", reason="POSIX actual execution pending on Windows")
def test_posix_real_fixed_metadata_guard(configured, monkeypatch):
    """Real approved storage uses fixed fstatfs metadata; procfs is refused without body reads."""
    policy, _ = configured
    monkeypatch.setattr(safe.Path, "read_text", lambda *a, **kw: pytest.fail("proc body read"))
    with policy.open_source("build") as handle:
        assert handle.read(9) == b"synthetic"
    descriptor = os.open("/proc/self/stat", os.O_PATH | os.O_CLOEXEC)
    try:
        with pytest.raises(safe.PathPolicyError) as error:
            safe._posix_local(descriptor)
        assert error.value.code == "SOURCE_NOT_LOCAL"
    finally:
        os.close(descriptor)


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


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
def test_windows_metadata_chain_native(configured, record_property):
    """Actual native ancestor containment must inspect metadata without exposing a data-read API."""
    _, source = configured
    assert "onedrive" not in str(source).lower()
    budget = safe._MetadataBudget()
    native = safe._NativeWindows(budget)
    with safe._WindowsMetadataProof(source, source.parent, _native=native) as proof:
        assert proof.metadata().file_id > 0
        assert not hasattr(proof, "read") and not hasattr(proof, "fileno")
        assert str(source) not in repr(proof)
    assert native.open_count == native.close_count
    record_property("native_metadata_calls", budget.calls)
    record_property("native_handle_cleanup", "complete")
    assert budget.calls <= 4096
    assert safe.capabilities()["windows_metadata_chain_observed"]
    assert safe.capabilities()["windows_capability_status"]["data_authorization"] == "unimplemented"
    assert not safe.capabilities()["data_access_available"]


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
def test_windows_metadata_readattributes_only_spy(configured, monkeypatch, record_property):
    """Actual native opens must request only READ_ATTRIBUTES and bind no source-data API."""
    _, source = configured
    native = safe._NativeWindows(safe._MetadataBudget())
    original = native.create
    opens = []

    def spy(path, access, sharing, security, disposition, flags, template):
        opens.append((access, sharing, disposition, flags))
        return original(path, access, sharing, security, disposition, flags, template)

    monkeypatch.setattr(native, "create", spy)
    with safe._WindowsMetadataProof(source, source.parent, _native=native):
        pass
    assert opens and all(row == (0x80, 3, 3, 0x02300000) for row in opens)
    assert not hasattr(native, "ReadFile") and not hasattr(native, "read")
    assert native.open_count == native.close_count
    record_property("native_open_count", len(opens))
    record_property("source_data_access_requested", "false")


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
def test_windows_deep_unicode_chain_native(tmp_path):
    """A real multi-component Unicode path must resolve through stable canonical handles."""
    root = tmp_path / "allowed"
    source = root / "évidence" / "nested" / "synthetic.log"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"synthetic\n")
    with safe._WindowsMetadataProof(source, root) as proof:
        assert proof.metadata().size_bytes == 10


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
def test_windows_short_alias_native(tmp_path, record_property):
    """Canonical handle identities must accept an observed8.3 alias without literal-prefix
    guesses.
    """
    source = tmp_path / "long-synthetic-log-name.log"
    source.write_bytes(b"synthetic\n")
    native = safe._NativeWindows(safe._MetadataBudget())
    c, w = native.ctypes, native.w
    function = c.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
    function.argtypes, function.restype = [w.LPCWSTR, w.LPWSTR, w.DWORD], w.DWORD
    buffer = c.create_unicode_buffer(32768)
    length = function(str(source), buffer, len(buffer))
    if not 0 < length < len(buffer) or buffer.value == str(source):
        record_property("required_capability_status", "unsupported-required:short-name-fixture")
        pytest.xfail("unsupported-required: no distinct short-name fixture")
    alias = Path(buffer.value)
    with safe._WindowsMetadataProof(alias, alias.parent) as proof:
        identity = proof.metadata()
    with safe._WindowsMetadataProof(source, tmp_path) as proof:
        assert proof.metadata() == identity
    record_property("distinct_short_alias_observed", "true")


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
@pytest.mark.parametrize("kind", ["directory", "hardlink", "missing"])
def test_windows_nonregular_native(tmp_path, kind):
    """Actual directory, multiple-link or missing final sources must never authorize metadata."""
    source = tmp_path / "synthetic.log"
    if kind == "directory":
        source.mkdir()
    elif kind == "hardlink":
        source.write_bytes(b"synthetic\n")
        os.link(source, tmp_path / "second.log")
    with pytest.raises(safe.PathPolicyError):
        safe._WindowsMetadataProof(source, tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
def test_windows_junction_ancestor_native(tmp_path, record_property):
    """A real owned junction to an outside sibling must be refused before following it further."""
    import _winapi

    allowed, outside = tmp_path / "allowed", tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (outside / "synthetic.log").write_bytes(b"synthetic\n")
    junction = allowed / "junction"
    _winapi.CreateJunction(str(outside), str(junction))
    try:
        with pytest.raises(safe.PathPolicyError) as error:
            safe._WindowsMetadataProof(junction / "synthetic.log", allowed)
        assert error.value.capability == "windows-reparse-or-recall"
    finally:
        os.rmdir(junction)  # Remove exactly the owned junction, never its target tree.
    assert outside.is_dir()
    record_property("native_junction_cleanup", "complete")


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
def test_windows_final_symlink_native(tmp_path, record_property):
    """An actual final symlink must refuse; unavailable creation privilege is a required finding."""
    source = tmp_path / "synthetic.log"
    source.write_bytes(b"synthetic\n")
    link = tmp_path / "link.log"
    try:
        link.symlink_to(source)
    except OSError as error:
        record_property("required_capability_status", "unsupported-required:symlink-fixture")
        record_property("native_error_code", error.winerror)
        pytest.xfail("unsupported-required: native symlink fixture unavailable")
    try:
        with pytest.raises(safe.PathPolicyError) as error:
            safe._WindowsMetadataProof(link, tmp_path)
        assert error.value.capability == "windows-reparse-or-recall"
    finally:
        link.unlink()


def _assert_blocked_windows_rename_revalidation(proof, native, record_property):
    """A blocked rename permits stable metadata, detected change, or exact safe expiry."""
    metadata = None
    try:
        metadata = proof.metadata()
    except safe.PathPolicyError as changed:
        if changed.code == "SOURCE_CHANGED":
            outcome = "blocked-and-invalidated"
        else:
            assert changed.code == "SOURCE_NOT_LOCAL"
            assert changed.capability == "windows-metadata-deadline"
            outcome = "blocked-and-expired"
            record_property("mutation_revalidation_qualification", "not-exercised-deadline")
        assert metadata is None and native.open_count == native.close_count
        with pytest.raises(safe.PathPolicyError) as poisoned:
            proof.metadata()
        assert poisoned.value.code == "SOURCE_CHANGED"
    else:
        assert metadata.file_id > 0
        outcome = "blocked"
    record_property("native_rename_outcome", outcome)


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
@pytest.mark.parametrize("which", ["source", "ancestor", "outside-ancestor"])
def test_windows_pinned_rename_native(tmp_path, which, record_property):
    """Actual pinned file/directory rename attempts must fail or invalidate before reuse."""
    root = tmp_path / "outer" / "allowed"
    nested = root / "nested"
    nested.mkdir(parents=True)
    source = nested / "synthetic.log"
    source.write_bytes(b"synthetic\n")
    target = {"source": source, "ancestor": nested, "outside-ancestor": root.parent}[which]
    native = safe._NativeWindows(safe._MetadataBudget())
    with safe._WindowsMetadataProof(source, root, _native=native) as proof:
        try:
            target.rename(tmp_path / "moved")
        except OSError as error:
            assert error.winerror in (5, 32, 33)
            record_property("native_os_rename_refused", "true")
            _assert_blocked_windows_rename_revalidation(proof, native, record_property)
        else:
            with pytest.raises(safe.PathPolicyError) as changed:
                proof.metadata()
            assert changed.value.code == "SOURCE_CHANGED"
            record_property("native_rename_outcome", "detected")
    assert native.open_count == native.close_count
    record_property("native_handle_cleanup", "complete")


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata proof")
def test_windows_rewrite_and_enter_failure_cleanup_native(configured):
    """A restored-mtime rewrite must invalidate metadata and failed context entry must
    close handles.
    """
    _, source = configured
    native = safe._NativeWindows(safe._MetadataBudget())
    proof = safe._WindowsMetadataProof(source, source.parent, _native=native)
    old = source.stat()
    source.write_bytes(b"changed\n")
    os.utime(source, ns=(old.st_atime_ns, old.st_mtime_ns))
    with pytest.raises(safe.PathPolicyError) as error:
        proof.__enter__()
    assert error.value.code == "SOURCE_CHANGED"
    assert native.open_count == native.close_count


@pytest.mark.skipif(os.name != "nt", reason="Windows actual ordinal comparison")
def test_windows_ordinal_components_native():
    """Windows ordinal comparison must reject sibling prefixes and Unicode casefold expansion."""
    native = safe._NativeWindows(safe._MetadataBudget())
    volume = "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\"
    assert native.ordinal_equal("Logs", "LOGS")
    assert not native.ordinal_equal("Straße", "STRASSE")
    assert safe._windows_under(native, volume + "Logs\\file", volume + "LOGS")
    assert not safe._windows_under(native, volume + "Logs-other\\file", volume + "Logs")
    assert not safe._windows_under(native, volume + "Logs", volume + "Logs")


class MockWindowsMetadata:
    """Injected mechanism only; cannot attest native Windows capability."""

    def __init__(self):
        self.opened = {}
        self.closed = []
        self.paths = {}
        self.change = None

    def open(self, path):
        key = str(path)
        if key not in self.paths:
            self.paths[key] = len(self.paths) + 1
        handle = len(self.opened) + 1
        canonical = "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\" + "\\".join(
            path.parts[1:]
        )
        directory = not path.name.endswith(".log")
        snapshot = safe._WindowsSnapshot(
            safe.FileIdentity(42, self.paths[key], 0, 2, 3),
            0x10 if directory else 0x20,
            0,
            directory,
            1,
            False,
            False,
            canonical,
        )
        self.opened[handle] = snapshot
        return handle

    def snapshot(self, handle):
        value = self.opened[handle]
        return value if self.change is None else self.change(value)

    def close(self, handle):
        assert handle not in self.closed
        self.closed.append(handle)

    @staticmethod
    def ordinal_equal(left, right):
        return left.upper() == right.upper()  # ASCII mechanism cases only, never Unicode proof.


def test_mock_windows_blocked_rename_expiry_is_refusal_not_mutation_proof(tmp_path, monkeypatch):
    """what_bug_this_catches: safe expiry was rejected or counted as mutation qualification."""
    clock = [0.0]
    monkeypatch.setattr(safe, "monotonic", lambda: clock[0])
    native = MockWindowsMetadata()
    # The recorder exercises the native test's classification, without claiming an OS rename.
    records = {}
    with safe._WindowsMetadataProof(tmp_path / "synthetic.log", tmp_path, _native=native) as proof:
        native.open_count = len(native.opened)
        native.close_count = 0
        original_close = native.close

        def close(handle):
            original_close(handle)
            native.close_count += 1

        native.close = close
        clock[0] = safe.WINDOWS_METADATA_SECONDS
        _assert_blocked_windows_rename_revalidation(proof, native, records.__setitem__)
    assert sorted(native.closed) == sorted(native.opened)
    assert records["native_rename_outcome"] == "blocked-and-expired"
    assert records["mutation_revalidation_qualification"] == "not-exercised-deadline"


@pytest.mark.parametrize(
    "code,capability",
    [
        ("SOURCE_NOT_LOCAL", "windows-metadata-call-limit"),
        ("SOURCE_NOT_LOCAL", "windows-canonical-budget"),
        ("PATH_FORBIDDEN", "windows-metadata-deadline"),
    ],
)
def test_mock_windows_blocked_rename_rejects_unrelated_refusal(tmp_path, code, capability):
    """what_bug_this_catches: arbitrary refusal cannot silently satisfy rename qualification."""
    native = MockWindowsMetadata()
    with safe._WindowsMetadataProof(tmp_path / "synthetic.log", tmp_path, _native=native) as proof:

        def refuse(_snapshot):
            raise safe.PathPolicyError(code, capability=capability)

        native.change = refuse
        with pytest.raises(AssertionError):
            _assert_blocked_windows_rename_revalidation(proof, native, lambda *_: None)
    assert sorted(native.closed) == sorted(native.opened)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tag", 0xA0000003),
        ("attributes", 0x1000),
        ("attributes", 0x40000),
        ("attributes", 0x400000),
        ("attributes", 0x80000000),
        ("case_sensitive", True),
        ("delete_pending", True),
        ("attributes", 0x20),
        ("links", 0),
    ],
)
def test_mock_windows_unsafe_metadata_refused(tmp_path, field, value):
    """Unknown/reparse/recall/case/delete state must refuse and close every acquired mock handle."""
    native = MockWindowsMetadata()
    native.change = lambda snapshot: replace(snapshot, **{field: value})
    with pytest.raises(safe.PathPolicyError):
        safe._WindowsMetadataProof(tmp_path / "synthetic.log", tmp_path, _native=native)
    assert sorted(native.closed) == sorted(native.opened)


@pytest.mark.parametrize("field", ["file_id", "volume_id", "change_time_ns"])
def test_mock_windows_postcheck_identity_change(tmp_path, field):
    """Post-acquisition metadata mutation must invalidate the proof instead of reusing old
    identity.
    """
    native = MockWindowsMetadata()
    with safe._WindowsMetadataProof(tmp_path / "synthetic.log", tmp_path, _native=native) as proof:
        native.change = lambda snapshot: replace(
            snapshot, identity=replace(snapshot.identity, **{field: 999})
        )
        with pytest.raises(safe.PathPolicyError):
            proof.metadata()
        native.change = None
        with pytest.raises(safe.PathPolicyError):
            proof.metadata()  # A failed validation poisons/closes the proof permanently.
    assert sorted(native.closed) == sorted(native.opened)


@pytest.mark.parametrize("scope", ["outside", "root", "descendant", "source"])
@pytest.mark.parametrize("field", ["size_bytes", "mtime_ns", "change_time_ns"])
def test_mock_windows_mutable_metadata_scope(tmp_path, scope, field):
    """Unrelated ancestor churn must not refuse; root and descendant evidence stays guarded."""
    root = tmp_path / "allowed"
    source = root / "nested" / "synthetic.log"
    target = {"outside": tmp_path, "root": root, "descendant": source.parent, "source": source}[
        scope
    ]
    native = MockWindowsMetadata()
    with safe._WindowsMetadataProof(source, root, _native=native) as proof:
        target_id = native.paths[str(target)]
        native.change = lambda snapshot: (
            replace(snapshot, identity=replace(snapshot.identity, **{field: 999}))
            if snapshot.identity.file_id == target_id
            else snapshot
        )
        if scope == "outside":
            assert proof.metadata().file_id == native.paths[str(source)]
        else:
            with pytest.raises(safe.PathPolicyError) as error:
                proof.metadata()
            assert error.value.code == "SOURCE_CHANGED"
            assert error.value.capability == f"windows-changed-{field}"
    assert sorted(native.closed) == sorted(native.opened)


@pytest.mark.parametrize(
    "field,value",
    [
        ("file_id", 999),
        ("volume_id", 999),
        ("attributes", 0x11),
        ("tag", 0xA0000003),
        ("case_sensitive", True),
        ("delete_pending", True),
        ("links", 2),
        ("final_path", "changed"),
    ],
)
def test_mock_windows_outside_ancestor_structural_mutation(tmp_path, field, value):
    """Outside-root identity, path, reparse and object-state changes must still refuse and close."""
    root = tmp_path / "allowed"
    native = MockWindowsMetadata()
    with safe._WindowsMetadataProof(root / "synthetic.log", root, _native=native) as proof:
        target_id = native.paths[str(tmp_path)]

        def change(snapshot):
            if snapshot.identity.file_id != target_id:
                return snapshot
            if field in ("file_id", "volume_id"):
                return replace(snapshot, identity=replace(snapshot.identity, **{field: value}))
            actual = snapshot.final_path + "\\changed" if field == "final_path" else value
            return replace(snapshot, **{field: actual})

        native.change = change
        with pytest.raises(safe.PathPolicyError):
            proof.metadata()
    assert sorted(native.closed) == sorted(native.opened)


def test_mock_windows_canonical_budget_and_error_cleanup(tmp_path, monkeypatch):
    """Canonical/intermediate budgets and unexpected OS failures must close handles without
    raw echo.
    """
    native = MockWindowsMetadata()
    monkeypatch.setattr(safe, "MAX_WINDOWS_CANONICAL_UNITS", 1)
    with pytest.raises(safe.PathPolicyError) as error:
        safe._WindowsMetadataProof(tmp_path / "synthetic.log", tmp_path, _native=native)
    assert error.value.capability == "windows-canonical-budget"
    assert sorted(native.closed) == sorted(native.opened)


def test_mock_windows_call_and_deadline_bounds(monkeypatch):
    """Native operation limits must stop before issuing excess calls, including cooperative
    expiry.
    """
    monkeypatch.setattr(safe, "monotonic", lambda: 0)
    budget = safe._MetadataBudget()
    budget.calls = safe.MAX_WINDOWS_METADATA_CALLS
    calls = []
    with pytest.raises(safe.PathPolicyError):
        budget.call(lambda: calls.append(True))
    assert calls == []
    monkeypatch.setattr(safe, "monotonic", lambda: 3)
    with pytest.raises(safe.PathPolicyError) as error:
        budget.check()
    assert error.value.capability == "windows-metadata-deadline"


def test_mock_windows_malformed_canonical_and_config_bounds(tmp_path):
    """Malformed internal names or excess configured components/chars must fail before
    native I/O.
    """
    for value in ("C:\\file", "\\\\server\\file", "\\\\?\\Volume{bad}\\file"):
        with pytest.raises(safe.PathPolicyError):
            safe._windows_parts(value)
    for path in (str(tmp_path / ("x" * 32768)), str(tmp_path.joinpath(*(["x"] * 257)))):
        with pytest.raises(safe.PathPolicyError):
            safe._configured_path(path)


def test_mock_windows_deadline_after_open_closes_new_handle(tmp_path, monkeypatch):
    """A deadline crossed inside CreateFile must still close the just-acquired metadata handle."""
    import ctypes

    clock = [0]
    monkeypatch.setattr(safe, "monotonic", lambda: clock[0])
    native = object.__new__(safe._NativeWindows)
    native.budget = safe._MetadataBudget()
    native.ctypes = ctypes
    native.open_count = native.close_count = 0
    native.drive_type = lambda anchor: 3
    closed = []
    native.close_handle = lambda handle: closed.append(handle) or True

    def create(*args):
        assert args[1] == 0x80
        clock[0] = 3
        return 123

    native.create = create
    with pytest.raises(safe.PathPolicyError) as error:
        native.open(tmp_path / "synthetic.log")
    assert error.value.capability == "windows-metadata-deadline"
    assert closed == [123] and native.open_count == native.close_count == 1


def test_mock_windows_unexpected_error_is_sanitized_and_closed(tmp_path, monkeypatch):
    """Unexpected backend failures must hide raw diagnostics and close every acquired handle."""
    native = MockWindowsMetadata()

    def fail(handle):
        raise OSError("private-path-and-content-sentinel")

    monkeypatch.setattr(native, "snapshot", fail)
    with pytest.raises(safe.PathPolicyError) as error:
        safe._WindowsMetadataProof(tmp_path / "synthetic.log", tmp_path, _native=native)
    assert str(error.value) == "The source changed during authorized access."
    assert error.value.__suppress_context__
    assert sorted(native.closed) == sorted(native.opened)


def test_mock_windows_root_shape_cannot_expand_authority(tmp_path):
    """Internal metadata entry must reuse the existing broad-root refusal before any native open."""
    native = MockWindowsMetadata()
    with pytest.raises(safe.PathPolicyError):
        safe._WindowsMetadataProof(
            tmp_path / "synthetic.log", Path(tmp_path.anchor), _native=native
        )
    assert native.opened == {}


def test_mock_windows_containment_negative_control(tmp_path, monkeypatch):
    """The containment assertion must fail when the actual ancestry comparison is sabotaged."""
    native = MockWindowsMetadata()

    def other_tree(snapshot):
        if snapshot.directory:
            return snapshot
        parts = safe._windows_parts(snapshot.final_path)
        return replace(snapshot, final_path=parts[0] + "\\".join(("different", *parts[2:])))

    native.change = other_tree
    with pytest.raises(safe.PathPolicyError):
        safe._WindowsMetadataProof(tmp_path / "synthetic.log", tmp_path, _native=native)
    sabotaged = MockWindowsMetadata()
    sabotaged.change = other_tree
    monkeypatch.setattr(safe, "_windows_under", lambda *args, **kwargs: True)

    def must_refuse():
        try:
            with safe._WindowsMetadataProof(
                tmp_path / "synthetic.log", tmp_path, _native=sabotaged
            ):
                pass
        except safe.PathPolicyError:
            return
        raise AssertionError("containment sabotage escaped the expected rejection")

    with pytest.raises(AssertionError, match="containment sabotage"):
        must_refuse()


def test_mock_domain_error_suppresses_existing_raw_context():
    """Sanitized domain failures must suppress a caller's active raw OS exception context."""
    import traceback

    def domain_failure():
        raise safe.PathPolicyError("SOURCE_CHANGED")

    try:
        try:
            raise OSError("private-path-and-content-sentinel")
        except OSError:
            domain_failure()
    except safe.PathPolicyError as error:
        rendered = "".join(traceback.format_exception(error))
        # Traceback includes source lines but must not print the prior OS exception value.
        assert "OSError: private-path-and-content-sentinel" not in rendered
        assert error.__suppress_context__


@pytest.mark.skipif(os.name != "nt", reason="Windows actual metadata mutation")
def test_windows_directory_entry_mutation_native(configured, record_property):
    """An owned directory-entry mutation must explicitly invalidate a previously stable chain."""
    _, source = configured
    with safe._WindowsMetadataProof(source, source.parent) as proof:
        (source.parent / "new-owned-entry").mkdir()
        with pytest.raises(safe.PathPolicyError) as error:
            proof.metadata()
        assert error.value.code == "SOURCE_CHANGED"
        assert error.value.capability in {
            "windows-changed-size_bytes",
            "windows-changed-mtime_ns",
            "windows-changed-change_time_ns",
        }
        record_property("native_mutation_field", error.value.capability)


@pytest.mark.skipif(os.name != "nt", reason="Windows actual sibling mutation")
def test_windows_outside_root_sibling_mutation_native(tmp_path, record_property):
    """Creating an unrelated sibling must not invalidate pinned configured-root metadata."""
    root = tmp_path / "allowed"
    root.mkdir()
    source = root / "synthetic.log"
    source.write_bytes(b"synthetic\n")
    native = safe._NativeWindows(safe._MetadataBudget())
    with safe._WindowsMetadataProof(source, root, _native=native) as proof:
        before = proof.metadata()
        (tmp_path / "unrelated-owned-sibling").mkdir()
        assert proof.metadata() == before
    assert native.open_count == native.close_count
    assert not safe.capabilities()["data_access_available"]
    record_property("source_data_access_available", "false")
    record_property("native_handle_cleanup", "complete")
