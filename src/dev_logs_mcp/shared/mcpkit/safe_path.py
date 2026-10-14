"""Configured-source authorization with bounded, identity-checked reads.

Windows data access is deliberately unavailable until the no-recall race proof is
available. Native metadata probes are diagnostic primitives, not that proof.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from time import monotonic
from typing import Any

_MESSAGES = {
    "UNKNOWN_SOURCE": "The configured source is unknown.",
    "CONFIG_INVALID": "The source policy configuration is invalid.",
    "PATH_FORBIDDEN": "The source path is forbidden by policy.",
    "SOURCE_NOT_LOCAL": "Required local filesystem safety is unavailable.",
    "NOT_REGULAR_FILE": "The source is not an authorized regular file.",
    "SOURCE_MISSING": "The configured source is missing.",
    "SOURCE_CHANGED": "The source changed during authorized access.",
}
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_DEVICE = re.compile(
    r"(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])(?:\..*)?\Z", re.I
)
_WINDOWS_OBSERVED = False
_WINDOWS_CHAIN_OBSERVED = False
_WINDOWS_API_UNAVAILABLE: set[str] = set()
MAX_WINDOWS_COMPONENTS = 256
MAX_WINDOWS_PATH_UNITS = 32767
MAX_WINDOWS_CANONICAL_UNITS = 262144
MAX_WINDOWS_METADATA_CALLS = 4096
WINDOWS_METADATA_SECONDS = 2.0


class PathPolicyError(Exception):
    """Value-free domain failure, suitable for translation by a tool adapter."""

    def __init__(self, code: str, *, capability: str | None = None) -> None:
        if code not in _MESSAGES:
            code = "PATH_FORBIDDEN"
        self.code = code
        self.message = _MESSAGES[code]
        self.hint = "Use an explicitly configured local source with supported safety checks."
        self.capability = capability
        super().__init__(self.message)
        self.__suppress_context__ = True

    def __repr__(self) -> str:
        return f"PathPolicyError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class FileIdentity:
    volume_id: int
    file_id: int
    size_bytes: int
    mtime_ns: int
    change_time_ns: int | None


def capabilities() -> dict[str, Any]:
    """Report implemented methods separately from actual observed OS execution."""
    windows = os.name == "nt"
    proc = os.name == "posix" and Path("/proc/self/fd").is_dir()
    return {
        "platform": os.name,
        "methods": (
            [
                "CreateFileW-metadata-only",
                "GetFileInformationByHandleEx",
                "GetFinalPathNameByHandleW",
            ]
            if windows
            else ["openat-O_NOFOLLOW", "fstat", "proc-fd-final-path"]
        ),
        "windows_metadata_observed": _WINDOWS_OBSERVED if windows else False,
        "windows_no_recall_race_proven": False,
        "windows_final_containment_authorization_proven": False,
        "windows_metadata_chain_observed": _WINDOWS_CHAIN_OBSERVED if windows else False,
        "windows_capability_status": {
            "ancestor_metadata": "observed"
            if _WINDOWS_CHAIN_OBSERVED
            else "implemented-unobserved",
            "data_authorization": "unimplemented",
            "no_recall_race": "unproven",
            "measured_api_unavailable": sorted(_WINDOWS_API_UNAVAILABLE),
        }
        if windows
        else {},
        "data_access_available": not windows and proc and hasattr(os, "O_NOFOLLOW"),
        "unsupported_required": (
            ["windows-no-recall-race", "windows-final-containment-authorization"]
            + ([] if _WINDOWS_OBSERVED else ["windows-metadata-change-time-unobserved"])
            if windows
            else ([] if proc and hasattr(os, "O_NOFOLLOW") else ["opened-handle-final-path"])
        ),
        "limitations": [
            "Metadata flag acceptance does not prove cloud recall race safety.",
            "Platform support requires separate real OS execution receipts.",
        ],
    }


def _configured_path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)):
        raise PathPolicyError("CONFIG_INVALID")
    text = str(value)
    if len(text) > MAX_WINDOWS_PATH_UNITS:
        raise PathPolicyError("CONFIG_INVALID")
    # Reject Windows ambiguity on every host, including relative drive and ADS forms.
    win = PureWindowsPath(text)
    if (
        not text
        or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in text)
        or text.startswith(("\\\\", "//"))
        or ".." in re.split(r"[/\\]", text)
        or any(_DEVICE.fullmatch(part.rstrip(" .")) for part in re.split(r"[/\\]", text))
        or any(part.endswith((" ", ".")) for part in re.split(r"[/\\]", text) if part)
        or any(char in text for char in '<>"|?*')
        or ":" in text[2:]
        or (":" in text and not (len(text) > 2 and text[1] == ":" and win.is_absolute()))
    ):
        raise PathPolicyError("CONFIG_INVALID")
    path = Path(text)
    if not path.is_absolute() or len(path.parts) > MAX_WINDOWS_COMPONENTS:
        raise PathPolicyError("CONFIG_INVALID")
    return path


class SafePathPolicy:
    """Authorize only opaque IDs bound to trusted, absolute configured paths."""

    def __init__(
        self, allowed_roots: Sequence[str | Path], sources: Mapping[str, str | Path]
    ) -> None:
        if (
            not isinstance(allowed_roots, Sequence)
            or isinstance(allowed_roots, (str, bytes, Path))
            or not allowed_roots
        ):
            raise PathPolicyError("CONFIG_INVALID")
        if not isinstance(sources, Mapping):
            raise PathPolicyError("CONFIG_INVALID")
        roots = tuple(_configured_path(root) for root in allowed_roots)
        home = Path.home()
        for root in roots:
            # Ancestors of home are broad too (e.g. C:\Users, /home).
            if root == Path(root.anchor) or root == home or root in home.parents:
                raise PathPolicyError("CONFIG_INVALID")
        configured: dict[str, tuple[Path, Path]] = {}
        for source_id, value in sources.items():
            if not isinstance(source_id, str) or not _ID.fullmatch(source_id):
                raise PathPolicyError("CONFIG_INVALID")
            path = _configured_path(value)
            matches = [root for root in roots if path != root and path.is_relative_to(root)]
            if not matches:
                raise PathPolicyError("CONFIG_INVALID")
            configured[source_id] = (path, max(matches, key=lambda root: len(root.parts)))
        self._sources = configured

    def __repr__(self) -> str:
        return "SafePathPolicy(<configured sources>)"

    def capabilities(self) -> dict[str, Any]:
        return capabilities()

    def open_source(self, source_id: str) -> AuthorizedReadHandle:
        if not isinstance(source_id, str) or not _ID.fullmatch(source_id):
            raise PathPolicyError("UNKNOWN_SOURCE")
        entry = self._sources.get(source_id)
        if entry is None:
            raise PathPolicyError("UNKNOWN_SOURCE")
        if os.name == "nt":
            # Even OPEN_NO_RECALL acceptance is not a guarantee for cloud providers.
            # Refuse before any data-bearing CreateFile call or source metadata I/O.
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-no-recall-race")
        if not capabilities()["data_access_available"]:
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="opened-handle-final-path")
        path, root = entry
        try:
            fd = _posix_open(path)
        except FileNotFoundError:
            raise PathPolicyError("SOURCE_MISSING") from None
        except OSError:
            raise PathPolicyError("PATH_FORBIDDEN") from None
        try:
            return AuthorizedReadHandle(fd, path, root)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass  # Preserve the original sanitized authorization failure.
            raise


def _posix_open(path: Path) -> int:
    """Walk every ancestor with no-follow and pin each directory during descent."""
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
            )
            os.close(directory)
            directory = child
        return os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory,
        )
    finally:
        os.close(directory)


def _identity(info: os.stat_result) -> FileIdentity:
    return FileIdentity(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _posix_local(fd: int) -> None:
    """Accept only a small allowlist of Linux local filesystem types.

    In particular overlay, FUSE and network mounts do not imply local storage.
    Kernel metadata reads are not source-data reads.
    """
    try:
        fields = Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines()
        mount_id = next(line.split()[1] for line in fields if line.startswith("mnt_id:"))
        mounts = Path("/proc/self/mountinfo").read_text().splitlines()
        entry = next(line for line in mounts if line.split()[0] == mount_id)
        fs_type = entry.split(" - ", 1)[1].split()[0]
        if fs_type not in {"ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs", "ramfs"}:
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="local-filesystem")
    except (OSError, StopIteration, IndexError, ValueError):
        raise PathPolicyError("SOURCE_NOT_LOCAL", capability="local-filesystem") from None


class AuthorizedReadHandle:
    """A bounded read interface; no public raw descriptor or unbounded reads."""

    def __init__(self, fd: int, path: Path, root: Path) -> None:
        self.__fd = fd
        self.__path = path
        self.__root = root
        self.__closed = False
        self.__read_bytes = 0
        self.__initial = self.__check()

    def __repr__(self) -> str:
        return f"AuthorizedReadHandle(closed={self.__closed}, read_bytes={self.__read_bytes})"

    @property
    def read_bytes(self) -> int:
        return self.__read_bytes

    def __check(self) -> FileIdentity:
        if self.__closed:
            raise PathPolicyError("SOURCE_CHANGED")
        try:
            info = os.fstat(self.__fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PathPolicyError("NOT_REGULAR_FILE")
            _posix_local(self.__fd)
            final = Path(os.readlink(f"/proc/self/fd/{self.__fd}"))
            if final != self.__path or not final.is_relative_to(self.__root):
                raise PathPolicyError("PATH_FORBIDDEN")
            named = os.stat(self.__path, follow_symlinks=False)
            if not stat.S_ISREG(named.st_mode) or _identity(named) != _identity(info):
                raise PathPolicyError("SOURCE_CHANGED")
            identity = _identity(info)
            if hasattr(self, "_AuthorizedReadHandle__initial") and identity != self.__initial:
                raise PathPolicyError("SOURCE_CHANGED")
            return identity
        except OSError:
            raise PathPolicyError("SOURCE_CHANGED") from None

    def read(self, size: int) -> bytes:
        if type(size) is not int or not 1 <= size <= 65536:
            raise PathPolicyError("PATH_FORBIDDEN")
        self.__check()
        try:
            data = os.read(self.__fd, size)
        except OSError:
            raise PathPolicyError("SOURCE_CHANGED") from None
        self.__read_bytes += len(data)
        self.__check()
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if type(offset) is not int or type(whence) is not int or whence not in (0, 1, 2):
            raise PathPolicyError("PATH_FORBIDDEN")
        self.__check()
        try:
            return os.lseek(self.__fd, offset, whence)
        except (OSError, OverflowError):
            raise PathPolicyError("PATH_FORBIDDEN") from None

    def tell(self) -> int:
        return self.seek(0, 1)

    def metadata(self) -> FileIdentity:
        return self.__check()

    def close(self) -> None:
        if not self.__closed:
            self.__closed = True
            try:
                os.close(self.__fd)
            except OSError:
                raise PathPolicyError("SOURCE_CHANGED") from None

    def __enter__(self) -> AuthorizedReadHandle:
        self.__check()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class _MetadataBudget:
    """Bound call count and check elapsed time around each synchronous native call.

    This cannot preempt a blocked kernel call. An outer process timeout remains
    necessary for adversarial driver stalls; no hard native-I/O latency claim.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.deadline = monotonic() + WINDOWS_METADATA_SECONDS

    def check(self) -> None:
        if monotonic() >= self.deadline:
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-metadata-deadline")

    def start_call(self) -> None:
        self.check()
        if self.calls == MAX_WINDOWS_METADATA_CALLS:
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-metadata-call-limit")
        self.calls += 1

    def call(self, function, *args):
        self.start_call()
        result = function(*args)
        self.check()
        return result


@dataclass(frozen=True, slots=True, repr=False)
class _WindowsSnapshot:
    identity: FileIdentity
    attributes: int
    tag: int
    directory: bool
    links: int
    delete_pending: bool
    case_sensitive: bool
    final_path: str

    def __repr__(self) -> str:
        return "WindowsSnapshot(<private metadata>)"


class _NativeWindows:
    """Read-attributes-only Win32 primitives; no source-data API is bound here."""

    def __init__(self, budget: _MetadataBudget) -> None:
        if os.name != "nt":
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-metadata")
        import ctypes
        from ctypes import wintypes

        self.ctypes, self.w = ctypes, wintypes
        self.budget = budget
        self.open_count = self.close_count = 0
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)

        def bind(name, args, result):
            try:
                function = getattr(kernel, name)
            except AttributeError:
                _WINDOWS_API_UNAVAILABLE.add(name)
                raise PathPolicyError(
                    "SOURCE_NOT_LOCAL", capability="windows-metadata-api"
                ) from None
            function.argtypes, function.restype = args, result
            return function

        self.create = bind(
            "CreateFileW",
            [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ],
            wintypes.HANDLE,
        )
        self.close_handle = bind("CloseHandle", [wintypes.HANDLE], wintypes.BOOL)
        self.query = bind(
            "GetFileInformationByHandleEx",
            [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
            wintypes.BOOL,
        )
        self.final = bind(
            "GetFinalPathNameByHandleW",
            [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD],
            wintypes.DWORD,
        )
        self.file_type = bind("GetFileType", [wintypes.HANDLE], wintypes.DWORD)
        self.drive_type = bind("GetDriveTypeW", [wintypes.LPCWSTR], wintypes.UINT)
        self.volume = bind(
            "GetVolumeInformationByHandleW",
            [
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPWSTR,
                wintypes.DWORD,
            ],
            wintypes.BOOL,
        )
        self.compare = bind(
            "CompareStringOrdinal",
            [wintypes.LPCWSTR, ctypes.c_int, wintypes.LPCWSTR, ctypes.c_int, wintypes.BOOL],
            ctypes.c_int,
        )

        class Basic(ctypes.Structure):
            _fields_ = [
                ("creation", ctypes.c_longlong),
                ("access", ctypes.c_longlong),
                ("write", ctypes.c_longlong),
                ("change", ctypes.c_longlong),
                ("attributes", wintypes.DWORD),
            ]

        class Standard(ctypes.Structure):
            _fields_ = [
                ("allocation", ctypes.c_longlong),
                ("size", ctypes.c_longlong),
                ("links", wintypes.DWORD),
                ("deleted", ctypes.c_ubyte),
                ("directory", ctypes.c_ubyte),
            ]

        class AttributeTag(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

        class Identity(ctypes.Structure):
            _fields_ = [("volume", ctypes.c_ulonglong), ("file", ctypes.c_ubyte * 16)]

        class Case(ctypes.Structure):
            _fields_ = [("flags", wintypes.DWORD)]

        self.Basic, self.Standard, self.AttributeTag = Basic, Standard, AttributeTag
        self.Identity, self.Case = Identity, Case

    def __repr__(self) -> str:
        return "NativeWindows(<metadata-only>)"

    def open(self, path: Path) -> int:
        # No network/removable filesystem and no FILE_READ_DATA or GENERIC_READ.
        if self.budget.call(self.drive_type, path.anchor) != 3:
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-fixed-volume")
        self.budget.start_call()
        handle = self.create(str(path), 0x80, 3, None, 3, 0x02300000, None)
        if handle == self.ctypes.c_void_p(-1).value:
            error = self.ctypes.get_last_error()
            code = "SOURCE_MISSING" if error in (2, 3) else "PATH_FORBIDDEN"
            raise PathPolicyError(code) from None
        self.open_count += 1
        try:
            self.budget.check()
        except BaseException:
            self.close(handle)
            raise
        return handle

    def close(self, handle: int) -> None:
        # Cleanup must still run after call/deadline exhaustion. No retries.
        if not self.close_handle(handle):
            raise PathPolicyError("SOURCE_CHANGED", capability="windows-handle-cleanup")
        self.close_count += 1

    def _info(self, handle, info_class, info_type):
        value = info_type()
        if not self.budget.call(
            self.query, handle, info_class, self.ctypes.byref(value), self.ctypes.sizeof(value)
        ):
            if self.ctypes.get_last_error() in (1, 50, 87):
                _WINDOWS_API_UNAVAILABLE.add(f"information-class-{info_class}")
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability=f"windows-info-{info_class}")
        return value

    def ordinal_equal(self, left: str, right: str) -> bool:
        result = self.budget.call(self.compare, left, -1, right, -1, True)
        if result not in (1, 2, 3):
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-ordinal-comparison")
        return result == 2

    def snapshot(self, handle: int) -> _WindowsSnapshot:
        if self.budget.call(self.file_type, handle) != 1:
            raise PathPolicyError("NOT_REGULAR_FILE")
        fs = self.ctypes.create_unicode_buffer(32)
        if not self.budget.call(self.volume, handle, None, 0, None, None, None, fs, len(fs)):
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-filesystem")
        if fs.value != "NTFS":
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-ntfs")
        basic = self._info(handle, 0, self.Basic)
        standard = self._info(handle, 1, self.Standard)
        tags = self._info(handle, 9, self.AttributeTag)
        identity = self._info(handle, 18, self.Identity)
        case = self._info(handle, 23, self.Case).flags if standard.directory else 0
        if case not in (0, 1) or basic.attributes != tags.attributes:
            raise PathPolicyError("SOURCE_CHANGED")
        buffer = self.ctypes.create_unicode_buffer(MAX_WINDOWS_PATH_UNITS + 1)
        length = self.budget.call(self.final, handle, buffer, len(buffer), 1)
        if not 0 < length < len(buffer):
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-final-guid-path")
        epoch = 116444736000000000
        file_identity = FileIdentity(
            identity.volume,
            int.from_bytes(identity.file, "little"),
            standard.size,
            (basic.write - epoch) * 100,
            (basic.change - epoch) * 100,
        )
        global _WINDOWS_OBSERVED
        _WINDOWS_OBSERVED = True
        return _WindowsSnapshot(
            file_identity,
            tags.attributes,
            tags.tag,
            bool(standard.directory),
            standard.links,
            bool(standard.deleted),
            bool(case),
            buffer.value,
        )


def _windows_parts(value: str) -> tuple[str, ...]:
    if (
        type(value) is not str
        or len(value) > MAX_WINDOWS_PATH_UNITS
        or "\x00" in value
        or any(part in (".", "..") for part in value.split("\\"))
    ):
        raise PathPolicyError("PATH_FORBIDDEN")
    parts = PureWindowsPath(value).parts
    if (
        not parts
        or len(parts) > MAX_WINDOWS_COMPONENTS
        or not re.fullmatch(
            r"\\\\\?\\Volume\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}\\", parts[0]
        )
    ):
        raise PathPolicyError("PATH_FORBIDDEN")
    return parts


def _windows_under(native, child: str, parent: str, *, strict: bool = True) -> bool:
    children, parents = _windows_parts(child), _windows_parts(parent)
    return (len(children) > len(parents) if strict else len(children) >= len(parents)) and all(
        native.ordinal_equal(left, right) for left, right in zip(children, parents, strict=False)
    )


def _windows_validate(snapshot: _WindowsSnapshot, *, directory: bool) -> None:
    known = (
        0x1 | 0x2 | 0x4 | 0x10 | 0x20 | 0x80 | 0x100 | 0x800 | 0x2000 | 0x4000 | 0x8000 | 0x20000
    )
    if snapshot.tag or snapshot.attributes & (0x400 | 0x1000 | 0x40000 | 0x400000):
        raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-reparse-or-recall")
    if snapshot.attributes & ~known or snapshot.case_sensitive:
        raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-attributes-or-case")
    if (
        snapshot.directory != directory
        or bool(snapshot.attributes & 0x10) != snapshot.directory
        or snapshot.links < 1
        or snapshot.delete_pending
        or (not directory and snapshot.links != 1)
    ):
        raise PathPolicyError("NOT_REGULAR_FILE")
    if (
        snapshot.identity.file_id <= 0
        or snapshot.identity.volume_id < 0
        or snapshot.identity.size_bytes < 0
        or snapshot.identity.change_time_ns is None
    ):
        raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-file-identity")
    _windows_parts(snapshot.final_path)


class _WindowsMetadataProof:
    """Internal metadata authorization only. Never provides a data handle or read API."""

    def __init__(self, path: Path, root: Path, *, _native=None) -> None:
        path, root = _configured_path(path), _configured_path(root)
        # Reuse the canonical configured-root/opaque-ID shape gate; no source I/O.
        SafePathPolicy([root], {"metadata": path})
        if (
            not path.is_relative_to(root)
            or path == root
            or len(str(path).encode("utf-16-le")) // 2 > MAX_WINDOWS_PATH_UNITS
        ):
            raise PathPolicyError("PATH_FORBIDDEN")
        self.__budget = _MetadataBudget()
        self.__native = _NativeWindows(self.__budget) if _native is None else _native
        self.__handles: list[tuple[int, _WindowsSnapshot, bool]] = []
        self.__closed = False
        self.__canonical_units = 0
        try:
            root_info = self._retain(root, directory=True)
            previous = None
            chain = list(reversed(path.parents)) + [path]
            for index, part in enumerate(chain):
                current = self._retain(part, directory=index < len(chain) - 1)
                if previous is not None and (
                    current.identity.volume_id != previous.identity.volume_id
                    or not _windows_under(self.__native, current.final_path, previous.final_path)
                    or len(_windows_parts(current.final_path))
                    != len(_windows_parts(previous.final_path)) + 1
                ):
                    raise PathPolicyError("PATH_FORBIDDEN")
                if index == len(root.parts) - 1 and (
                    current.identity != root_info.identity
                    or not self.__native.ordinal_equal(current.final_path, root_info.final_path)
                ):
                    raise PathPolicyError("PATH_FORBIDDEN")
                previous = current
            self.__final = current.identity
            if not _windows_under(self.__native, current.final_path, root_info.final_path):
                raise PathPolicyError("PATH_FORBIDDEN")
            self.metadata()
            if type(self.__native) is _NativeWindows:
                global _WINDOWS_CHAIN_OBSERVED
                _WINDOWS_CHAIN_OBSERVED = True
        except BaseException as error:
            self.close()
            if isinstance(error, PathPolicyError) or not isinstance(error, Exception):
                raise
            raise PathPolicyError("SOURCE_CHANGED") from None

    def __repr__(self) -> str:
        return f"WindowsMetadataProof(closed={self.__closed})"

    def _retain(self, path: Path, *, directory: bool) -> _WindowsSnapshot:
        self.__budget.check()
        handle = self.__native.open(path)
        try:
            snapshot = self.__native.snapshot(handle)
        except BaseException:
            self.__native.close(handle)
            raise
        self.__handles.append((handle, snapshot, directory))
        self.__canonical_units += len(snapshot.final_path.encode("utf-16-le")) // 2
        if self.__canonical_units > MAX_WINDOWS_CANONICAL_UNITS:
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-canonical-budget")
        _windows_validate(snapshot, directory=directory)
        return snapshot

    def metadata(self) -> FileIdentity:
        if self.__closed:
            raise PathPolicyError("SOURCE_CHANGED")
        try:
            for handle, before, directory in self.__handles:
                self.__budget.check()
                after = self.__native.snapshot(handle)
                _windows_validate(after, directory=directory)
                for field in ("volume_id", "file_id", "size_bytes", "mtime_ns", "change_time_ns"):
                    if getattr(before.identity, field) != getattr(after.identity, field):
                        raise PathPolicyError(
                            "SOURCE_CHANGED", capability=f"windows-changed-{field}"
                        )
                if (
                    before.attributes,
                    before.tag,
                    before.directory,
                    before.links,
                    before.delete_pending,
                    before.case_sensitive,
                ) != (
                    after.attributes,
                    after.tag,
                    after.directory,
                    after.links,
                    after.delete_pending,
                    after.case_sensitive,
                ):
                    raise PathPolicyError(
                        "SOURCE_CHANGED", capability="windows-changed-object-state"
                    )
                if not self.__native.ordinal_equal(before.final_path, after.final_path):
                    raise PathPolicyError("SOURCE_CHANGED", capability="windows-changed-final-path")
            self.__budget.check()
            return self.__final
        except PathPolicyError:
            self.close()
            raise
        except Exception:
            self.close()
            raise PathPolicyError("SOURCE_CHANGED") from None

    def close(self) -> None:
        if not self.__closed:
            self.__closed = True
            failed = False
            for handle, _snapshot, _directory in reversed(self.__handles):
                try:
                    self.__native.close(handle)
                except Exception:
                    failed = True
            self.__handles.clear()
            if failed:
                raise PathPolicyError("SOURCE_CHANGED", capability="windows-handle-cleanup")

    def __enter__(self) -> _WindowsMetadataProof:
        try:
            self.metadata()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _windows_probe(path: Path) -> tuple[FileIdentity, int, str]:
    """Owned synthetic metadata diagnostic; no authorization or no-recall data proof."""
    native = _NativeWindows(_MetadataBudget())
    handle = native.open(_configured_path(path))
    try:
        snapshot = native.snapshot(handle)
        return snapshot.identity, snapshot.attributes, snapshot.final_path
    finally:
        native.close(handle)
