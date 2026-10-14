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
    if not path.is_absolute():
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


def _windows_probe(path: Path) -> tuple[FileIdentity, int, str]:
    """Native metadata-only capability spike. Never used to authorize data reads.

    Caller must supply a newly-created synthetic fixture. The returned path is
    private authorization data; never include it in a receipt or public response.
    """
    if os.name != "nt":
        raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-metadata")
    import ctypes
    from ctypes import wintypes

    class BasicInfo(ctypes.Structure):
        _fields_ = [
            ("creation", ctypes.c_longlong),
            ("access", ctypes.c_longlong),
            ("write", ctypes.c_longlong),
            ("change", ctypes.c_longlong),
            ("attributes", wintypes.DWORD),
        ]

    class HandleInfo(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation", wintypes.FILETIME),
            ("access", wintypes.FILETIME),
            ("write", wintypes.FILETIME),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    basic_query = kernel.GetFileInformationByHandleEx
    basic_query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    basic_query.restype = wintypes.BOOL
    identity_query = kernel.GetFileInformationByHandle
    identity_query.argtypes = [wintypes.HANDLE, ctypes.POINTER(HandleInfo)]
    identity_query.restype = wintypes.BOOL
    final_query = kernel.GetFinalPathNameByHandleW
    final_query.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    final_query.restype = wintypes.DWORD
    # FILE_READ_ATTRIBUTES; share read/write/delete; OPEN_EXISTING; flags are
    # OPEN_REPARSE_POINT | OPEN_NO_RECALL | BACKUP_SEMANTICS. No FILE_READ_DATA.
    handle = create(str(path), 0x80, 7, None, 3, 0x02300000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-metadata")
    try:
        basic, info = BasicInfo(), HandleInfo()
        buffer = ctypes.create_unicode_buffer(32768)
        length = final_query(handle, buffer, len(buffer), 0)
        if (
            not basic_query(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic))
            or not identity_query(handle, ctypes.byref(info))
            or not 0 < length < len(buffer)
        ):
            raise PathPolicyError("SOURCE_NOT_LOCAL", capability="windows-metadata")
        global _WINDOWS_OBSERVED
        _WINDOWS_OBSERVED = True
        epoch = 116444736000000000
        identity = FileIdentity(
            info.volume,
            info.index_high << 32 | info.index_low,
            info.size_high << 32 | info.size_low,
            (basic.write - epoch) * 100,
            (basic.change - epoch) * 100,
        )
        return identity, basic.attributes, buffer.value
    finally:
        close(handle)
