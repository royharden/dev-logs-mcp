"""Explicit bounded source catalog; metadata listing never reads source content."""

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .config import AppConfig
from .index import ReadBudget, ReadFailure
from .shared.mcpkit.errors import MAX_SOURCES, ErrorCode
from .shared.mcpkit.models import SourceInfo
from .shared.mcpkit.redact import CustomRule, Redactor
from .shared.mcpkit.safe_path import PathPolicyError, SafePathPolicy, _posix_local

MAX_DIRECTORY_ENTRIES = 1000


def _same_named_directory(fd: int, path: Path) -> None:
    info = os.fstat(fd)
    named = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or Path(os.readlink(f"/proc/self/fd/{fd}")) != path
        or (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
        != (named.st_dev, named.st_ino, named.st_mtime_ns, named.st_ctime_ns)
    ):
        raise ReadFailure("SOURCE_CHANGED")


@dataclass(frozen=True, slots=True, repr=False)
class Source:
    id: str
    path: Path = field(repr=False)
    root: Path = field(repr=False)
    format: str = "auto"
    timezone: str = "UTC"


def _absolute(base: Path, value: str) -> Path:
    # Do not resolve(): following a symlink here would erase policy evidence.
    candidate = Path(value)
    return candidate if candidate.is_absolute() else base / candidate


def _metadata_open(path: Path, *, directory: bool) -> int:
    """Linux O_PATH walker, with no source-data permission or reparse following."""
    if os.name != "posix" or not hasattr(os, "O_PATH"):
        raise ReadFailure("SOURCE_NOT_LOCAL")
    fd = None
    try:
        fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in path.parts[1:-1]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        flags = os.O_RDONLY | os.O_DIRECTORY if directory else os.O_PATH
        result = os.open(path.name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            _posix_local(result)
            return result
        except BaseException:
            os.close(result)
            raise
    except FileNotFoundError:
        raise ReadFailure("SOURCE_MISSING") from None
    except OSError:
        raise ReadFailure("PATH_FORBIDDEN") from None
    finally:
        if fd is not None:
            os.close(fd)


class SourceCatalog:
    def __init__(self, config: AppConfig, base: Path, *, budget: ReadBudget | None = None):
        if not base.is_absolute() or ".." in base.parts:
            raise ReadFailure("CONFIG_INVALID")
        budget = budget or ReadBudget()
        self.tool_limits = config.tool_limits
        roots = tuple(_absolute(base, root) for root in config.allowed_roots)
        sources: dict[str, Source] = {}
        # Validate authority lexically BEFORE any directory enumeration.
        probes = {
            item.id: _absolute(base, item.path) / ".catalog-probe"
            if item.kind == "directory"
            else _absolute(base, item.path)
            for item in config.sources
        }
        SafePathPolicy(roots, probes)
        for item in config.sources:
            budget.check()
            path = _absolute(base, item.path)
            if item.kind == "file":
                paths = [(item.id, path)]
            else:
                paths = self._discover(path, item.id, item.extensions, budget)
            for source_id, source_path in paths:
                if source_id in sources or len(sources) >= MAX_SOURCES:
                    raise ReadFailure("CONFIG_INVALID")
                matched = [
                    root
                    for root in roots
                    if source_path != root and source_path.is_relative_to(root)
                ]
                if not matched:
                    raise ReadFailure("CONFIG_INVALID")
                root = max(matched, key=lambda value: len(value.parts))
                sources[source_id] = Source(
                    source_id, source_path, root, item.format, item.timezone
                )
        if not sources:
            raise ReadFailure("CONFIG_INVALID")
        self._sources = sources
        self.custom_rules = tuple(
            CustomRule(rule.type_name, rule.pattern) for rule in config.redaction_rules
        )
        self._policy = SafePathPolicy(roots, {key: value.path for key, value in sources.items()})
        # Fingerprint is private metadata; never persist configured path strings.
        self.config_hash = hashlib.sha256(
            json.dumps(
                {
                    "base": str(base),
                    "config": config.model_dump(),
                    "pipeline": "S1-v1-parse-redact-generation",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    @staticmethod
    def _discover(path: Path, source_id: str, extensions: list[str], budget: ReadBudget):
        fd = _metadata_open(path, directory=True)
        results = []
        try:
            _same_named_directory(fd, path)
            before = os.fstat(fd)
            with os.scandir(fd) as entries:
                for count, entry in enumerate(entries, 1):
                    budget.check()
                    if count > MAX_DIRECTORY_ENTRIES:
                        raise ReadFailure("CONFIG_INVALID")
                    if Path(entry.name).suffix not in extensions:
                        continue
                    metadata = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        continue  # Never recurse.
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise ReadFailure("PATH_FORBIDDEN")
                    if len(results) >= MAX_SOURCES:
                        raise ReadFailure("CONFIG_INVALID")
                    opaque = (
                        "s_"
                        + hashlib.sha256((source_id + "\x00" + entry.name).encode()).hexdigest()[
                            :32
                        ]
                    )
                    results.append((opaque, path / entry.name))
            after = os.fstat(fd)
            _same_named_directory(fd, path)
            if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ReadFailure("SOURCE_CHANGED")
            return sorted(results, key=lambda item: item[0])
        except OSError:
            raise ReadFailure("PATH_FORBIDDEN") from None
        finally:
            os.close(fd)

    def get(self, source_id: str) -> Source:
        source = self._sources.get(source_id)
        if source is None:
            raise ReadFailure("UNKNOWN_SOURCE")
        return source

    def open(self, source_id: str):
        self.get(source_id)
        return self._policy.open_source(source_id)

    def infos(self, redactor: Redactor, budget: ReadBudget) -> list[SourceInfo]:
        result = []
        for source in self._sources.values():
            budget.check()
            display = redactor.redact(source.path.relative_to(source.root).as_posix()).text.value
            if len(display) > 256:
                display = source.id
            size = modified = problem = None
            fd = None
            try:
                fd = _metadata_open(source.path, directory=False)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ReadFailure("NOT_REGULAR_FILE")
                if not os.access(source.path, os.R_OK, effective_ids=True, follow_symlinks=False):
                    raise ReadFailure("PATH_FORBIDDEN")
                final = Path(os.readlink(f"/proc/self/fd/{fd}"))
                if final != source.path or not final.is_relative_to(source.root):
                    raise ReadFailure("PATH_FORBIDDEN")
                named = os.stat(source.path, follow_symlinks=False)
                if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    named.st_dev,
                    named.st_ino,
                    named.st_size,
                    named.st_mtime_ns,
                    named.st_ctime_ns,
                ):
                    raise ReadFailure("SOURCE_CHANGED")
                size = info.st_size
                modified = datetime.fromtimestamp(info.st_mtime, UTC).isoformat()
            except (ReadFailure, PathPolicyError) as failure:
                problem = ErrorCode(failure.code)
            except (OSError, ValueError, OverflowError):
                problem = ErrorCode.PATH_FORBIDDEN
            finally:
                if fd is not None:
                    os.close(fd)
            result.append(
                SourceInfo(
                    id=source.id,
                    display_path=display,
                    size=size,
                    modified=modified,
                    readable=problem is None,
                    problem=problem,
                )
            )
        return result
