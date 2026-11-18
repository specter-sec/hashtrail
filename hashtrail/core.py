"""Core implementation for offline HashTrail SHA-256 snapshots.

A snapshot describes files observed during traversal; it is not an atomic
filesystem image and does not establish authenticity or chain of custody.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

__all__ = ["FileEntry", "Snapshot", "create_snapshot", "load_manifest", "compare_snapshots"]

_SCHEMA_VERSION = 1
_ALGORITHM = "sha256"
_CHUNK_SIZE = 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_DEFAULT_OMITTED_DIRECTORIES = frozenset({".git", "__pycache__", ".venv", "node_modules"})
_SKIP_KEYS = ("symlink", "excluded", "special")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class FileEntry:
    """A regular file's normalized relative path, size, and SHA-256 digest."""

    path: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass
class Snapshot:
    """A directory snapshot and its traversal status."""

    files: list[FileEntry]
    excluded_patterns: list[str]
    skipped: dict[str, int]
    errors: list[str]
    complete: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "algorithm": _ALGORITHM,
            "files": [entry.to_dict() for entry in self.files],
            "excluded_patterns": list(self.excluded_patterns),
            "skipped": dict(self.skipped),
            "errors": list(self.errors),
            "complete": self.complete,
        }


def _valid_pattern(pattern: object) -> bool:
    if not isinstance(pattern, str) or not pattern or "\x00" in pattern or "\\" in pattern:
        return False
    # A trailing slash and '/**' are explicit subtree selectors. Validate the
    # path portion while preserving the spelling supplied by the caller.
    base = pattern[:-3] if pattern.endswith("/**") else pattern[:-1] if pattern.endswith("/") else pattern
    if not base or base.startswith("/") or _DRIVE_PREFIX.match(base):
        return False
    components = base.split("/")
    return all(component not in {"", ".", ".."} for component in components)


def _pattern_matches(pattern: str, relative_path: str) -> bool:
    if pattern.endswith("/**") or pattern.endswith("/"):
        base = pattern[:-3] if pattern.endswith("/**") else pattern[:-1]
        parts = relative_path.split("/")
        return any(fnmatch.fnmatchcase("/".join(parts[:length]), base)
                   for length in range(1, len(parts) + 1))
    return fnmatch.fnmatchcase(relative_path, pattern)


def _is_excluded(relative_path: str, is_directory: bool, patterns: tuple[str, ...]) -> bool:
    parts = relative_path.split("/")
    if is_directory and parts[-1] in _DEFAULT_OMITTED_DIRECTORIES:
        return True
    return any(_pattern_matches(pattern, relative_path) for pattern in patterns)


def _valid_relative_file_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return False
    if value.startswith("/") or _DRIVE_PREFIX.match(value):
        return False
    # PurePosixPath is used for the platform-independent manifest grammar.
    # Compare the rendered value to reject repeated separators and dot parts.
    pure = PurePosixPath(value)
    if pure.is_absolute() or pure.as_posix() != value:
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _stat_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def create_snapshot(root: Path | str, *, exclude: tuple[str, ...] = ()) -> Snapshot:
    """Hash regular files under *root* without following symbolic links.

    Files are read in sorted path order using 1 MiB chunks. Directory entries
    and each file descriptor are checked without following symlinks. Any
    recoverable traversal/read issue makes the returned snapshot incomplete.
    """
    try:
        root_path = Path(root)
        root_info = os.lstat(root_path)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("root must be an accessible directory") from exc
    if stat.S_ISLNK(root_info.st_mode):
        raise ValueError("root must not be a symbolic link")
    if not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("root must be a directory")
    if not isinstance(exclude, tuple) or any(not _valid_pattern(item) for item in exclude):
        raise ValueError("exclude must be a tuple of valid relative glob patterns")

    files: list[FileEntry] = []
    skipped = {key: 0 for key in _SKIP_KEYS}
    errors: list[str] = []
    complete = True

    def record_error(category: str) -> None:
        nonlocal complete
        complete = False
        errors.append(category)

    try:
        root_fd = os.open(root_path, _open_flags(directory=True))
    except OSError as exc:
        raise ValueError("root must be an accessible non-symlink directory") from exc

    try:
        opened_root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(opened_root_info.st_mode) or _stat_signature(root_info)[:2] != _stat_signature(opened_root_info)[:2]:
            raise ValueError("root changed while opening")
    except BaseException:
        os.close(root_fd)
        raise

    def walk(directory_fd: int, prefix: str, directory_before: os.stat_result) -> None:
        nonlocal complete
        try:
            with os.scandir(directory_fd) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
                for entry in entries:
                    name = entry.name
                    relative_path = f"{prefix}/{name}" if prefix else name
                    if "\x00" in name or "\\" in name or _DRIVE_PREFIX.match(relative_path):
                        record_error("unsafe_path")
                        continue
                    try:
                        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError:
                        record_error("stat_error")
                        continue

                    if stat.S_ISLNK(before.st_mode):
                        skipped["symlink"] += 1
                        continue

                    is_directory = stat.S_ISDIR(before.st_mode)
                    if _is_excluded(relative_path, is_directory, exclude):
                        skipped["excluded"] += 1
                        continue

                    if is_directory:
                        child_fd: int | None = None
                        try:
                            child_fd = os.open(name, _open_flags(directory=True), dir_fd=directory_fd)
                            opened = os.fstat(child_fd)
                            if not stat.S_ISDIR(opened.st_mode) or _stat_signature(before)[:2] != _stat_signature(opened)[:2]:
                                record_error("unstable_directory")
                            else:
                                walk(child_fd, relative_path, opened)
                                after_dir = os.fstat(child_fd)
                                if _stat_signature(opened) != _stat_signature(after_dir):
                                    record_error("unstable_directory")
                        except OSError:
                            # A raced-in symlink is counted as a symlink, not
                            # traversed; other open failures make the result incomplete.
                            try:
                                latest = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                            except OSError:
                                latest = None
                            if latest is not None and stat.S_ISLNK(latest.st_mode):
                                skipped["symlink"] += 1
                            else:
                                record_error("stat_error")
                        finally:
                            if child_fd is not None:
                                os.close(child_fd)
                        continue

                    if not stat.S_ISREG(before.st_mode):
                        skipped["special"] += 1
                        continue

                    file_fd: int | None = None
                    try:
                        file_fd = os.open(name, _open_flags(), dir_fd=directory_fd)
                        opened = os.fstat(file_fd)
                        if not stat.S_ISREG(opened.st_mode) or _stat_signature(before) != _stat_signature(opened):
                            record_error("unstable_file")
                            continue
                        digest = hashlib.sha256()
                        bytes_read = 0
                        with os.fdopen(file_fd, "rb", closefd=False) as stream:
                            while True:
                                block = stream.read(_CHUNK_SIZE)
                                if not block:
                                    break
                                digest.update(block)
                                bytes_read += len(block)
                        after = os.fstat(file_fd)
                        if _stat_signature(opened) != _stat_signature(after) or bytes_read != after.st_size:
                            record_error("unstable_file")
                            continue
                        files.append(FileEntry(relative_path, bytes_read, digest.hexdigest()))
                    except OSError:
                        record_error("read_error")
                    finally:
                        if file_fd is not None:
                            os.close(file_fd)
        except OSError:
            record_error("readdir_error")

        try:
            directory_after = os.fstat(directory_fd)
            if _stat_signature(directory_before) != _stat_signature(directory_after):
                record_error("unstable_directory")
        except OSError:
            record_error("stat_error")

    try:
        walk(root_fd, "", opened_root_info)
    finally:
        os.close(root_fd)

    files.sort(key=lambda item: item.path)
    return Snapshot(files, list(exclude), skipped, errors, complete)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def load_manifest(path: Path | str) -> Snapshot:
    """Load and strictly validate a complete HashTrail JSON manifest."""
    try:
        with open(path, "rb") as stream:
            raw = stream.read(_MAX_MANIFEST_BYTES + 1)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("cannot read manifest") from exc
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds 8 MiB limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ValueError("manifest is not valid strict JSON") from exc

    required_top = {"schema_version", "algorithm", "files", "excluded_patterns", "skipped", "errors", "complete"}
    if not isinstance(document, dict) or set(document) != required_top:
        raise ValueError("manifest has missing or unknown fields")
    if type(document["schema_version"]) is not int or document["schema_version"] != _SCHEMA_VERSION:
        raise ValueError("unsupported manifest schema version")
    if document["algorithm"] != _ALGORITHM or not isinstance(document["algorithm"], str):
        raise ValueError("unsupported manifest algorithm")
    if type(document["complete"]) is not bool or document["complete"] is not True:
        raise ValueError("manifest must declare a complete snapshot")

    raw_patterns = document["excluded_patterns"]
    if not isinstance(raw_patterns, list) or any(not _valid_pattern(pattern) for pattern in raw_patterns):
        raise ValueError("invalid excluded_patterns")

    raw_skipped = document["skipped"]
    if not isinstance(raw_skipped, dict) or set(raw_skipped) != set(_SKIP_KEYS):
        raise ValueError("invalid skipped counts")
    skipped: dict[str, int] = {}
    for key in _SKIP_KEYS:
        count = raw_skipped[key]
        if type(count) is not int or count < 0:
            raise ValueError("invalid skipped count")
        skipped[key] = count

    raw_errors = document["errors"]
    if not isinstance(raw_errors, list) or any(not isinstance(error, str) for error in raw_errors):
        raise ValueError("invalid errors list")
    if raw_errors:
        raise ValueError("incomplete manifests with errors cannot be loaded")

    raw_files = document["files"]
    if not isinstance(raw_files, list):
        raise ValueError("files must be a list")
    files: list[FileEntry] = []
    seen_paths: set[str] = set()
    for item in raw_files:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise ValueError("invalid file entry")
        relative_path = item["path"]
        size = item["size"]
        digest = item["sha256"]
        if not _valid_relative_file_path(relative_path):
            raise ValueError("invalid file path")
        if relative_path in seen_paths:
            raise ValueError("duplicate file path")
        seen_paths.add(relative_path)
        if type(size) is not int or size < 0:
            raise ValueError("invalid file size")
        if not isinstance(digest, str) or not _HEX_256.fullmatch(digest):
            raise ValueError("invalid SHA-256 digest")
        files.append(FileEntry(relative_path, size, digest))

    return Snapshot(files, list(raw_patterns), skipped, list(raw_errors), True)


def compare_snapshots(expected: Snapshot, actual: Snapshot) -> dict[str, Any]:
    """Compare snapshots by manifest paths, content digests, and file sizes."""
    expected_by_path = {item.path: item for item in expected.files}
    actual_by_path = {item.path: item for item in actual.files}
    expected_paths = set(expected_by_path)
    actual_paths = set(actual_by_path)
    added = sorted(actual_paths - expected_paths)
    removed = sorted(expected_paths - actual_paths)
    modified: list[str] = []
    unchanged = 0
    for path in sorted(expected_paths & actual_paths):
        old = expected_by_path[path]
        new = actual_by_path[path]
        if old.sha256 != new.sha256 or old.size != new.size:
            modified.append(path)
        else:
            unchanged += 1
    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged": unchanged,
        "complete": actual.complete,
        "errors": list(actual.errors),
        "skipped": dict(actual.skipped),
    }
