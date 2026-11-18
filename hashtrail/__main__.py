"""Safe command-line interface for local SHA-256 directory integrity review."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .core import create_snapshot, load_manifest, compare_snapshots
from .reports import render


MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="hashtrail", description="Offline file integrity checks. Checksums are not signatures.")
    root.add_argument("--version", action="version", version="HashTrail " + __version__)
    sub = root.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot", help="Create a new SHA-256 manifest outside a directory")
    snap.add_argument("directory", type=Path)
    snap.add_argument("--output", type=Path, required=True)
    snap.add_argument("--exclude", action="append", default=[], metavar="PATTERN")
    verify = sub.add_parser("verify", help="Compare a trusted manifest with a local directory")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("directory", type=Path)
    verify.add_argument("--format", choices=("text", "json", "html"), default="text")
    verify.add_argument("--output", type=Path)
    return root


def validate_output(path: Path, directory: Path) -> None:
    """Never overwrite a file, follow an output symlink, or write into input."""
    if path.exists() or path.is_symlink():
        raise ValueError("Choose a new output file")
    resolved = path.resolve()
    if not resolved.parent.is_dir() or resolved.is_relative_to(directory.resolve()):
        raise ValueError("Output must be outside the input directory with an existing parent")


def write_new(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(content)
    finally:
        if descriptor != -1:
            os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.output is not None:
            validate_output(args.output, args.directory)
        if args.command == "snapshot":
            snapshot = create_snapshot(args.directory, exclude=tuple(args.exclude))
            if not snapshot.complete:
                sys.stderr.write("HashTrail: snapshot incomplete; no manifest was written. Check local permissions and filesystem stability.\n")
                return 2
            content = json.dumps(snapshot.to_dict(), ensure_ascii=True, indent=2) + "\n"
            if len(content.encode("utf-8")) > MAX_MANIFEST_BYTES:
                raise ValueError("Manifest exceeds supported read limit")
            write_new(args.output, content)
            sys.stdout.write(f"Snapshot created: {len(snapshot.files)} files hashed; {sum(snapshot.skipped.values())} entries skipped.\nKeep the manifest in a trusted location. A checksum is not a signature.\n")
            return 0
        expected = load_manifest(args.manifest)
        actual = create_snapshot(args.directory, exclude=tuple(expected.excluded_patterns))
        comparison = compare_snapshots(expected, actual)
        report = render(comparison, args.format)
        if args.output:
            write_new(args.output, report)
        else:
            sys.stdout.write(report)
        if not comparison["complete"]:
            return 2
        return 1 if any(comparison[key] for key in ("added", "removed", "modified")) else 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        sys.stderr.write("HashTrail: invalid input or file operation failed. Check the directory, trusted manifest format, and new output path.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
