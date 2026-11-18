"""HashTrail: offline SHA-256 directory snapshots."""

from .core import FileEntry, Snapshot, compare_snapshots, create_snapshot, load_manifest

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "FileEntry",
    "Snapshot",
    "create_snapshot",
    "load_manifest",
    "compare_snapshots",
]
