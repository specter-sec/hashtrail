"""Contract tests for HashTrail's snapshot and manifest core."""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from hashtrail.core import (
    FileEntry,
    Snapshot,
    compare_snapshots,
    create_snapshot,
    load_manifest,
)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "tree"
        self.root.mkdir()

    def test_snapshot_serializes_exact_manifest_keys(self):
        (self.root / "one.txt").write_bytes(b"hello")
        manifest = create_snapshot(self.root).to_dict()
        self.assertEqual(
            set(manifest),
            {"schema_version", "algorithm", "files", "excluded_patterns", "skipped", "errors", "complete"},
        )
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["algorithm"], "sha256")
        self.assertEqual(set(manifest["files"][0]), {"path", "size", "sha256"})
        self.assertEqual(set(manifest["skipped"]), {"symlink", "excluded", "special"})

    def test_known_sha256_for_file_bytes(self):
        data = b"hello world\n"
        (self.root / "known.bin").write_bytes(data)
        snapshot = create_snapshot(self.root)
        self.assertEqual(snapshot.files[0].sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(snapshot.files[0].size, len(data))

    def test_binary_and_unicode_filenames_are_hashed(self):
        binary = bytes(range(256)) + b"\x00\xff"
        (self.root / "payload-雪.dat").write_bytes(binary)
        (self.root / "café.txt").write_bytes("naïve ☃".encode("utf-8"))
        snapshot = create_snapshot(self.root)
        indexed = {entry.path: entry for entry in snapshot.files}
        self.assertEqual(set(indexed), {"payload-雪.dat", "café.txt"})
        self.assertEqual(indexed["payload-雪.dat"].sha256, hashlib.sha256(binary).hexdigest())
        unicode_data = "naïve ☃".encode("utf-8")
        self.assertEqual(indexed["café.txt"].size, len(unicode_data))
        self.assertEqual(indexed["café.txt"].sha256, hashlib.sha256(unicode_data).hexdigest())

    def test_empty_file_has_standard_empty_digest(self):
        (self.root / "empty").write_bytes(b"")
        snapshot = create_snapshot(self.root)
        self.assertEqual(snapshot.files[0].sha256, hashlib.sha256(b"").hexdigest())
        self.assertEqual(snapshot.files[0].size, 0)

    def test_files_are_ordered_deterministically(self):
        for name in ("zeta", "éclair", "alpha"):
            (self.root / name).write_bytes(name.encode())
        paths1 = [item.path for item in create_snapshot(self.root).files]
        paths2 = [item.path for item in create_snapshot(self.root).files]
        self.assertEqual(paths1, sorted(paths1))
        self.assertEqual(paths1, paths2)

    def test_nested_paths_use_relative_posix_names(self):
        nested = self.root / "nested" / "deep"
        nested.mkdir(parents=True)
        (nested / "file.txt").write_text("data", encoding="utf-8")
        self.assertEqual(create_snapshot(self.root).files[0].path, "nested/deep/file.txt")

    def test_default_excluded_directories_are_skipped(self):
        for name in (".git", "__pycache__", ".venv", "node_modules"):
            directory = self.root / name
            directory.mkdir()
            (directory / "hidden").write_text("ignored", encoding="utf-8")
        snapshot = create_snapshot(self.root)
        self.assertEqual(snapshot.files, [])
        self.assertEqual(snapshot.skipped["excluded"], 4)
        self.assertTrue(snapshot.complete)

    def test_custom_fnmatch_exclusion_applies(self):
        (self.root / "keep.txt").write_text("keep", encoding="utf-8")
        (self.root / "secret.log").write_text("secret", encoding="utf-8")
        snapshot = create_snapshot(self.root, exclude=("*.log",))
        self.assertEqual([item.path for item in snapshot.files], ["keep.txt"])
        self.assertEqual(snapshot.excluded_patterns, ["*.log"])
        self.assertEqual(snapshot.skipped["excluded"], 1)
        self.assertTrue(snapshot.complete)

    def test_custom_exclusion_can_skip_directory_tree(self):
        directory = self.root / "generated"
        directory.mkdir()
        (directory / "artifact.bin").write_bytes(b"x")
        snapshot = create_snapshot(self.root, exclude=("generated",))
        self.assertEqual(snapshot.files, [])
        self.assertEqual(snapshot.skipped["excluded"], 1)

    def test_file_and_directory_symlinks_are_skipped_without_following(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "secret").write_text("outside", encoding="utf-8")
        (self.root / "link-file").symlink_to(outside / "secret")
        (self.root / "link-dir").symlink_to(outside, target_is_directory=True)
        snapshot = create_snapshot(self.root)
        self.assertEqual(snapshot.files, [])
        self.assertEqual(snapshot.skipped["symlink"], 2)
        self.assertTrue(snapshot.complete)

    def test_symlinked_root_is_rejected(self):
        link = Path(self.temp.name) / "root-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            create_snapshot(link)

    def test_non_directory_root_is_rejected(self):
        file_path = Path(self.temp.name) / "plain-file"
        file_path.write_text("not a directory", encoding="utf-8")
        with self.assertRaises((ValueError, OSError)):
            create_snapshot(file_path)

    def test_nested_symlink_target_is_not_included(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (self.root / "alias.txt").symlink_to(outside)
        snapshot = create_snapshot(self.root)
        self.assertNotIn("alias.txt", [entry.path for entry in snapshot.files])
        self.assertEqual(snapshot.skipped["symlink"], 1)

    def test_special_file_is_skipped_and_counted(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        os.mkfifo(self.root / "pipe")
        snapshot = create_snapshot(self.root)
        self.assertEqual(snapshot.files, [])
        self.assertEqual(snapshot.skipped["special"], 1)
        self.assertTrue(snapshot.complete)


class ManifestValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "manifest.json"

    @staticmethod
    def valid_manifest():
        return {
            "schema_version": 1,
            "algorithm": "sha256",
            "files": [{"path": "dir/file.txt", "size": 2, "sha256": hashlib.sha256(b"hi").hexdigest()}],
            "excluded_patterns": ["*.tmp"],
            "skipped": {"symlink": 0, "excluded": 1, "special": 0},
            "errors": [],
            "complete": True,
        }

    def load_data(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")
        return load_manifest(self.path)

    def test_valid_manifest_round_trips_to_snapshot(self):
        loaded = self.load_data(self.valid_manifest())
        self.assertIsInstance(loaded, Snapshot)
        self.assertEqual(loaded.to_dict(), self.valid_manifest())

    def test_fileentry_value_object_fields(self):
        entry = FileEntry("a.txt", 3, hashlib.sha256(b"abc").hexdigest())
        self.assertEqual((entry.path, entry.size, entry.sha256), ("a.txt", 3, hashlib.sha256(b"abc").hexdigest()))

    def test_manifest_with_duplicate_json_keys_is_rejected(self):
        self.path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaises(ValueError):
            load_manifest(self.path)

    def test_manifest_larger_than_limit_is_rejected(self):
        self.path.write_bytes(b" " * (8 * 1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            load_manifest(self.path)

    def test_invalid_json_is_rejected(self):
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_manifest(self.path)

    def test_unknown_or_missing_manifest_keys_are_rejected(self):
        for mutate in (lambda obj: obj.update(extra=True), lambda obj: obj.pop("errors")):
            with self.subTest(mutate=mutate):
                data = self.valid_manifest()
                mutate(data)
                with self.assertRaises(ValueError):
                    self.load_data(data)

    def test_wrong_schema_version_is_rejected(self):
        data = self.valid_manifest()
        data["schema_version"] = 2
        with self.assertRaises(ValueError):
            self.load_data(data)

    def test_wrong_algorithm_is_rejected(self):
        data = self.valid_manifest()
        data["algorithm"] = "md5"
        with self.assertRaises(ValueError):
            self.load_data(data)

    def test_boolean_size_is_not_accepted_as_integer(self):
        data = self.valid_manifest()
        data["files"][0]["size"] = True
        with self.assertRaises(ValueError):
            self.load_data(data)

    def test_negative_and_non_integer_sizes_are_rejected(self):
        for size in (-1, 1.5, "2"):
            with self.subTest(size=size):
                data = self.valid_manifest()
                data["files"][0]["size"] = size
                with self.assertRaises(ValueError):
                    self.load_data(data)

    def test_invalid_sha256_values_are_rejected(self):
        for digest in ("", "0" * 63, "g" * 64, 42):
            with self.subTest(digest=digest):
                data = self.valid_manifest()
                data["files"][0]["sha256"] = digest
                with self.assertRaises(ValueError):
                    self.load_data(data)

    def test_duplicate_file_paths_are_rejected(self):
        data = self.valid_manifest()
        data["files"].append(dict(data["files"][0]))
        with self.assertRaises(ValueError):
            self.load_data(data)

    def test_absolute_and_traversal_paths_are_rejected(self):
        for path in ("/etc/passwd", "../escape", "a/../../escape", "./relative"):
            with self.subTest(path=path):
                data = self.valid_manifest()
                data["files"][0]["path"] = path
                with self.assertRaises(ValueError):
                    self.load_data(data)

    def test_windows_paths_are_rejected(self):
        for path in ("folder\\file.txt", "C:/temp/file.txt", "C:\\temp\\file.txt"):
            with self.subTest(path=path):
                data = self.valid_manifest()
                data["files"][0]["path"] = path
                with self.assertRaises(ValueError):
                    self.load_data(data)

    def test_incomplete_manifest_is_rejected(self):
        data = self.valid_manifest()
        data["complete"] = False
        with self.assertRaises(ValueError):
            self.load_data(data)

    def test_non_boolean_complete_and_invalid_skip_counts_are_rejected(self):
        data = self.valid_manifest()
        data["complete"] = 1
        with self.assertRaises(ValueError):
            self.load_data(data)
        data = self.valid_manifest()
        data["skipped"]["symlink"] = True
        with self.assertRaises(ValueError):
            self.load_data(data)


class ComparisonTests(unittest.TestCase):
    def make_snapshot(self, names_and_bytes):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for name, content in names_and_bytes.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return create_snapshot(root)

    def test_comparison_identifies_added_removed_and_modified(self):
        expected = self.make_snapshot({"stay": b"same", "edit": b"old", "gone": b"x"})
        actual = self.make_snapshot({"stay": b"same", "edit": b"new", "added": b"y"})
        result = compare_snapshots(expected, actual)
        self.assertEqual(result["added"], ["added"])
        self.assertEqual(result["removed"], ["gone"])
        self.assertEqual(result["modified"], ["edit"])
        self.assertEqual(result["unchanged"], 1)

    def test_same_size_content_change_is_detected(self):
        expected = self.make_snapshot({"file": b"cat"})
        actual = self.make_snapshot({"file": b"dog"})
        self.assertEqual(expected.files[0].size, actual.files[0].size)
        self.assertEqual(compare_snapshots(expected, actual)["modified"], ["file"])

    def test_comparison_lists_are_sorted_and_use_actual_status(self):
        expected = self.make_snapshot({"z": b"1", "a": b"1"})
        actual = self.make_snapshot({"q": b"1", "b": b"1"})
        result = compare_snapshots(expected, actual)
        self.assertEqual(result["added"], ["b", "q"])
        self.assertEqual(result["removed"], ["a", "z"])
        self.assertEqual(result["modified"], [])
        self.assertEqual(result["unchanged"], 0)

    def test_comparison_carries_actual_completeness_errors_and_skips(self):
        expected = self.make_snapshot({})
        actual = self.make_snapshot({"included": b"yes"})
        result = compare_snapshots(expected, actual)
        self.assertEqual(result["complete"], actual.complete)
        self.assertEqual(result["errors"], list(actual.errors))
        self.assertEqual(result["skipped"], actual.skipped)

    def test_identical_snapshots_have_no_differences(self):
        expected = self.make_snapshot({"nested/file": b"same"})
        actual = self.make_snapshot({"nested/file": b"same"})
        result = compare_snapshots(expected, actual)
        self.assertEqual((result["added"], result["removed"], result["modified"]), ([], [], []))
        self.assertEqual(result["unchanged"], 1)


if __name__ == "__main__":
    unittest.main()
