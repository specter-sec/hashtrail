"""Command-line contract tests for ``python -m hashtrail``."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "input"
        self.root.mkdir()
        self.external = self.base / "external"
        self.external.mkdir()
        self.env = os.environ.copy()
        old_pythonpath = self.env.get("PYTHONPATH")
        self.env["PYTHONPATH"] = str(WORKSPACE) + (os.pathsep + old_pythonpath if old_pythonpath else "")

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "hashtrail", *map(str, args)],
            cwd=WORKSPACE,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def make_manifest(self, *, exclude=()):
        target = self.external / "manifest.json"
        command = ["snapshot", self.root, "--output", target]
        for pattern in exclude:
            command.extend(("--exclude", pattern))
        result = self.run_cli(*command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(target.is_file())
        return target

    def test_snapshot_writes_complete_manifest_outside_root(self):
        (self.root / "sample.txt").write_text("fixture", encoding="utf-8")
        target = self.external / "snapshot.json"
        result = self.run_cli("snapshot", self.root, "--output", target)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertTrue(payload["complete"])
        self.assertEqual([entry["path"] for entry in payload["files"]], ["sample.txt"])
        self.assertFalse((self.root / "snapshot.json").exists())

    def test_snapshot_requires_output_and_rejects_missing_root(self):
        missing_output = self.run_cli("snapshot", self.root)
        self.assertEqual(missing_output.returncode, 2)
        missing_root = self.run_cli("snapshot", self.base / "absent", "--output", self.external / "absent.json")
        self.assertEqual(missing_root.returncode, 2)
        self.assertFalse((self.external / "absent.json").exists())

    def test_snapshot_refuses_existing_paths_and_outputs_inside_input(self):
        destination = self.external / "existing.json"
        destination.write_text("preserve", encoding="utf-8")
        existing = self.run_cli("snapshot", self.root, "--output", destination)
        self.assertEqual(existing.returncode, 2)
        self.assertEqual(destination.read_text(encoding="utf-8"), "preserve")

        inside = self.root / "manifest.json"
        rejected = self.run_cli("snapshot", self.root, "--output", inside)
        self.assertEqual(rejected.returncode, 2)
        self.assertFalse(inside.exists())

    def test_snapshot_refuses_symlink_output_without_touching_target(self):
        protected = self.external / "protected.txt"
        protected.write_text("preserve", encoding="utf-8")
        link = self.external / "manifest-link.json"
        try:
            link.symlink_to(protected)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        result = self.run_cli("snapshot", self.root, "--output", link)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(protected.read_text(encoding="utf-8"), "preserve")

    def test_verify_exit_codes_for_equal_changed_and_invalid_manifests(self):
        (self.root / "item").write_bytes(b"old")
        manifest = self.make_manifest()
        same = self.run_cli("verify", manifest, self.root)
        self.assertEqual(same.returncode, 0, same.stderr)

        (self.root / "item").write_bytes(b"new")
        changed = self.run_cli("verify", manifest, self.root)
        self.assertEqual(changed.returncode, 1, changed.stderr)

        invalid_path = self.external / "invalid.json"
        invalid_path.write_text("not json", encoding="utf-8")
        invalid = self.run_cli("verify", invalid_path, self.root)
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn("Traceback", invalid.stdout + invalid.stderr)

        incomplete_path = self.external / "incomplete.json"
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["complete"] = False
        incomplete_path.write_text(json.dumps(payload), encoding="utf-8")
        incomplete = self.run_cli("verify", incomplete_path, self.root)
        self.assertEqual(incomplete.returncode, 2)

    def test_verify_formats_include_json_metadata_and_html_escapes_names(self):
        filename = 'odd <tag> "quote".txt'
        secret_content = "SOURCE_CONTENT_MUST_NOT_APPEAR"
        (self.root / filename).write_text(secret_content, encoding="utf-8")
        manifest = self.make_manifest()
        (self.root / filename).write_text("changed synthetic content", encoding="utf-8")
        (self.root / "added").write_text("new secret payload", encoding="utf-8")

        text = self.run_cli("verify", manifest, self.root, "--format", "text")
        self.assertEqual(text.returncode, 1)
        self.assertNotIn(secret_content, text.stdout + text.stderr)
        self.assertNotIn("new secret payload", text.stdout + text.stderr)

        json_result = self.run_cli("verify", manifest, self.root, "--format", "json")
        self.assertEqual(json_result.returncode, 1)
        report = json.loads(json_result.stdout)
        self.assertIn("tool", report)
        self.assertIn("version", report)
        for key in ("added", "removed", "modified", "unchanged", "complete", "errors", "skipped"):
            self.assertIn(key, report)

        html_result = self.run_cli("verify", manifest, self.root, "--format", "html")
        self.assertEqual(html_result.returncode, 1)
        self.assertIn("&lt;tag&gt;", html_result.stdout)
        self.assertNotIn("<tag>", html_result.stdout)
        self.assertNotIn(secret_content, html_result.stdout)
        self.assertNotIn("new secret payload", html_result.stdout)

    def test_verify_formats_can_write_new_report_outside_root(self):
        (self.root / "item").write_text("content", encoding="utf-8")
        manifest = self.make_manifest()
        report = self.external / "report.html"
        result = self.run_cli("verify", manifest, self.root, "--format", "html", "--output", report)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(report.is_file())
        self.assertIn("<html", report.read_text(encoding="utf-8").lower())

    def test_verify_refuses_existing_symlink_and_inside_root_report_output(self):
        manifest = self.make_manifest()
        protected = self.external / "protected-report"
        protected.write_text("preserve", encoding="utf-8")
        link = self.external / "report-link"
        try:
            link.symlink_to(protected)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        symlink_result = self.run_cli("verify", manifest, self.root, "--output", link)
        self.assertEqual(symlink_result.returncode, 2)
        self.assertEqual(protected.read_text(encoding="utf-8"), "preserve")

        inside = self.root / "report.json"
        inside_result = self.run_cli("verify", manifest, self.root, "--output", inside)
        self.assertEqual(inside_result.returncode, 2)
        self.assertFalse(inside.exists())

    def test_verify_reuses_manifest_exclusion_patterns(self):
        (self.root / "keep.txt").write_text("keep", encoding="utf-8")
        (self.root / "cache.tmp").write_text("volatile", encoding="utf-8")
        manifest = self.make_manifest(exclude=("*.tmp",))
        (self.root / "cache.tmp").write_text("changed but excluded", encoding="utf-8")
        result = self.run_cli("verify", manifest, self.root, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["added"], [])

    def test_invalid_format_is_reported_as_usage_error(self):
        manifest = self.make_manifest()
        result = self.run_cli("verify", manifest, self.root, "--format", "xml")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
