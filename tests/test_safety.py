"""Additional independent safety regressions with entirely synthetic fixtures."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hashtrail.core import create_snapshot, Snapshot
from hashtrail.__main__ import main
from hashtrail.reports import render


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'files'
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def incomplete(self):
        return Snapshot([], [], {'symlink': 0, 'excluded': 0, 'special': 0}, ['read_error'], False)

    def test_streaming_hash_crosses_chunk_boundary(self):
        value = bytes(range(256)) * 4097
        (self.root / 'large.bin').write_bytes(value)
        result = create_snapshot(self.root)
        self.assertTrue(result.complete)
        self.assertEqual(result.files[0].sha256, hashlib.sha256(value).hexdigest())

    def test_subtree_glob_honors_wildcards(self):
        folder = self.root / 'cache-production'
        folder.mkdir()
        (folder / 'note.txt').write_text('synthetic', encoding='utf-8')
        result = create_snapshot(self.root, exclude=('cache*/**',))
        self.assertEqual(result.files, [])
        self.assertEqual(result.skipped['excluded'], 1)

    def test_trailing_slash_glob_honors_wildcards(self):
        (self.root / 'generated-01').mkdir()
        (self.root / 'generated-01' / 'a').write_bytes(b'a')
        self.assertEqual(create_snapshot(self.root, exclude=('generated-*/',)).files, [])

    def test_default_directory_name_as_file_is_hashed(self):
        (self.root / '.git').write_bytes(b'not a directory')
        result = create_snapshot(self.root)
        self.assertEqual([item.path for item in result.files], ['.git'])

    def test_read_error_is_sanitized_and_incomplete(self):
        (self.root / 'blocked.txt').write_bytes(b'PRIVATE_SYNTHETIC_SOURCE')
        real_open = os.open
        def deny(path, *args, **kwargs):
            if path == 'blocked.txt':
                raise PermissionError('PRIVATE_SYNTHETIC_SOURCE')
            return real_open(path, *args, **kwargs)
        with patch('hashtrail.core.os.open', side_effect=deny):
            result = create_snapshot(self.root)
        self.assertFalse(result.complete)
        self.assertTrue(result.errors)
        self.assertNotIn('PRIVATE_SYNTHETIC_SOURCE', json.dumps(result.to_dict()))

    def test_file_modified_during_hash_is_not_accepted(self):
        target = self.root / 'changing.txt'
        target.write_bytes(b'original content')
        real_sha256 = hashlib.sha256
        class MutatingDigest:
            def __init__(self):
                self.digest = real_sha256()
                self.once = False
            def update(self, block):
                self.digest.update(block)
                if not self.once:
                    self.once = True
                    with target.open('ab') as handle:
                        handle.write(b'changed during read')
            def hexdigest(self):
                return self.digest.hexdigest()
        with patch('hashtrail.core.hashlib.sha256', side_effect=MutatingDigest):
            result = create_snapshot(self.root)
        self.assertFalse(result.complete)
        self.assertEqual(result.files, [])

    def test_incomplete_snapshot_cli_writes_no_manifest(self):
        output = self.base / 'manifest.json'
        with patch('hashtrail.__main__.create_snapshot', return_value=self.incomplete()), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main(['snapshot', str(self.root), '--output', str(output)])
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())

    def test_incomplete_verification_cli_returns_two(self):
        (self.root / 'a').write_bytes(b'unchanged')
        manifest = self.base / 'reference.json'
        manifest.write_text(json.dumps(create_snapshot(self.root).to_dict()), encoding='utf-8')
        out = io.StringIO()
        with patch('hashtrail.__main__.create_snapshot', return_value=self.incomplete()), redirect_stdout(out):
            code = main(['verify', str(manifest), str(self.root), '--format', 'json'])
        self.assertEqual(code, 2)
        self.assertIs(json.loads(out.getvalue())['complete'], False)

    def test_terminal_escapes_filename_controls(self):
        report = render({'modified': ['note\x1b[31m\n.txt'], 'added': [], 'removed': [], 'unchanged': 0, 'complete': True, 'errors': [], 'skipped': {}})
        self.assertNotIn('\x1b', report)
        self.assertIn('\\u001b', report)
        self.assertIn('\\n.txt', report)

    def test_unknown_report_format_rejected(self):
        with self.assertRaises(ValueError):
            render({}, 'unknown-format')


if __name__ == '__main__':
    unittest.main()
