"""Generate a fictional manifest, altered file set and real HTML report.

Usage: python3 demo.py NEW_DIRECTORY
The destination must not exist. No real user data or network access is used.
"""
from pathlib import Path
import json
import sys
from hashtrail.core import create_snapshot, compare_snapshots
from hashtrail.reports import render


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 demo.py NEW_DIRECTORY", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    root.mkdir(exist_ok=False)
    files = root / 'files'
    (files / 'archive').mkdir(parents=True)
    (files / 'photos').mkdir()
    (files / 'readme.txt').write_text('Fictional local backup demo.\n', encoding='utf-8')
    (files / 'notes.txt').write_text('Backup completed on Monday.\n', encoding='utf-8')
    (files / 'archive' / 'old.txt').write_text('Synthetic archived note.\n', encoding='utf-8')
    (files / 'photos' / 'pixel.bin').write_bytes(bytes(range(256)))
    expected = create_snapshot(files)
    with (root / 'snapshot.json').open('x', encoding='utf-8') as handle:
        json.dump(expected.to_dict(), handle, indent=2)
        handle.write('\n')
    (files / 'notes.txt').write_text('Backup completed on Tuesday.\n', encoding='utf-8')
    (files / 'archive' / 'old.txt').unlink()
    (files / 'release').mkdir()
    (files / 'release' / 'checklist.md').write_text('# Synthetic release checklist\n', encoding='utf-8')
    result = compare_snapshots(expected, create_snapshot(files))
    (root / 'report.html').write_text(render(result, 'html'), encoding='utf-8')
    print('Created fictional files, trusted reference and a real local comparison report.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
