# Contributing to HashTrail

Thanks for improving an offline integrity tool. Keep changes small, explain the problem and provide a synthetic reproduction. Do not upload real user files, private manifests or sensitive directory names.

## Local development

Use Python 3.11 or newer. No third-party test or runtime framework is needed.

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q hashtrail tests demo.py
```

For an end-to-end manual check, run `python3 demo.py` with a new temporary directory, then verify its manifest against the generated `files` directory. The deliberately changed demo should return exit code 1.

## Design boundaries

Keep SHA-256 hashing streaming and deterministic. Preserve strict manifest parsing, duplicate-key rejection, portable relative paths and the 8 MiB read/write compatibility limit. Never turn manifest paths into unrestricted file reads. Never follow symlinks, silently replace outputs or write reports into the input directory.

Make exclusions visible, reproducible and stored in the reference manifest. Do not quietly introduce broader default exclusions. Tests must distinguish a successful traversal with skipped entries from an incomplete traversal with errors.

Reports may include filenames and counts, but never source bytes. Escape HTML and terminal-control characters, including those in adversarial filenames. Every output format must honestly state coverage and completion. Do not claim authentication, signing or forensic chain of custody without implementing and reviewing those features.

## Tests and reviews

Add regression tests for each behavior change, including malformed inputs, incomplete reads and output safety. Use `tempfile` fixtures, deterministic byte strings and no network services. Keep CI actions pinned to immutable commit hashes. New dependencies require explicit discussion because offline portability is a core goal.

Be respectful, explain tradeoffs and criticize code rather than people. Security-sensitive issues belong in the private channel described in SECURITY.md, not in a public issue containing real data.
