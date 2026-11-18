"""Content-free verification reports. Filenames and hashes are still metadata."""
from __future__ import annotations

import html
import json
from . import __version__


def render(comparison: dict, format: str = "text") -> str:
    data = {"tool": "HashTrail", "version": __version__, **comparison}
    if format == "json":
        return json.dumps(data, ensure_ascii=True, indent=2) + "\n"
    if format == "html":
        return html_report(comparison)
    if format != "text":
        raise ValueError("Unsupported report format")
    changed = sum(len(comparison[key]) for key in ("modified", "added", "removed"))
    lines = [f"HashTrail {__version__} | SHA-256 integrity review", "=" * 55,
             f"Complete: {comparison['complete']} | Changed paths: {changed} | Unchanged: {comparison['unchanged']}"]
    for category in ("modified", "added", "removed"):
        for path in comparison[category]:
            lines.append(f"{category.upper():8} {json.dumps(path, ensure_ascii=True)}")
    lines.append("Skipped: " + str(sum(comparison["skipped"].values())) + " | Errors: " + str(len(comparison["errors"])))
    lines.append("No changes in the covered files is not proof of authenticity. Trust the manifest separately.")
    return "\n".join(lines) + "\n"


def html_report(result: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    changed = sum(len(result[key]) for key in ("modified", "added", "removed"))
    status = "Review required" if changed else "No covered changes"
    if not result['complete']:
        status = "Incomplete check"
    rows = []
    for category in ("modified", "added", "removed"):
        for path in result[category]:
            rows.append(f'<tr><td><span class="pill {category}">{category.upper()}</span></td><td><code>{esc(path)}</code></td><td>{ {"modified": "Content digest or byte size differs", "added": "Not present in the trusted manifest", "removed": "No longer present in the current directory"}[category] }</td></tr>')
    if not rows:
        rows.append('<tr><td colspan="3">No changed paths found in the covered scope. Review completion and skipped entries.</td></tr>')
    coverage = " · ".join(f"{esc(key)}: {value}" for key, value in sorted(result['skipped'].items())) or "None"
    errors = "".join(f'<li>{esc(item)}</li>' for item in result['errors'])
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>HashTrail · Integrity review</title><style>
:root{font-family:system-ui,-apple-system,sans-serif;color:#183c35;background:#f1f3eb;color-scheme:light}*{box-sizing:border-box}body{margin:0}main{max-width:1180px;margin:auto;padding:38px 36px}header{display:flex;justify-content:space-between;align-items:center;padding-bottom:24px;border-bottom:1px solid #c6d3c8}.brand{font-weight:850;font-size:26px;letter-spacing:-1px}.brand span{background:#c4ed93;border-radius:6px;padding:2px 7px;margin-right:8px}.stamp{font-size:11px;font-weight:700;letter-spacing:1.5px;padding:10px 14px;border:1px solid #b7c7b8;border-radius:30px}.hero{display:grid;grid-template-columns:1.7fr 1fr;gap:35px;align-items:center;padding:40px 0 30px}.eyebrow{font-size:11px;letter-spacing:2px;color:#4a6d5d;font-weight:750}h1{font-size:clamp(38px,5vw,66px);line-height:1.02;letter-spacing:-3px;margin:16px 0}p{color:#546b60;line-height:1.7;font-size:14px}.status{border-left:3px solid #82aa5c;background:#e6ecde;padding:22px}.status small{font-size:10px;letter-spacing:1.5px}.status strong{display:block;font-size:25px;margin:10px 0}.status p{margin:0;font-size:12px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card{padding:20px;background:#fffef8;border:1px solid #cbd6c8;border-radius:10px}.card .label{font-size:10px;letter-spacing:1.7px;font-weight:750;color:#546b60}.card b{display:block;font-size:39px;margin:8px 0 0}.card small{font-size:11px;color:#6d7f70}.section-head{display:flex;align-items:center;justify-content:space-between;margin:30px 0 14px}.section-head h2{font-size:21px;margin:0}.section-head span{font-size:11px;color:#607567}.table-wrap{overflow:auto;border:1px solid #c6d3c8;border-radius:10px;background:#fffef8}table{width:100%;border-collapse:collapse;text-align:left}th{padding:15px 19px;font-size:10px;letter-spacing:1.6px;background:#e8eee1;color:#526b59}td{padding:21px 19px;border-top:1px solid #dce3d5;font-size:12px;color:#576c60}td code{font-size:12px;color:#183c35;overflow-wrap:anywhere}.pill{font-size:9px;letter-spacing:.8px;font-weight:800;border:1px solid;border-radius:20px;padding:6px 10px;white-space:nowrap}.modified{background:#fff0cd;border-color:#dac183;color:#7a5613}.added{background:#def0d4;border-color:#a9c69a;color:#39682c}.removed{background:#fae3db;border-color:#d9afa0;color:#904b35}.note{padding:18px 23px;background:#193f36;color:#eef4e9;border-radius:10px;margin-top:22px}.note p{color:#dae6d8;margin:0;font-size:12px}.note strong{color:#c4ed93}.coverage{font-size:11px;margin-top:18px}footer{display:flex;justify-content:space-between;gap:20px;margin-top:28px;padding-top:20px;border-top:1px solid #c6d3c8;font-size:10px;color:#637969}@media(max-width:680px){main{padding:25px 16px}.hero{grid-template-columns:1fr;gap:15px;padding:30px 0 22px}h1{letter-spacing:-1.5px}.stats{grid-template-columns:repeat(2,1fr)}.card{padding:16px}.stamp{font-size:8px;letter-spacing:.6px}.brand{font-size:22px}header{gap:12px}th,td{padding:15px 11px}footer{flex-direction:column;gap:6px}.section-head span{font-size:9px}}
</style></head><body><main><header><div class="brand"><span>#</span>HashTrail</div><div class="stamp">SHA-256 / OFFLINE / NO UPLOADS</div></header><section class="hero"><div><div class="eyebrow">YOUR FILES. A CLEARER PAPER TRAIL.</div><h1>Know what changed.<br>Keep what matters.</h1><p>Compare a local directory with a trusted snapshot. See added, removed and modified files without putting file contents in a report.</p></div>''' + (
        f'<aside class="status"><small>VERIFICATION STATUS</small><strong>{esc(status)}</strong><p>Traversal complete: <b>{"Yes" if result["complete"] else "No"}</b><br>Integrity checks are not digital signatures.</p></aside></section>'
        f'<section class="stats" aria-label="Comparison summary"><div class="card"><span class="label">UNCHANGED</span><b>{result["unchanged"]:02d}</b><small>same size + SHA-256</small></div>'
        f'<div class="card"><span class="label">MODIFIED</span><b>{len(result["modified"]):02d}</b><small>review content changes</small></div>'
        f'<div class="card"><span class="label">ADDED</span><b>{len(result["added"]):02d}</b><small>new relative paths</small></div>'
        f'<div class="card"><span class="label">REMOVED</span><b>{len(result["removed"]):02d}</b><small>missing relative paths</small></div></section>'
        '<div class="section-head"><h2>Change ledger</h2><span>RELATIVE PATHS · NO FILE CONTENTS</span></div><div class="table-wrap"><table><thead><tr><th>STATUS</th><th>FILE</th><th>WHAT IT MEANS</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div><div class="note"><p><strong>Trust the reference, not just the result.</strong> A changed file may be expected. An attacker who can replace both files and the manifest can create a matching result. Store your manifest separately in a trusted location.</p></div>'
        f'<p class="coverage"><strong>Skipped entries:</strong> {coverage}. Skipped files, directories and symlink targets are outside coverage. File metadata, permissions and empty directories are not compared.</p><ul class="coverage">{errors}</ul>'
        f'<footer><span>HashTrail {esc(__version__)} · Built by IFTIKHAR · Generated locally</span><span>No telemetry · No scripts · No external assets</span></footer></main></body></html>')
