from __future__ import annotations

import html
import json

from .findings import as_dicts, dedup_and_sort


def export_json(findings, path: str) -> None:
    with open(path, "w") as fh:
        json.dump(as_dicts(findings), fh, indent=2)


def export_sarif(findings, path: str) -> None:
    rules, results = [], []
    for f in dedup_and_sort(findings):
        rid = f.title.lower().replace(" ", "_")[:60]
        rules.append({"id": rid, "shortDescription": {"text": f.title}})
        results.append({"ruleId": rid, "level": f.severity,
                        "message": {"text": f"{f.title} on {f.target} "
                                             f"({f.confidence})"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": f.target}}}]}
                       )
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "SpectreOps", "rules": rules}},
                       "results": results}]}
    with open(path, "w") as fh:
        json.dump(sarif, fh, indent=2)


_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>SpectreOps Report</title><style>
body{{font-family:sans-serif;max-width:900px;margin:2rem auto;color:#222}}
h2{{border-bottom:2px solid #444;padding-bottom:.2rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #999;padding:.4rem}}
.critical{{background:#c0392b;color:#fff}}.high{{background:#e67e22}}
.medium{{background:#f1c40f}}.low{{background:#7f8c8d;color:#fff}}
.info{{background:#95a5a6}}pre{{background:#f4f4f4;padding:.6rem;overflow-x:auto}}
</style></head><body><h1>SpectreOps Assessment Report</h1>
{body}</body></html>"""


def export_html(findings, path: str) -> None:
    rows = []
    for f in dedup_and_sort(findings):
        rows.append(
            f"<h2>{html.escape(f.title)}</h2>"
            f"<table><tr><th>Severity</th><td class='{f.severity}'>{f.severity} "
            f"(confidence: {f.confidence})</td></tr>"
            f"<tr><th>Target</th><td><code>{html.escape(f.target)}</code></td></tr>"
            f"<tr><th>Reproduction</th><td><pre>{html.escape(f.reproduction)}</pre>"
            f"</td></tr>"
            f"<tr><th>Remediation</th><td>{html.escape(f.remediation)}</td></tr>"
            f"</table>")
    with open(path, "w") as fh:
        fh.write(_HTML.format(body="\n".join(rows)))
