from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    title: str
    severity: str          # critical|high|medium|low|info
    confidence: str        # verified|likely|possible
    target: str
    evidence: dict = field(default_factory=dict)
    tool: str = ""
    reproduction: str = ""
    remediation: str = ""

    def to_markdown(self) -> str:
        return (
            f"## {self.title}\n\n"
            f"- **Severity:** {self.severity}  **Confidence:** {self.confidence}\n"
            f"- **Target:** `{self.target}`  **Tool:** {self.tool}\n\n"
            f"### Evidence\n```json\n{json.dumps(self.evidence, indent=2)[:4000]}\n```\n\n"
            f"### Reproduction\n{self.reproduction or 'See evidence.'}\n\n"
            f"### Remediation\n{self.remediation or 'TBD'}\n")


def from_memory(rows: list[dict]) -> list[Finding]:
    """Convert Memory.findings() rows into Finding objects for the exporters."""
    return [Finding(title=r["title"], severity=r["severity"],
                    confidence=r["confidence"], target=r["target"] or "",
                    evidence=r["evidence"] if isinstance(r["evidence"], dict) else {},
                    tool=r["tool"] or "", reproduction=r.get("reproduction") or "",
                    remediation=r.get("remediation") or "")
            for r in rows]


def as_dicts(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in dedup_and_sort(findings)]


def dedup_and_sort(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out = []
    for f in findings:
        key = (f.title.lower(), f.target)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return sorted(out, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


def export_markdown(findings: list[Finding], path: str) -> None:
    body = "# SpectreOps Assessment Report\n\n" + "\n".join(
        f.to_markdown() for f in dedup_and_sort(findings))
    with open(path, "w") as fh:
        fh.write(body)
