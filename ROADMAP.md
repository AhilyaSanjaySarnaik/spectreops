# Roadmap

## Implemented
- Local LLM integration (Ollama/OpenAI-compatible), validated config schema + env overrides
- Hash-chained audit log with secret redaction
- Scope validator: hosts, URLs, IPv4/IPv6, CIDR targets and exclusions, mode-vs-danger checks
- Executor: autonomy levels, approval gate, per-tool target declarations, timeouts,
  transient-only retries, prompt-injection scrubbing and secret redaction of tool output
- 9 built-in tools + `record_finding`; nmap flag allowlist; sandboxed shell (full mode + approval)
- CLI: chat / run / scope / tools / findings / report / verify-audit / dashboard
- Exporters: Markdown, JSON, SARIF 2.1.0, HTML
- Engagement-wide rate limiting (per request) + nmap/nuclei rate flags
- Planner wired into the agent: phase in system prompt, plan tools, persistence/resume,
  exploit phase gated by approval + scope mode, exploit tools phase-locked
- nuclei: local templates only, no interactsh OOB, no update checks
- Sandbox image Dockerfile (`docker/tools`), loud failure when image is missing,
  configurable sandbox network (host | none)
- Local vuln lab (Juice Shop + DVWA), CI (ruff + pytest on 3.11–3.13)

## Partial
- Dashboard: read-only JSON endpoints; no live task streaming or UI yet
- Injection guard: pattern-based; no LLM-based detection
- Sandbox image: Dockerfile written but not yet build-tested in CI
- External tools (nmap, nuclei, subfinder, trivy) run on the host, not in the sandbox
- Workbench projects (`workbench/projects.py`) not yet wired to plans/evidence

## Planned
- Pin resolved IPs at scope-check time to prevent DNS rebinding between check and request
- Route external tools through the sandbox; per-call network none/host by danger level
- CI job that builds docker/tools and runs the vulnlab integration tests
- Burp/ZAP adapters, sqlmap + ffuf wrappers, GraphQL testing, Semgrep integration
- Session/auth testing module, request replay + regression diffing
- CVE correlation (local NVD mirror), bug-bounty scope importer
- Integration tests against docker/vulnlab, audit log signing / external anchoring
