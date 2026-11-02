# Roadmap

## Implemented
- Local LLM integration (Ollama/OpenAI-compatible), validated config schema + env overrides
- Hash-chained audit log with secret redaction
- Scope validator: hosts, URLs, IPv4/IPv6, CIDR targets and exclusions, mode-vs-danger checks
- Executor: autonomy levels, approval gate, per-tool target declarations, timeouts,
  transient-only retries, prompt-injection scrubbing and secret redaction of tool output
- 18 built-in tools + `record_finding`; nmap/ffuf/sqlmap arg allowlists; sandboxed shell
- Tool coverage: recon (dns, subfinder, archive URLs, nmap, http probe/fingerprint,
  katana crawl, arjun params), API (OpenAPI, GraphQL introspection), fuzzing (dir_brute,
  ffuf), manual request/replay, vuln (nuclei, trivy), exploitation (sqlmap, locked down)
- Authenticated & multi-identity testing: per-host credentials from env/secrets store,
  host-bound so tokens never cross hosts, `http_replay` across identities for BOLA/IDOR
- Noise profile (stealth | normal | loud): quiet-by-default nmap (no -sV, top-N ports),
  caps rate/concurrency; profile can only lower, never raise, policy limits
- Attack-surface queue (memory `surfaces` + surface_add/next/done tools, `spec surfaces`,
  dashboard /surfaces) — discovered endpoints worked through explicitly
- Test suites split: unit, integration (agent loop), security (adversarial/abuse cases)
- CLI: chat / run / scope / auth / tools / surfaces / findings / report / verify-audit / dashboard
- Exporters: Markdown, JSON, SARIF 2.1.0, HTML; findings store request/response evidence
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
- External tools (nmap, nuclei, ffuf, sqlmap, etc.) run on the host, not in the sandbox
- Workbench projects (`workbench/projects.py`) not yet wired to plans/evidence
- Adapters for katana/arjun/gau/ffuf/sqlmap are command-built and unit-tested, but not
  yet run end-to-end against a live target in CI (binaries aren't installed there)

## Planned
- Pin resolved IPs at scope-check time to prevent DNS rebinding between check and request
- Route external tools through the sandbox; per-call network none/host by danger level
- CI job that builds docker/tools and runs the vulnlab integration tests
- Burp/ZAP adapters, Semgrep integration, gRPC/SOAP spec ingestion
- Regression diffing (replay a saved request set and compare over time)
- CVE correlation (local NVD mirror), bug-bounty scope importer
- Response diffing/fuzzing beyond identity-swap; CVSS scoring + cross-run dedup
- Integration tests against docker/vulnlab, audit log signing / external anchoring
