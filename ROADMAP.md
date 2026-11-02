# Roadmap

## Implemented
- Local LLM integration (Ollama/OpenAI-compatible), config schema + env overrides
- Hash-chained audit log, scope validator + policy, executor with retries/timeouts
- Tool registry + 9 built-in tools, sandbox, approval gates, injection guard, secrets
- CLI (chat/run/scope/report/tools/verify-audit), workbench, memory DB, exporters

## Partial
- Dashboard (read-only endpoints; no live task streaming yet)
- Injection guard (pattern-based; no LLM-based detection)

## Planned
- Burp/ZAP adapters, sqlmap + ffuf wrappers, GraphQL testing, Semgrep integration
- Session/auth testing module, request replay + regression diffing
- CVE correlation (local NVD mirror), bug-bounty scope importer
- End-to-end tests against docker/vulnlab, log signing
