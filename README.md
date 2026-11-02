# SpectreOps

Local-first AI cybersecurity & red-team agent for authorized testing.

> Only use against targets you have explicit, written permission to test.

## Install
    ./setup.sh
    source .venv/bin/activate

Requires Python 3.11+ and a local LLM (default: Ollama, `ollama pull qwen2.5-coder:7b`).
Optional external tools: nmap, nuclei, subfinder, ffuf, katana, arjun, gau,
sqlmap, trivy. Tools whose binary is missing report that clearly instead of
crashing; `spec tools` shows what is available. Fingerprinting, GraphQL
introspection and the HTTP request/replay tools are built in (no binary needed).

## Quick start (local lab)
    docker compose -f docker/vulnlab/docker-compose.yml up -d   # Juice Shop + DVWA on 127.0.0.1
    spec scope  -c config/examples/local_lab.yaml               # check what is in scope
    spec tools  -c config/examples/local_lab.yaml               # which tools can run
    spec run "enumerate http://127.0.0.1:3000" -c config/examples/local_lab.yaml
    spec findings -c config/examples/local_lab.yaml
    spec report report.html -c config/examples/local_lab.yaml   # .md | .json | .sarif | .html
    spec verify-audit -c config/examples/local_lab.yaml
    spec run "..." --plan ~/.spectreops/plans/plan-XYZ.json      # resume a saved plan
    spec chat -c config/examples/local_lab.yaml                 # interactive
    spec dashboard -c config/examples/local_lab.yaml            # http://127.0.0.1:8765

## Architecture
- `core/` agent loop, tool registry, executor, SQLite memory, hash-chained audit log
- `llm/` Ollama + any OpenAI-compatible backend (llama.cpp, vLLM, LM Studio)
- `scope/` authoritative target validation (enforced in code, not prompts)
- `safety/` sandbox, approval gates, prompt-injection scrubbing, secret redaction
- `core/auth.py` per-host credentials and named identities for authenticated testing
- `tools/` tool adapters; each declares its danger level and which args are targets
- `reporting/` Markdown, JSON, SARIF 2.1.0 and HTML exporters

## Tool coverage
Grouped by phase (danger level in brackets):

- **Recon/discovery:** `dns_lookup` (safe), `subfinder_enum` / `archive_urls`
  (safe, third-party — offline-blocked), `nmap_scan` (active, flag allowlist),
  `http_probe` / `http_fingerprint` (active), `crawl` (katana, active),
  `param_discover` (arjun, active)
- **API:** `openapi_endpoints` (safe), `graphql_introspect` (active)
- **Content/param fuzzing:** `dir_brute` (active), `ffuf_fuzz` (active, local
  wordlists only)
- **Manual request/replay:** `http_send` (active), `http_replay` (active —
  replays one request across auth identities to surface BOLA/IDOR)
- **Vuln scanning:** `nuclei_scan` (active, local templates, no OOB),
  `trivy_scan` (safe, local)
- **Active exploitation:** `sqlmap_test` (exploit — detection/enumeration only,
  OS/file/shell options disabled; runs only in the exploit phase, with approval)
- **Shell:** `run_shell` (sandboxed; scope mode `full` + approval every call)
- **Reporting:** `record_finding` (store a finding with request/response evidence)

### Authenticated & multi-identity testing
Configure auth identities in the `auth` config section (see `config/default.yaml`).
Raw tokens are never stored in config — each credential names an env var or a
secrets-store key, and resolved values are registered for redaction. A credential
is only ever sent to the host it was configured for, so a token can't leak across
hosts even if the model asks. Tools take an `identity` argument; `http_replay`
takes a list of identities and diffs the responses — the primitive for broken
object/function-level authorization. `spec auth` lists identities and their hosts
(never the values).

## Security model
Every tool call the model makes goes through `Executor.run`, which enforces, in order:

1. **Autonomy** — `advisory` runs passive tools only; `supervised` asks before
   actions tagged in `scope.require_approval_for`; `authorized` pre-approves them.
2. **Scope mode vs. danger** — `none` blocks all network tools; `passive_only`
   allows only `safe` tools; `active` adds `active` tools; `full` adds `exploit`/`destructive`.
3. **Targets** — every declared target argument (URL, host, IP or CIDR) must be in
   scope and not excluded; any URL found in *any* other argument is checked too.
   Multi-target strings are rejected.
4. **Offline mode** — tools that contact third parties (e.g. subfinder, gau) are disabled.
5. **Unscoped tools** (`run_shell`) need scope mode `full` *and* approval on every call.
6. **Output** — tool output is scrubbed for prompt-injection phrases and secrets are
   redacted before it reaches the model; audit records redact secrets too.

The audit log is a SHA-256 hash chain: edits, insertions and deletions are detected
by `spec verify-audit`. Truncating the newest records is not detectable from the
file alone — anchor the latest hash elsewhere if you need that.

### Engagement phases
Each run keeps a plan (recon → collect → test → exploit → report) in code. The
model queues and completes tasks and asks to advance with `plan_next_phase`; the
current phase is injected into its system prompt every round. Exploit/destructive
tools only run in the `exploit` phase; entering it needs operator approval and is
skipped entirely unless scope mode is `full`. Plans are saved after every change.

### Rate limiting
`scope.rate_limit` (requests/sec) and `scope.concurrency` are enforced per request
for HTTP tools via an engagement-wide limiter, and passed to nmap (`--max-rate`)
and nuclei (`-rl`, `-c`). nuclei also runs with `-ni` (no out-of-band interactsh
callbacks to third-party servers) and only accepts local template paths.

### Sandbox
`run_shell` runs in docker (preferred), bwrap, or — last resort — directly with a
destructive-command tripwire. Build the docker image once with
`docker/tools/build.sh`; SpectreOps refuses to start a shell call if it is missing.
`runtime.sandbox_network: host` lets the container reach lab targets (the scope
validator is then the only network boundary); `none` isolates it completely.
nmap, nuclei, subfinder and trivy currently run on the host, not in the sandbox.

### Configuration overrides
Any config field can be overridden with `SPECTREOPS_<SECTION>__<FIELD>`, e.g.
`SPECTREOPS_LLM__MODEL=qwen2.5-coder:14b` or `SPECTREOPS_SCOPE__TARGETS=127.0.0.1,10.0.0.5`.
Overrides are validated like the YAML.

## Development
    pip install -e ".[dev,dashboard]"
    ruff check . && pytest -q
