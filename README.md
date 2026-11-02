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
    spec surfaces -c config/examples/local_lab.yaml             # discovered-endpoint queue
    spec run "enumerate http://127.0.0.1:3000" -c config/examples/local_lab.yaml
    spec findings -c config/examples/local_lab.yaml
    spec report report.html -c config/examples/local_lab.yaml   # .md | .json | .sarif | .html
    spec verify-audit -c config/examples/local_lab.yaml
    spec run "..." --plan ~/.spectreops/plans/plan-XYZ.json      # resume a saved plan
    spec chat -c config/examples/local_lab.yaml                 # interactive
    spec dashboard -c config/examples/local_lab.yaml            # http://127.0.0.1:8765

## Phase 1 supported secure mode: offline AI-agent lab

SpectreOps has one deliberately constrained, CI-tested scanning mode: **offline
Docker loopback lab**. It is not a general-purpose secure scanner for public
or corporate infrastructure. Other scanner adapters remain disabled by default.

1. Build the dedicated scanner image:
   `docker build -t spectreops/lab-scanner:latest docker/lab-scanner`
2. Start a local lab target:
   `docker run -d --rm --network none --cap-drop ALL --name spectre-lab python:3.12-alpine python -m http.server 8765 --bind 127.0.0.1`
3. Read its immutable Docker container ID:
   `docker inspect --format '{{.Id}}' spectre-lab`
4. Copy `config/examples/secure_offline_agent.yaml` to your own config file
   and replace `REPLACE_WITH_64_CHARACTER_DOCKER_CONTAINER_ID` with that ID.
   This profile requires `scope.mode: active`, only loopback scope targets,
   `runtime.offline: true`, `sandbox_network: none`, host scanners off,
   and a locally hosted LLM.
5. Invoke `spec run "check port 8765 on 127.0.0.1 using nmap" -c YOUR_CONFIG.yaml`
   **without** `--yes`; every isolated Nmap invocation requires approval.
   Stop the target with `docker rm -f spectre-lab` afterward.

The agent's network tools other than isolated `nmap_scan` are blocked in this
mode. The isolated scanner is built as an unprivileged image and operates only
on the loopback interface of a running Docker target configured with
`--network none`. CI runs actual Nmap against an offline loopback server and
tests that an external TEST-NET address cannot be reached.

**Trust boundary:** Docker daemon administrators may reconfigure target
containers, so do not treat this mode as a defence against a malicious Docker
administrator. The general-purpose Python HTTP helpers still use DNS preflight
rather than socket-level IP pinning and must not be considered a verified
remote-assessment isolation boundary. The unsafe legacy host-scanner opt-in is
outside this mode's security guarantee.

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

### Noise profile
`scope.profile` tunes how loud/detectable the agent is, from one setting:

- `stealth` — minimal footprint: request rate capped at 2/s, single connection,
  nmap top-50 ports at `-T2` with no version detection.
- `normal` (default) — quiet-by-default: nmap top-100 ports, no version detection
  unless asked (`service_detection: true` or the `-sV` flag).
- `loud` — lab/CTF speed: faster timing, version detection on.

The profile can only *lower* `scope.rate_limit` / `scope.concurrency`, never raise
them past what the policy allows. `spec scope` prints the effective rate/concurrency.
(The old default ran `nmap -sV` across ~1000 ports on every scan — that is gone.)

### Rate limiting
`scope.rate_limit` (requests/sec) and `scope.concurrency` are enforced per request
for HTTP tools via an engagement-wide limiter, and passed to nmap (`--max-rate`)
and nuclei (`-rl`, `-c`). nuclei also runs with `-ni` (no out-of-band interactsh
callbacks to third-party servers) and only accepts local template paths.

### Attack-surface queue
Discovery tools find endpoints; the agent records them with `surface_add` and
works through them one at a time with `surface_next` / `surface_done`, so coverage
is explicit — every endpoint is tested or deliberately skipped. `spec surfaces`
lists the queue; the dashboard exposes `/surfaces`.

### Offline Docker scanner lab (Phase 1 boundary)

For isolated security testing, SpectreOps provides `spectreops lab-nmap`. This
path shares the network namespace of an **already running**, unprivileged
Docker container with `--network none`. The scanner itself has no host
mounts, drops Linux capabilities, runs read-only, and cannot access public
networks. The only accepted destinations in this mode are the target
container's loopback addresses. This is deliberately **not** a general
network-restricted scanner for external domains, nor a substitute for a
destination allowlist firewall for real engagements.

Build the tool image, start a *local* offline server using an image already
available on your machine, then scan its loopback interface:

```sh
docker/tools/build.sh
docker run -d --rm --network none --name spectre-lab \
  python:3.12-alpine python -m http.server 8765 --bind 127.0.0.1
docker inspect --format '{{.Id}}' spectre-lab
# Replace <container-id> with the returned hex ID:
spectreops lab-nmap <container-id> --ports 8765
docker rm -f spectre-lab
```

The command rejects target containers that are not running, whose network
mode is not `none`, or that have another Docker network attached. It refuses
non-loopback scan targets. The restricted runner does not require enabling
the unsafe `runtime.allow_host_scanners` setting.

A Docker CI job uses a target and runner in the same disconnected network
namespace to verify the local service is reachable and a TEST-NET address
is unreachable. CI demonstrates **offline containment only**. This does
not prove all scanner adapters or normal Python HTTP requests have
connection-level destination controls. Do not enable host scanners for
untrusted engagements.

### Phase 1 network-boundary validation

The shell sandbox defaults to `runtime.sandbox_network: none`. Docker and
Bubblewrap should isolate network access for shell commands. **External scanners
still execute on the host if explicitly opted in**; do not treat this as a
universal network firewall.

On a machine with Docker and the prebuilt SpectreOps tools image, verify
the no-network boundary with this deliberately unreachable TEST-NET destination:

```sh
docker/tools/build.sh
docker run --rm --network none --entrypoint python3 spectreops/tools:latest \
  -c 'import socket; s=socket.socket(); s.settimeout(2); s.connect(("192.0.2.1", 9))'
```

**Expected:** the Python process exits non-zero with a network-unreachable error.
If the connection unexpectedly succeeds, do not run security tools until the
network configuration is inspected. Repeat under your actual deployment runtime.

Use `ruff check . && pytest -q` to run unit regressions. DNS validation
performed before HTTP dispatch detects some changed answers, but is not a
socket-level control: DNS can still change before connection. Do not claim
connection-level egress assurance until a network-isolated runtime and
on-the-wire tests are available for every external tool.

### External scanner isolation status

**Fail-closed default:** standalone scanners (nmap, nuclei, sqlmap,
katana, arjun, ffuf, subfinder, gau and trivy) currently launch subprocesses
directly on the host. They are **not** protected by the shell Sandbox or a
network egress firewall. To prevent unintentional host execution,
`runtime.allow_host_scanners` defaults to `false`.

For an operator-controlled lab ONLY, you can explicitly opt in:

```yaml
runtime:
  allow_host_scanners: true   # unsafe outside a tightly isolated lab
```

Each scanner invocation still requires operator approval, even with opt-in.
This is a temporary operational guard, **not** real scanner isolation.
Keep the option disabled until a dedicated network-restricted runtime is
available. The Python HTTP tools can still run without this opt-in.

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
