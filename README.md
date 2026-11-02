# SpectreOps

Local-first AI cybersecurity & red-team agent for authorized testing.

## Install
    ./setup.sh
    source .venv/bin/activate

Requires: Python 3.11+, Ollama (`ollama pull qwen2.5-coder:7b`).
Optional tools: nmap, nuclei, subfinder, ffuf, sqlmap, trivy, semgrep — the agent
degrades gracefully when they are missing.

## Usage
    spec scope -c config/examples/local_lab.yaml
    spec run "enumerate http://127.0.0.1:3000" -c config/examples/local_lab.yaml
    spec chat
    spec verify-audit
    spec report report.md
    python -m spectreops.dashboard.app      # localhost:8765

## Architecture
- core/ agent loop, planner, tool registry, executor, SQLite memory, hash-chained audit
- llm/ Ollama + any OpenAI-compatible backend (llama.cpp, vLLM, LM Studio)
- scope/ authoritative target validation (enforced in code, not prompts)
- safety/ sandbox, approval gates, prompt-injection scrubbing, secret redaction
- tools/ plugin adapters with graceful missing-dependency handling
- reporting/ markdown, JSON, SARIF, HTML exporters

## Security model
All network actions require an explicitly configured scope; out-of-scope egress
is blocked at the executor layer regardless of what the model requests.
Only use against targets you have explicit permission to test.
