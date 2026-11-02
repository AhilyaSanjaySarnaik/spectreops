#!/usr/bin/env bash
set -euo pipefail
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null || { echo "Python 3.11+ required"; exit 1; }
echo "[*] Creating virtualenv"
[ -d .venv ] || "$PY" -m venv .venv
source .venv/bin/activate
pip install --upgrade pip >/dev/null
pip install -e ".[dev]"
if command -v ollama >/dev/null; then
  ollama pull qwen2.5-coder:7b || echo "    pull failed — run manually later"
else
  echo "[!] Ollama not found. Install from https://ollama.com"
fi
echo "[*] Optional security tools:"
for t in nmap nuclei subfinder ffuf sqlmap trivy semgrep; do
  command -v "$t" >/dev/null && echo "    [x] $t" || echo "    [ ] $t  (optional)"
done
mkdir -p ~/.spectreops
echo "[✓] Done. Try: source .venv/bin/activate && spec --help"
