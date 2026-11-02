#!/usr/bin/env bash
# Build the sandbox image used when runtime.sandbox is "docker" (or "auto" with docker present).
set -euo pipefail
docker build -t spectreops/tools:latest "$(cd "$(dirname "$0")" && pwd)"
echo "[✓] built spectreops/tools:latest"
