# Sandbox image for SpectreOps' docker sandbox (run_shell).
# Build: docker/tools/build.sh   ->   spectreops/tools:latest
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl dnsutils iputils-ping netcat-openbsd \
      nmap nuclei subfinder ffuf sqlmap trivy python3 python3-pip pipx \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Unprivileged user. ("operator" already exists as a group in Debian-based images.)
RUN useradd --create-home --shell /bin/bash spectre \
 && mkdir -p /work && chown spectre:spectre /work
USER spectre
ENV PATH="/home/spectre/.local/bin:${PATH}"

# semgrep isn't packaged in Kali; nuclei templates are fetched at build time so
# scans work with runtime.offline=true (nuclei runs with -duc -ni).
RUN pipx install semgrep \
 && nuclei -update-templates -silent || true

WORKDIR /work
ENTRYPOINT []
CMD ["bash"]
