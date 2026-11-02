# Minimal scanner image for the explicitly offline SpectreOps Phase 1 lab.
# Build before entering a disconnected namespace: docker build -t spectreops/lab-scanner:latest docker/lab-scanner
FROM alpine:3.20
RUN apk add --no-cache nmap
USER 65534:65534
ENTRYPOINT []
