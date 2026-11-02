from __future__ import annotations

import asyncio
import re

from ...core.profile import current_profile
from ...core.rate_limit import current_limiter
from ..base import require_binary

# The model may only pass these flags. Anything else — extra targets, -iL,
# --script, output files, -oN, --datadir — is rejected, because 'extra' would
# otherwise let it scan hosts the executor never validated.
ALLOWED_FLAGS = {
    "-sV", "-sT", "-sS", "-sU", "-sn", "-Pn", "-n", "-F", "-O",
    "--open", "--reason", "--version-light", "--version-all",
    "-T0", "-T1", "-T2", "-T3", "-T4",
}
FLAGS_WITH_VALUE = {"--top-ports": re.compile(r"^\d{1,5}$"),
                    "--max-rate": re.compile(r"^\d{1,6}(\.\d+)?$")}
PORTS_RE = re.compile(r"^[TU:0-9,\-]+$")


def parse_extra(extra: str) -> list[str]:
    tokens = extra.split()
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ALLOWED_FLAGS:
            out.append(tok)
        elif tok in FLAGS_WITH_VALUE:
            if i + 1 >= len(tokens) or not FLAGS_WITH_VALUE[tok].match(tokens[i + 1]):
                raise ValueError(f"nmap flag {tok} needs a numeric value")
            out += [tok, tokens[i + 1]]
            i += 1
        else:
            raise ValueError(f"nmap option not allowed: {tok!r}. Allowed: "
                             f"{sorted(ALLOWED_FLAGS | set(FLAGS_WITH_VALUE))}")
        i += 1
    return out


def apply_rate_ceiling(extra: list[str], rate: float) -> list[str]:
    """Cap nmap's --max-rate at the engagement rate limit (0 = unlimited)."""
    if rate <= 0:
        return extra
    if "--max-rate" in extra:
        i = extra.index("--max-rate")
        extra[i + 1] = f"{min(float(extra[i + 1]), rate):g}"
        return extra
    return extra + ["--max-rate", f"{rate:g}"]


def default_extra(profile, service_detection: bool) -> list[str]:
    """Quiet-by-default nmap flags, tuned by the active noise profile.

    Unlike the old default ("-sV --open", version detection on 1000 ports), this
    stays quiet: open ports only, the profile's timing, and version detection
    only when the caller explicitly asks for it."""
    extra = ["--open", profile.nmap_timing]
    if service_detection or profile.service_detection:
        extra.append("-sV")
    return extra


async def nmap_scan(args: dict) -> dict:
    target = args["target"]
    ports = args.get("ports")
    if ports and not PORTS_RE.match(str(ports)):
        raise ValueError(f"invalid port spec: {ports!r}")
    profile = current_profile()
    if args.get("extra"):
        extra = parse_extra(args["extra"])
    else:
        extra = default_extra(profile, bool(args.get("service_detection")))
    # if the caller pinned no ports and no breadth, limit to the profile's top-N
    if not ports and "--top-ports" not in extra and "-p" not in extra:
        extra += ["--top-ports", str(profile.nmap_top_ports)]
    extra = apply_rate_ceiling(extra, current_limiter().rate)
    binary = require_binary("nmap")
    cmd = [binary, "-oX", "-", "-Pn"]
    if ports:
        cmd += ["-p", str(ports)]
    cmd += extra + ["--", target]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0:
        return {"error": f"nmap exit {proc.returncode}: {err.decode()[:2000]}"}
    return {"target": target, "xml": out.decode(errors="replace")[:200000],
            "summary": err.decode(errors="replace")[:2000]}


TOOL = {
    "name": "nmap_scan",
    "description": "Scan ONE in-scope host or small CIDR for open TCP ports using "
                   "nmap. Quiet by default (open ports only, top-N ports per the "
                   "engagement noise profile, no version detection). Set "
                   "'service_detection' for -sV. 'extra' (advanced) accepts only: "
                   + " ".join(sorted(ALLOWED_FLAGS | set(FLAGS_WITH_VALUE))),
    "parameters": {"type": "object",
                   "properties": {"target": {"type": "string"},
                                  "ports": {"type": "string",
                                            "description": "e.g. '22,80,443' or '1-1024'"},
                                  "service_detection": {"type": "boolean",
                                      "description": "enable -sV (noisier)"},
                                  "extra": {"type": "string"}},
                   "required": ["target"]},
}
