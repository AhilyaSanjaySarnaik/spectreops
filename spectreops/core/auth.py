"""Per-host authentication and multi-identity support.

Most high-value API findings (BOLA/IDOR, broken function-level auth) need the
agent to (a) send authenticated requests and (b) replay one identity's request
with another identity's credentials. This module holds named identities, each a
map of host -> credential, and attaches the right credential to an outbound
request.

Two safety rules are non-negotiable:

1. A credential is only ever attached to the host it was configured for. A token
   for ``api.example.com`` is never sent to ``evil.example`` even if the model
   asks — the host of the request URL must match the credential's host.
2. Raw secrets never live in the YAML config. Each credential names an env var
   (or a key in the secrets store); the value is resolved at load time and
   registered for redaction so it cannot leak into tool output or the audit log.
"""
from __future__ import annotations

import os
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlparse

from ..safety.secrets import load_secrets, register_runtime_secret

CredKind = str  # bearer | header | cookie | basic | query

_VALID_KINDS = {"bearer", "header", "cookie", "basic", "query"}


@dataclass(frozen=True)
class Credential:
    kind: CredKind
    value: str
    name: str = ""          # header/cookie/query-param name (not used for bearer/basic)

    def apply(self, headers: dict[str, str], cookies: dict[str, str],
              params: dict[str, str]) -> None:
        if self.kind == "bearer":
            headers["Authorization"] = f"Bearer {self.value}"
        elif self.kind == "basic":
            headers["Authorization"] = f"Basic {self.value}"
        elif self.kind == "header":
            headers[self.name] = self.value
        elif self.kind == "cookie":
            cookies[self.name] = self.value
        elif self.kind == "query":
            params[self.name] = self.value


def _host_key(url_or_host: str) -> tuple[str, str]:
    """Return (host, host:port) lowercased for matching a request against config."""
    s = url_or_host.strip()
    parsed = urlparse(s if "://" in s else f"//{s}")
    host = (parsed.hostname or "").lower()
    hostport = f"{host}:{parsed.port}" if parsed.port else host
    return host, hostport


def _resolve_value(spec: dict) -> str | None:
    """Resolve a credential value from env or the secrets store; never from raw config."""
    if spec.get("token_env") or spec.get("value_env"):
        return os.environ.get(spec.get("token_env") or spec["value_env"]) or None
    if spec.get("secret"):
        return load_secrets().get(spec["secret"]) or None
    return None


class Identity:
    def __init__(self, name: str, creds: dict[str, Credential]):
        self.name = name
        self._creds = creds            # keyed by host and host:port

    def credential_for(self, url: str) -> Credential | None:
        host, hostport = _host_key(url)
        return self._creds.get(hostport) or self._creds.get(host)


class AuthStore:
    def __init__(self, identities: dict[str, Identity], active: str | None):
        self.identities = identities
        self.active = active
        self.warnings: list[str] = []

    @classmethod
    def empty(cls) -> AuthStore:
        return cls({}, None)

    @classmethod
    def from_config(cls, auth_cfg) -> AuthStore:
        """Build from the `auth` config section, resolving secrets from the environment."""
        store = cls({}, getattr(auth_cfg, "active", None) or None)
        identities = getattr(auth_cfg, "identities", {}) or {}
        for ident_name, hosts in identities.items():
            creds: dict[str, Credential] = {}
            for host, spec in (hosts or {}).items():
                kind = str(spec.get("kind") or spec.get("type") or "bearer").lower()
                if kind not in _VALID_KINDS:
                    store.warnings.append(f"{ident_name}/{host}: bad kind {kind!r}")
                    continue
                value = _resolve_value(spec)
                if not value:
                    store.warnings.append(
                        f"{ident_name}/{host}: no credential value "
                        "(set token_env/value_env/secret)")
                    continue
                register_runtime_secret(value)
                _, hostport = _host_key(host)
                creds[hostport] = Credential(kind=kind, value=value,
                                             name=spec.get("header")
                                             or spec.get("cookie")
                                             or spec.get("param") or "")
            if creds:
                store.identities[ident_name] = Identity(ident_name, creds)
        if store.active and store.active not in store.identities:
            store.warnings.append(f"active identity {store.active!r} has no usable creds")
            store.active = None
        return store

    def identity(self, name: str | None) -> Identity | None:
        return self.identities.get(name) if name else (
            self.identities.get(self.active) if self.active else None)

    def apply(self, url: str, headers: dict[str, str], identity: str | None = None
              ) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        """Return (headers, cookies, params) with the identity's credential for
        this host merged in. If the host has no configured credential, nothing
        is added — credentials never cross hosts."""
        headers = dict(headers)
        cookies: dict[str, str] = {}
        params: dict[str, str] = {}
        ident = self.identity(identity)
        if ident is not None:
            cred = ident.credential_for(url)
            if cred is not None:
                cred.apply(headers, cookies, params)
        return headers, cookies, params

    def names(self) -> list[str]:
        return sorted(self.identities)


_EMPTY = AuthStore.empty()
_current: ContextVar[AuthStore] = ContextVar("spectreops_auth", default=_EMPTY)


def current_auth() -> AuthStore:
    return _current.get()


def use_auth(store: AuthStore):
    return _current.set(store)


def reset_auth(token) -> None:
    _current.reset(token)
