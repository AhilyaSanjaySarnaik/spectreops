"""Tests for auth/identities, ffuf/sqlmap/graphql adapters and the request-replay tool."""
from __future__ import annotations

import pytest

from spectreops.core.auth import AuthStore, reset_auth, use_auth
from spectreops.core.config import AuthConfig
from spectreops.safety import secrets
from spectreops.tools.recon.crawl import build_command as katana_cmd
from spectreops.tools.recon.params import build_command as arjun_cmd
from spectreops.tools.vuln.sqlmap import build_command as sqlmap_cmd
from spectreops.tools.web.ffuf import build_command as ffuf_cmd
from spectreops.tools.web.ffuf import resolve_wordlist


# ---- auth / identities -----------------------------------------------------
def _store(monkeypatch):
    monkeypatch.setenv("TOK_A", "aaaa-token-A")
    monkeypatch.setenv("TOK_B", "bbbb-token-B")
    cfg = AuthConfig(active="alice", identities={
        "alice": {"127.0.0.1:3000": {"kind": "bearer", "token_env": "TOK_A"}},
        "bob": {"127.0.0.1:3000": {"kind": "header", "header": "X-Key",
                                   "value_env": "TOK_B"}},
    })
    return AuthStore.from_config(cfg)


def test_auth_attaches_active_identity(monkeypatch):
    s = _store(monkeypatch)
    headers, _, _ = s.apply("http://127.0.0.1:3000/api", {})
    assert headers["Authorization"] == "Bearer aaaa-token-A"


def test_auth_never_crosses_hosts(monkeypatch):
    s = _store(monkeypatch)
    headers, cookies, params = s.apply("http://evil.example/api", {})
    assert headers == {} and cookies == {} and params == {}


def test_auth_identity_override(monkeypatch):
    s = _store(monkeypatch)
    headers, _, _ = s.apply("http://127.0.0.1:3000/x", {}, identity="bob")
    assert headers["X-Key"] == "bbbb-token-B" and "Authorization" not in headers


def test_auth_values_registered_for_redaction(monkeypatch):
    secrets.clear_runtime_secrets()
    _store(monkeypatch)
    assert "[REDACTED]" in secrets.redact("leak aaaa-token-A here")
    secrets.clear_runtime_secrets()


def test_auth_missing_env_warns(monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    s = AuthStore.from_config(AuthConfig(active="x", identities={
        "x": {"h": {"kind": "bearer", "token_env": "NOPE"}}}))
    assert s.active is None and any("no credential" in w for w in s.warnings)


@pytest.mark.asyncio
async def test_http_request_applies_and_isolates_auth(monkeypatch):
    import spectreops.tools.base as base
    s = _store(monkeypatch)
    captured = {}

    class FakeResp:
        status_code = 200
        url = "http://127.0.0.1:3000/"
        headers = {}
        text = "ok"

        class request:
            headers = {"Authorization": "Bearer aaaa-token-A"}

    class FakeClient:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def request(self, method, url, headers=None, **kw):
            captured["headers"] = headers
            return FakeResp()

    monkeypatch.setattr(base.httpx, "AsyncClient", FakeClient)
    tok = use_auth(s)
    try:
        await base.http_request("GET", "http://127.0.0.1:3000/")
        assert captured["headers"]["Authorization"] == "Bearer aaaa-token-A"
        captured.clear()
        await base.http_request("GET", "http://evil.example/")
        assert "Authorization" not in captured["headers"]
    finally:
        reset_auth(tok)


# ---- ffuf ------------------------------------------------------------------
def test_ffuf_rejects_remote_wordlist():
    with pytest.raises(ValueError):
        resolve_wordlist("http://evil.example/words.txt")


def test_ffuf_builds_dir_command(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("admin\nlogin\n")
    cmd = ffuf_cmd("ffuf", {"url": "http://127.0.0.1", "wordlist": str(wl),
                            "match_codes": "200,403"}, rate=10, concurrency=5)
    assert cmd[cmd.index("-u") + 1].endswith("/FUZZ")
    assert cmd[cmd.index("-mc") + 1] == "200,403"
    assert cmd[cmd.index("-rate") + 1] == "10"


def test_ffuf_bad_match_codes(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("x\n")
    with pytest.raises(ValueError):
        ffuf_cmd("ffuf", {"url": "http://127.0.0.1", "wordlist": str(wl),
                          "match_codes": "2xx; rm -rf"}, rate=0, concurrency=5)


# ---- katana / arjun --------------------------------------------------------
def test_katana_depth_bounds():
    assert "-jc" in katana_cmd("katana", {"url": "http://127.0.0.1", "depth": 3,
                                          "js_crawl": True}, rate=5, concurrency=5)
    with pytest.raises(ValueError):
        katana_cmd("katana", {"url": "http://127.0.0.1", "depth": 99}, rate=5, concurrency=5)


def test_arjun_method_allowlist():
    assert arjun_cmd("arjun", "http://127.0.0.1", "POST", "/tmp/o.json", 10, 5)
    with pytest.raises(ValueError):
        arjun_cmd("arjun", "http://127.0.0.1", "TRACE", "/tmp/o.json", 10, 5)


# ---- sqlmap (locked down) --------------------------------------------------
def test_sqlmap_blocks_code_execution():
    for bad in [{"enumerate": ["--os-shell"]}, {"enumerate": ["--file-read"]},
                {"enumerate": ["--sql-shell"]}]:
        with pytest.raises(ValueError):
            sqlmap_cmd("sqlmap", {"url": "http://127.0.0.1/?id=1", **bad}, "/tmp/o", 0)


def test_sqlmap_rejects_forbidden_in_body():
    with pytest.raises(ValueError):
        sqlmap_cmd("sqlmap", {"url": "http://127.0.0.1/", "data": "x=--os-cmd=id"},
                   "/tmp/o", 0)


def test_sqlmap_detection_command_is_safe():
    cmd = sqlmap_cmd("sqlmap", {"url": "http://127.0.0.1/?id=1", "level": "2",
                                "risk": "1", "enumerate": ["--banner", "--dbs"]},
                     "/tmp/o", 0.1)
    assert "--batch" in cmd and "--banner" in cmd and "--dbs" in cmd
    assert "--delay" in cmd
    assert not any("--os" in c or "shell" in c for c in cmd)


def test_sqlmap_level_risk_validated():
    with pytest.raises(ValueError):
        sqlmap_cmd("sqlmap", {"url": "http://127.0.0.1/?id=1", "level": "9"}, "/tmp/o", 0)


@pytest.mark.asyncio
async def test_sqlmap_registered_as_exploit():
    from spectreops.core.tool_registry import ToolRegistry
    from spectreops.tools.loader import register_all
    reg = ToolRegistry()
    register_all(reg)
    assert reg.get("sqlmap_test").danger == "exploit"


# ---- graphql ---------------------------------------------------------------
@pytest.mark.asyncio
async def test_graphql_detects_disabled_introspection(monkeypatch):
    import spectreops.tools.api.graphql as gq

    async def fake_req(method, url, **kw):
        return {"status": 400, "body": '{"errors":[{"message":"introspection disabled"}]}'}
    monkeypatch.setattr(gq, "http_request", fake_req)
    res = await gq.graphql_introspect({"url": "http://127.0.0.1/graphql"})
    assert res["introspection_enabled"] is False


@pytest.mark.asyncio
async def test_graphql_enumerates_schema(monkeypatch):
    import spectreops.tools.api.graphql as gq
    schema = {"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": [{"name": "Query", "kind": "OBJECT", "fields": [{"name": "me"}]},
                  {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "login"}]},
                  {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}]},
                  {"name": "__Directive", "kind": "OBJECT", "fields": []}]}}}

    async def fake_req(method, url, **kw):
        import json
        return {"status": 200, "body": json.dumps(schema)}
    monkeypatch.setattr(gq, "http_request", fake_req)
    res = await gq.graphql_introspect({"url": "http://127.0.0.1/graphql"})
    assert res["introspection_enabled"] and res["queries"] == ["me"]
    assert res["mutations"] == ["login"] and "User" in res["types"]
    assert "__Directive" not in res["types"]


# ---- replay / BOLA ---------------------------------------------------------
@pytest.mark.asyncio
async def test_http_replay_flags_identical_responses(monkeypatch):
    import spectreops.tools.builtin.http_request_tool as hr

    async def fake_send(args):
        return {"status": 200, "body": "same object for everyone"}
    monkeypatch.setattr(hr, "http_send", fake_send)
    res = await hr.http_replay({"url": "http://127.0.0.1/api/orders/1",
                                "identities": ["alice", "bob", ""]})
    assert res["identical_responses"] is True and len(res["runs"]) == 3


@pytest.mark.asyncio
async def test_http_send_rejects_bad_method():
    from spectreops.tools.builtin.http_request_tool import http_send
    assert "method must be" in (await http_send({"url": "http://127.0.0.1/",
                                                 "method": "CONNECT"}))["error"]
