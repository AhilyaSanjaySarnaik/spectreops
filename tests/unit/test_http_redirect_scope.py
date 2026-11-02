"""Regression coverage for safe handling of HTTP redirects."""
from __future__ import annotations

import httpx
import pytest

from spectreops.tools import base


@pytest.mark.asyncio
async def test_redirect_never_contacts_second_host(monkeypatch):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.host == "127.0.0.1":
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})
        raise AssertionError("out-of-scope redirect was followed")

    real_client = httpx.AsyncClient

    def client_factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(base.httpx, "AsyncClient", client_factory)
    result = await base.http_request(
        "GET", "http://127.0.0.1/", follow_redirects=True,
        headers={"Authorization": "Bearer local-only"},
    )

    assert "redirect not followed" in result["error"]
    assert result["status"] == 302
    assert result["location"] == "http://169.254.169.254/latest/meta-data"
    assert requests == ["http://127.0.0.1/"]


@pytest.mark.asyncio
async def test_redirect_with_follow_disabled_is_plain_response(monkeypatch):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"Location": "/new"}, text="redirect")

    real_client = httpx.AsyncClient

    def client_factory(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(base.httpx, "AsyncClient", client_factory)
    result = await base.http_request("GET", "http://127.0.0.1/", follow_redirects=False)
    assert result["status"] == 307
    assert "error" not in result
