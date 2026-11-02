"""Regression checks for HTTPS verification and inherited proxy settings."""
from __future__ import annotations

import httpx
import pytest

from spectreops.tools import base
from spectreops.tools.api import openapi_ingest
from spectreops.tools.web import dir_brute


@pytest.mark.asyncio
async def test_shared_http_client_enforces_tls_and_disables_env_proxy(monkeypatch):
    observed = {}

    class FakeClient:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def request(self, method, url, **_kwargs):
            request = httpx.Request(method, url)
            return httpx.Response(200, text="ok", request=request)

    monkeypatch.setattr(base.httpx, "AsyncClient", FakeClient)
    response = await base.http_request("GET", "https://127.0.0.1/")
    assert response["status"] == 200
    assert observed["verify"] is True
    assert observed["trust_env"] is False
    assert observed["follow_redirects"] is False


@pytest.mark.asyncio
async def test_openapi_fetch_enforces_tls_and_disables_env_proxy(monkeypatch):
    observed = {}

    class FakeClient:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, url):
            return httpx.Response(
                200,
                text='{"openapi":"3.0.0","paths":{},"info":{"title":"safe"}}',
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr(openapi_ingest.httpx, "AsyncClient", FakeClient)
    result = await openapi_ingest.openapi_endpoints({"url": "https://127.0.0.1/openapi.json"})
    assert result["title"] == "safe"
    assert observed["verify"] is True
    assert observed["trust_env"] is False
    assert observed["follow_redirects"] is False


@pytest.mark.asyncio
async def test_directory_probe_enforces_tls_and_disables_env_proxy(monkeypatch):
    observed = {}

    class FakeClient:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, url):
            return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(dir_brute.httpx, "AsyncClient", FakeClient)
    await dir_brute.dir_brute({"base_url": "https://127.0.0.1", "words": ["robots.txt"]})
    assert observed["verify"] is True
    assert observed["trust_env"] is False
    assert observed["follow_redirects"] is False
