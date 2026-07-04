"""Tests for the HTTP prober plugin.

All network calls are mocked — no real HTTP requests are made.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from async_recon.modules.active.http_prober import HttpProber


def _make_mock_response(
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: str = "<html><title>Test Page</title></html>",
    url: str = "https://example.com",
    history: list[Any] | None = None,
) -> MagicMock:
    """Create a mock aiohttp response."""
    resp = MagicMock()
    resp.status = status
    resp.headers = headers or {"Server": "nginx/1.21.0", "Content-Type": "text/html"}
    resp.text = AsyncMock(return_value=body)
    resp.url = url
    resp.history = history or []
    return resp


@pytest.fixture
def prober() -> HttpProber:
    return HttpProber(timeout=5, concurrency=5)


@pytest.mark.asyncio
async def test_normalize_response(prober: HttpProber) -> None:
    """Test that _normalize_response extracts title, server, etc."""
    mock_resp = _make_mock_response()
    result = prober._normalize_response(
        "https://example.com",
        mock_resp,
        "<html><title>Hello World</title></html>",
    )
    assert result["status_code"] == 200
    assert result["title"] == "Hello World"
    assert result["server"] == "nginx/1.21.0"
    assert result["content_type"] == "text/html"


@pytest.mark.asyncio
async def test_normalize_response_no_title(prober: HttpProber) -> None:
    """Test normalization when no title tag is present."""
    mock_resp = _make_mock_response()
    result = prober._normalize_response(
        "https://example.com",
        mock_resp,
        "<html><body>No title</body></html>",
    )
    assert result["title"] == ""


@pytest.mark.asyncio
async def test_normalize_response_with_redirect(prober: HttpProber) -> None:
    """Test that redirect URLs are captured when history is present."""
    mock_resp = _make_mock_response(
        url="https://www.example.com",
        history=[MagicMock()],
    )
    result = prober._normalize_response(
        "https://example.com",
        mock_resp,
        "<html><title>Redirected</title></html>",
    )
    assert result["redirect_url"] == "https://www.example.com"


@pytest.mark.asyncio
async def test_probe_url_success(prober: HttpProber) -> None:
    """Test full probe flow with mocked aiohttp session."""
    mock_resp = _make_mock_response()

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_session.get = MagicMock(return_value=mock_ctx)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await prober._probe_url("http://example.com")

    results = prober.collect_results()
    assert len(results) == 1
    assert results[0]["status_code"] == 200
    assert results[0]["title"] == "Test Page"


@pytest.mark.asyncio
async def test_probe_url_timeout(prober: HttpProber) -> None:
    """Test that timeouts are handled gracefully."""
    with patch("aiohttp.ClientSession", side_effect=Exception("timeout")):
        await prober._probe_url("http://timeout.example.com")

    # Should not crash, should log error
    results = prober.collect_results()
    assert len(results) == 0


@pytest.mark.asyncio
async def test_initialize(prober: HttpProber) -> None:
    """Test that initialize completes without error."""
    await prober.initialize()
