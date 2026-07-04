"""Tests for the technology detection plugin.

All HTTP calls are mocked — no real network requests are made.
"""

from unittest.mock import AsyncMock, patch

import pytest

from async_recon.modules.active.tech_detect import TechDetector


@pytest.fixture
def detector() -> TechDetector:
    return TechDetector(timeout=5)


def test_match_signatures_nginx(detector: TechDetector) -> None:
    """Test detection of Nginx from Server header."""
    headers = {"Server": "nginx/1.21.0", "Content-Type": "text/html"}
    body = "<html></html>"
    matches = detector._match_signatures("https://example.com", headers, body)
    names = [m["name"] for m in matches]
    assert "Nginx" in names


def test_match_signatures_php(detector: TechDetector) -> None:
    """Test detection of PHP from X-Powered-By header."""
    headers = {"X-Powered-By": "PHP/8.1.0", "Server": "Apache/2.4.51"}
    body = "<html></html>"
    matches = detector._match_signatures("https://example.com", headers, body)
    names = [m["name"] for m in matches]
    assert "PHP" in names
    assert "Apache" in names


def test_match_signatures_wordpress(detector: TechDetector) -> None:
    """Test detection of WordPress from body content."""
    headers = {"Server": "nginx"}
    body = '<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">'
    matches = detector._match_signatures("https://example.com", headers, body)
    names = [m["name"] for m in matches]
    assert "WordPress" in names
    assert "Nginx" in names


def test_match_signatures_cloudflare(detector: TechDetector) -> None:
    """Test detection of Cloudflare from CF-RAY header."""
    headers = {"Server": "cloudflare", "CF-RAY": "abc123"}
    body = "<html></html>"
    matches = detector._match_signatures("https://example.com", headers, body)
    names = [m["name"] for m in matches]
    assert "Cloudflare" in names


def test_match_signatures_no_match(detector: TechDetector) -> None:
    """Test that no matches are returned for generic headers."""
    headers = {"Content-Type": "text/html"}
    body = "<html><body>Hello</body></html>"
    matches = detector._match_signatures("https://example.com", headers, body)
    assert len(matches) == 0


def test_extract_version() -> None:
    """Test version extraction from header values."""
    assert TechDetector._extract_version("nginx/1.21.0") == "1.21.0"
    assert TechDetector._extract_version("Apache/2.4") == "2.4"
    assert TechDetector._extract_version("cloudflare") == ""


def test_match_signatures_deduplication(detector: TechDetector) -> None:
    """Test that duplicate detections are not reported."""
    # Cloudflare appears in both web-server and cdn signatures
    headers = {"Server": "cloudflare", "CF-RAY": "abc123"}
    body = "<html></html>"
    matches = detector._match_signatures("https://example.com", headers, body)
    cloudflare_matches = [m for m in matches if m["name"] == "Cloudflare"]
    # Should have at most 2 (one per category: web-server and cdn)
    assert len(cloudflare_matches) == 2


@pytest.mark.asyncio
async def test_detect_with_mock(detector: TechDetector) -> None:
    """Test full detection flow with mocked HTTP response."""
    mock_headers = {"Server": "nginx/1.21.0", "Content-Type": "text/html"}
    mock_body = '<html><script src="/wp-content/main.js"></script></html>'

    with patch.object(
        detector, "_fetch", new=AsyncMock(return_value=(mock_headers, mock_body))
    ):
        results = await detector._detect("https://example.com")

    names = [r["name"] for r in results]
    assert "Nginx" in names
    assert "WordPress" in names


@pytest.mark.asyncio
async def test_initialize(detector: TechDetector) -> None:
    """Test that initialize completes without error."""
    await detector.initialize()


@pytest.mark.asyncio
async def test_custom_signatures() -> None:
    """Test that custom signatures can be injected."""
    custom_sigs = [
        {
            "category": "custom",
            "name": "MyApp",
            "header": "X-Custom",
            "pattern": r"myapp",
        }
    ]
    detector = TechDetector(signatures=custom_sigs)
    headers = {"X-Custom": "myapp/2.0"}
    body = ""
    matches = detector._match_signatures("https://example.com", headers, body)
    assert len(matches) == 1
    assert matches[0]["name"] == "MyApp"
    assert matches[0]["version"] == "2.0"
