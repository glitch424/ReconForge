from collections.abc import Generator

import pytest
import aiodns
from unittest.mock import AsyncMock, patch

from async_recon.scanner.dns_resolver import DNSResolver


class MockDNSRecord:
    def __init__(self, host: str) -> None:
        self.host = host


class MockCNAMERecord:
    def __init__(self, cname: str) -> None:
        self.cname = cname


@pytest.fixture
def dns_resolver() -> Generator[DNSResolver, None, None]:
    with patch("aiodns.DNSResolver") as mock_resolver_cls:
        instance = mock_resolver_cls.return_value
        resolver = DNSResolver()
        resolver.resolver = instance
        yield resolver


@pytest.mark.asyncio
async def test_resolve_a(dns_resolver: DNSResolver) -> None:
    with patch.object(
        dns_resolver.resolver,
        "query",
        new=AsyncMock(return_value=[MockDNSRecord("1.2.3.4")]),
    ):
        results = await dns_resolver.resolve_a("example.com")
        assert results == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_resolve_cname(dns_resolver: DNSResolver) -> None:
    with patch.object(
        dns_resolver.resolver,
        "query",
        new=AsyncMock(return_value=MockCNAMERecord("alias.example.com")),
    ):
        results = await dns_resolver.resolve_cname("example.com")
        assert results == ["alias.example.com"]


@pytest.mark.asyncio
async def test_check_wildcard(dns_resolver: DNSResolver) -> None:
    # Test True
    with patch.object(
        dns_resolver.resolver,
        "query",
        new=AsyncMock(return_value=[MockDNSRecord("1.2.3.4")]),
    ):
        assert await dns_resolver.check_wildcard("example.com") is True

    # Test False
    with patch.object(
        dns_resolver.resolver,
        "query",
        new=AsyncMock(side_effect=aiodns.error.DNSError),
    ):
        assert await dns_resolver.check_wildcard("example.com") is False
