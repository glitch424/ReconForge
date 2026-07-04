import logging
from typing import List, Dict, Optional
import aiodns

logger = logging.getLogger(__name__)


class DNSResolver:
    def __init__(self, nameservers: Optional[List[str]] = None) -> None:
        self.resolver = aiodns.DNSResolver(nameservers=nameservers)

    async def resolve_a(self, domain: str) -> List[str]:
        try:
            result = await self.resolver.query(domain, "A")
            return [res.host for res in result]
        except (aiodns.error.DNSError, Exception) as e:
            logger.debug(f"Failed to resolve A record for {domain}: {e}")
            return []

    async def resolve_aaaa(self, domain: str) -> List[str]:
        try:
            result = await self.resolver.query(domain, "AAAA")
            return [res.host for res in result]
        except (aiodns.error.DNSError, Exception) as e:
            logger.debug(f"Failed to resolve AAAA record for {domain}: {e}")
            return []

    async def resolve_cname(self, domain: str) -> List[str]:
        try:
            result = await self.resolver.query(domain, "CNAME")
            return [result.cname]
        except (aiodns.error.DNSError, Exception) as e:
            logger.debug(f"Failed to resolve CNAME record for {domain}: {e}")
            return []

    async def check_wildcard(self, domain: str) -> bool:
        """Check if a domain has a wildcard DNS record."""
        # Query a random non-existent subdomain
        random_sub = f"nonexistent-wildcard-test-123456789.{domain}"
        try:
            result = await self.resolver.query(random_sub, "A")
            if result:
                return True
        except (aiodns.error.DNSError, Exception):
            pass
        return False

    async def resolve_all(self, domain: str) -> Dict[str, List[str]]:
        """Resolve A, AAAA, and CNAME records."""
        results: Dict[str, List[str]] = {"A": [], "AAAA": [], "CNAME": []}

        a_records = await self.resolve_a(domain)
        if a_records:
            results["A"] = a_records

        aaaa_records = await self.resolve_aaaa(domain)
        if aaaa_records:
            results["AAAA"] = aaaa_records

        cname_records = await self.resolve_cname(domain)
        if cname_records:
            results["CNAME"] = cname_records

        return results
