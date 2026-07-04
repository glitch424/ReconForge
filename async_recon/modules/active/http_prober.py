"""HTTP prober plugin.

Uses aiohttp to probe discovered subdomains and collect status codes,
redirect chains, response headers, page titles, content length, and
TLS certificate information.

Subprocess execution, parsing, and normalization are separated into
distinct methods for testability.
"""

import asyncio
import logging
import re
import ssl
from typing import Any, Dict, List

import aiohttp

from async_recon.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

# Regex to extract <title> from HTML
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class HttpProber(BasePlugin):
    """Probes HTTP/HTTPS endpoints and collects response metadata."""

    def __init__(self, timeout: int = 15, concurrency: int = 20) -> None:
        super().__init__("http_prober")
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)

    async def initialize(self) -> None:
        """No external binary required — pure Python plugin."""
        logger.info("HttpProber initialized (aiohttp-based, no external binary).")

    async def run(self, target: str) -> None:
        """Probe a single URL target (e.g. 'https://example.com:443')."""
        async with self._semaphore:
            await self._probe_url(target)

    async def run_batch(self, urls: List[str]) -> None:
        """Probe multiple URLs concurrently, respecting the semaphore."""
        tasks = [asyncio.create_task(self.run(url)) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_url(self, url: str) -> None:
        """Execute a single HTTP probe and normalize the result."""
        try:
            client_timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                timeout=client_timeout, connector=connector
            ) as session:
                async with session.get(
                    url, allow_redirects=True, max_redirects=10
                ) as response:
                    body = await response.text(errors="replace")
                    result = self._normalize_response(url, response, body)

                    # Collect TLS info if HTTPS
                    if url.startswith("https://"):
                        tls_info = await self._collect_tls_info(url)
                        result.update(tls_info)

                    self.results.append(result)

        except asyncio.TimeoutError:
            logger.warning(f"Timeout probing {url}")
        except aiohttp.ClientError as e:
            logger.warning(f"HTTP error probing {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error probing {url}: {e}")

    def _normalize_response(
        self,
        url: str,
        response: aiohttp.ClientResponse,
        body: str,
    ) -> Dict[str, Any]:
        """Extract and normalize response metadata into a flat dict."""
        title = ""
        title_match = TITLE_RE.search(body)
        if title_match:
            title = title_match.group(1).strip()

        redirect_url = ""
        if response.history:
            redirect_url = str(response.url)

        return {
            "url": url,
            "status_code": response.status,
            "title": title[:256],
            "content_length": len(body),
            "redirect_url": redirect_url,
            "server": response.headers.get("Server", ""),
            "content_type": response.headers.get("Content-Type", ""),
            "tls_issuer": "",
            "tls_subject": "",
            "tls_not_after": "",
        }

    async def _collect_tls_info(self, url: str) -> Dict[str, str]:
        """Connect with TLS and extract certificate details."""
        result: Dict[str, str] = {
            "tls_issuer": "",
            "tls_subject": "",
            "tls_not_after": "",
        }
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port or 443

            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=self.timeout,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    result["tls_issuer"] = issuer.get("organizationName", "")
                    result["tls_subject"] = subject.get("commonName", "")
                    result["tls_not_after"] = cert.get("notAfter", "")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"TLS info collection failed for {url}: {e}")
        return result

    async def cleanup(self) -> None:
        """No resources to clean up."""
        pass
