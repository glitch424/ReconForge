"""Technology detection plugin.

Uses httpx to fingerprint web technologies by inspecting HTTP response
headers, cookies, and HTML content. Each detection rule is a simple
dict-based signature for easy extension.

Subprocess execution is not needed — this is a pure-Python plugin.
Detection logic, signature matching, and normalization are separated
for testability.
"""

import asyncio
import logging
import re
from typing import Any, Dict, List

import httpx

from async_recon.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Signature database — easy to extend without touching framework core #
# ------------------------------------------------------------------ #
TECH_SIGNATURES: List[Dict[str, Any]] = [
    # Web servers
    {
        "category": "web-server",
        "name": "Nginx",
        "header": "Server",
        "pattern": r"nginx",
    },
    {
        "category": "web-server",
        "name": "Apache",
        "header": "Server",
        "pattern": r"Apache",
    },
    {
        "category": "web-server",
        "name": "Microsoft-IIS",
        "header": "Server",
        "pattern": r"Microsoft-IIS",
    },
    {
        "category": "web-server",
        "name": "LiteSpeed",
        "header": "Server",
        "pattern": r"LiteSpeed",
    },
    {
        "category": "web-server",
        "name": "Cloudflare",
        "header": "Server",
        "pattern": r"cloudflare",
    },
    # Frameworks / Languages
    {
        "category": "framework",
        "name": "Express",
        "header": "X-Powered-By",
        "pattern": r"Express",
    },
    {
        "category": "language",
        "name": "PHP",
        "header": "X-Powered-By",
        "pattern": r"PHP",
    },
    {
        "category": "language",
        "name": "ASP.NET",
        "header": "X-Powered-By",
        "pattern": r"ASP\.NET",
    },
    {
        "category": "framework",
        "name": "Django",
        "header": "X-Frame-Options",
        "pattern": r"DENY|SAMEORIGIN",
        "body_pattern": r"csrfmiddlewaretoken",
    },
    # CDN / WAF
    {
        "category": "cdn",
        "name": "Cloudflare",
        "header": "CF-RAY",
        "pattern": r".+",
    },
    {
        "category": "cdn",
        "name": "Akamai",
        "header": "X-Akamai-Transformed",
        "pattern": r".+",
    },
    # CMS
    {
        "category": "cms",
        "name": "WordPress",
        "body_pattern": r"wp-content|wp-includes",
    },
    {
        "category": "cms",
        "name": "Joomla",
        "body_pattern": r"/media/jui/|/components/com_",
    },
    {
        "category": "cms",
        "name": "Drupal",
        "body_pattern": r"Drupal\.settings|sites/default/files",
    },
]


class TechDetector(BasePlugin):
    """Fingerprints web technologies from HTTP responses."""

    def __init__(
        self,
        timeout: int = 30,
        concurrency: int = 20,
        signatures: List[Dict[str, Any]] | None = None,
    ) -> None:
        super().__init__("tech_detector")
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)
        self.signatures = signatures if signatures is not None else TECH_SIGNATURES

    async def initialize(self) -> None:
        """No external binary required — pure Python plugin."""
        logger.info(f"TechDetector initialized with {len(self.signatures)} signatures.")

    async def run(self, target: str) -> None:
        """Detect technologies on a single URL."""
        async with self._semaphore:
            await self._detect(target)

    async def run_batch(self, urls: List[str]) -> None:
        """Detect technologies on multiple URLs concurrently."""
        tasks = [asyncio.create_task(self.run(url)) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _detect(self, url: str) -> None:
        """Fetch URL and match against signature database."""
        try:
            headers_dict, body = await self._fetch(url)
            matches = self._match_signatures(url, headers_dict, body)
            self.results.extend(matches)
        except httpx.TimeoutException:
            logger.warning(f"Timeout detecting technologies on {url}")
        except httpx.HTTPError as e:
            logger.warning(f"HTTP error detecting technologies on {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error detecting technologies on {url}: {e}")

    async def _fetch(self, url: str) -> tuple[Dict[str, str], str]:
        """Fetch URL and return (headers_dict, body) for matching."""
        async with httpx.AsyncClient(
            timeout=self.timeout, verify=False, follow_redirects=True
        ) as client:
            response = await client.get(url)
            headers_dict = dict(response.headers)
            body = response.text
            return headers_dict, body

    def _match_signatures(
        self,
        url: str,
        headers: Dict[str, str],
        body: str,
    ) -> List[Dict[str, Any]]:
        """Match response against all signatures and return detections."""
        detections: List[Dict[str, Any]] = []
        seen: set[str] = set()

        for sig in self.signatures:
            category = sig["category"]
            name = sig["name"]
            key = f"{category}:{name}"

            if key in seen:
                continue

            matched = False
            version = ""

            # Check header-based signature
            header_name = sig.get("header", "")
            if header_name:
                header_val = headers.get(header_name, "") or headers.get(
                    header_name.lower(), ""
                )
                if header_val:
                    pattern = sig.get("pattern", "")
                    if pattern and re.search(pattern, header_val, re.IGNORECASE):
                        matched = True
                        version = self._extract_version(header_val)

            # Check body-based signature
            body_pattern = sig.get("body_pattern", "")
            if body_pattern and not matched:
                if re.search(body_pattern, body, re.IGNORECASE):
                    matched = True

            if matched:
                seen.add(key)
                detections.append(
                    {
                        "url": url,
                        "category": category,
                        "name": name,
                        "version": version,
                        "confidence": 100,
                        "source": self.name,
                    }
                )

        return detections

    @staticmethod
    def _extract_version(header_value: str) -> str:
        """Try to extract a version number from a header value."""
        match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", header_value)
        return match.group(0) if match else ""

    async def cleanup(self) -> None:
        """No resources to clean up."""
        pass
