"""Gowitness screenshot plugin.

Wraps the gowitness binary via asyncio.create_subprocess_exec to capture
screenshots of discovered HTTP endpoints. Screenshot metadata (URL + file
path) is returned as normalized result dicts and persisted to the DB so
the reporting layer can reference them without re-scanning.

Subprocess execution and output parsing are separated for testability.
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List

from async_recon.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class GowitnessPlugin(BasePlugin):
    """Gowitness wrapper for automated web screenshot capture."""

    def __init__(
        self,
        output_dir: str = "screenshots",
        timeout: int = 30,
    ) -> None:
        super().__init__("gowitness")
        self.output_dir = output_dir
        self.timeout = timeout

    async def initialize(self) -> None:
        """Verify that the gowitness binary is available in PATH."""
        try:
            process = await asyncio.create_subprocess_exec(
                "gowitness",
                "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
        except FileNotFoundError:
            logger.warning(
                "gowitness binary not found in PATH. Plugin will be disabled."
            )
            raise

    async def run(self, target: str) -> List[Dict[str, Any]]:
        """Capture a screenshot for a single URL target.

        Args:
            target: A fully-qualified URL, e.g. 'https://example.com'.

        Returns:
            A list containing one result dict with 'url' and 'file_path',
            or an empty list on failure.
        """
        logger.info(f"Capturing screenshot for {target}")
        try:
            output_path = await self._execute(target)
            if output_path and Path(output_path).exists():
                return [
                    {
                        "url": target,
                        "file_path": output_path,
                        "source": self.name,
                    }
                ]
            else:
                logger.warning(f"gowitness ran for {target} but no output file found")
                return []
        except asyncio.TimeoutError:
            logger.error(f"gowitness timed out after {self.timeout}s for {target}")
            return []
        except Exception as e:
            logger.error(f"Error capturing screenshot for {target}: {e}")
            return []

    async def _execute(self, url: str) -> str:
        """Shell out to gowitness and return the expected output path.

        gowitness single --url <url> --screenshot-path <dir>
        The output filename is derived deterministically from the URL by
        gowitness itself; we return the expected path after execution.
        """
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        process = await asyncio.create_subprocess_exec(
            "gowitness",
            "single",
            "--url",
            url,
            "--screenshot-path",
            self.output_dir,
            "--disable-db",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=self.timeout
        )

        if process.returncode != 0:
            logger.warning(
                f"gowitness returned exit code {process.returncode} for {url}"
            )
            if stderr:
                logger.debug(f"gowitness stderr: {stderr.decode().strip()}")

        # Derive filename the same way gowitness does: URL-safe slug + .png
        output_path = self._derive_output_path(url)
        logger.debug(f"Expected screenshot path: {output_path}")
        return output_path

    def _derive_output_path(self, url: str) -> str:
        """Derive the expected screenshot filename from a URL.

        gowitness names files after the URL with special chars replaced by
        underscores, e.g. https://example.com → https_example_com.png
        """
        # Strip scheme separators and replace non-alphanumeric chars
        slug = url.replace("://", "_").replace("/", "_")
        # Remove trailing underscores
        slug = slug.rstrip("_")
        filename = f"{slug}.png"
        return str(Path(self.output_dir) / filename)

    async def cleanup(self) -> None:
        """No resources to clean up."""
        pass
