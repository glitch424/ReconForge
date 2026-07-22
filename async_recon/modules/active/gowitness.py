"""Gowitness screenshot plugin.

Wraps the gowitness binary via asyncio.create_subprocess_exec to capture
screenshots of discovered HTTP endpoints. Screenshot metadata (URL + file
path) is returned as normalized result dicts and persisted to the DB so
the reporting layer can reference them without re-scanning.

Subprocess execution and output detection are separated for testability.
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
        timeout: int = 90,
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

            if process.returncode != 0:
                logger.warning(
                    "gowitness version command returned a non-zero exit code."
                )

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

            logger.warning(
                f"gowitness ran for {target} but no screenshot file was found"
            )
            return []

        except asyncio.TimeoutError:
            logger.error(
                f"gowitness timed out after {self.timeout}s for {target}"
            )
            return []

        except Exception as e:
            logger.error(
                f"Error capturing screenshot for {target}: {e}"
            )
            return []

    async def _execute(self, url: str) -> str:
        """Run Gowitness v3 and return the screenshot file it created."""
        output_dir = Path(self.output_dir)

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Record screenshots that already exist before running Gowitness.
        before = {
            path.resolve()
            for path in output_dir.iterdir()
            if path.is_file()
            and path.suffix.lower() in {".png", ".jpg", ".jpeg"}
        }

        process = await asyncio.create_subprocess_exec(
            "gowitness",
            "scan",
            "single",
            "-u",
            url,
            "--screenshot-path",
            str(output_dir),
            "--screenshot-format",
            "png",
            "--write-none",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=self.timeout,
        )

        if process.returncode != 0:
            logger.warning(
                f"gowitness returned exit code "
                f"{process.returncode} for {url}"
            )

            if stderr:
                logger.debug(
                    "gowitness stderr: "
                    f"{stderr.decode(errors='replace').strip()}"
                )

            return ""

        # Check which screenshot files exist after Gowitness finished.
        after = {
            path.resolve()
            for path in output_dir.iterdir()
            if path.is_file()
            and path.suffix.lower() in {".png", ".jpg", ".jpeg"}
        }

        # Files that did not exist before are screenshots created
        # by this Gowitness execution.
        new_files = after - before

        if not new_files:
            logger.warning(
                f"gowitness completed for {url} "
                "but did not create a screenshot"
            )

            if stdout:
                logger.debug(
                    "gowitness stdout: "
                    f"{stdout.decode(errors='replace').strip()}"
                )

            if stderr:
                logger.debug(
                    "gowitness stderr: "
                    f"{stderr.decode(errors='replace').strip()}"
                )

            return ""

        # `scan single` should normally create one screenshot.
        # If multiple files appear, select the most recently modified one.
        screenshot = max(
            new_files,
            key=lambda path: path.stat().st_mtime,
        )

        logger.debug(
            f"Gowitness screenshot created: {screenshot}"
        )

        return str(screenshot)

    async def cleanup(self) -> None:
        """No resources to clean up."""
        pass