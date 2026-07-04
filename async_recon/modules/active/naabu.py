"""Naabu port scanner plugin.

Wraps the Naabu binary via asyncio.create_subprocess_exec, parses its
line-based output, and normalizes results into PortRecord-compatible
dicts. Subprocess execution, output parsing, and result normalization
are in separate methods for testability.
"""

import asyncio
import logging
from typing import Any, Dict, List

from async_recon.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class NaabuPlugin(BasePlugin):
    """Naabu wrapper for async port discovery."""

    def __init__(self, timeout: int = 600) -> None:
        super().__init__("naabu")
        self.timeout = timeout

    async def initialize(self) -> None:
        """Verify that the naabu binary is available in PATH."""
        try:
            process = await asyncio.create_subprocess_exec(
                "naabu",
                "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
        except FileNotFoundError:
            logger.warning("naabu binary not found in PATH. Plugin will be disabled.")
            raise

    async def run(self, target: str) -> List[Dict[str, Any]]:
        """Run naabu against a single target domain/IP."""
        logger.info(f"Running naabu port scan against {target}")
        results: List[Dict[str, Any]] = []
        try:
            stdout = await self._execute(target)
            parsed = self._parse_output(stdout, target)
            results.extend(parsed)
        except asyncio.TimeoutError:
            logger.error(f"naabu timed out after {self.timeout}s for {target}")
        except Exception as e:
            logger.error(f"Error running naabu against {target}: {e}")
        return results

    async def _execute(self, target: str) -> str:
        """Shell out to naabu and return raw stdout."""
        process = await asyncio.create_subprocess_exec(
            "naabu",
            "-host",
            target,
            "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=self.timeout
        )

        if process.returncode != 0:
            logger.warning(
                f"naabu returned exit code {process.returncode} for {target}"
            )
            if stderr:
                logger.debug(f"naabu stderr: {stderr.decode().strip()}")

        return stdout.decode() if stdout else ""

    def _parse_output(self, raw: str, target: str) -> List[Dict[str, Any]]:
        """Parse naabu line output into normalized result dicts.

        Naabu outputs lines like:
          host:port
          192.168.1.1:80
          example.com:443
        """
        results: List[Dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # Handle host:port format
            if ":" in line:
                parts = line.rsplit(":", 1)
                host = parts[0]
                port_str = parts[1]
            else:
                # Some versions output just the port number
                host = target
                port_str = line

            try:
                port = int(port_str)
                results.append(
                    {
                        "target": target,
                        "host": host,
                        "port": port,
                        "protocol": "tcp",
                        "source": self.name,
                    }
                )
            except ValueError:
                logger.debug(f"Skipping unparsable naabu line: {line}")

        return results

    async def cleanup(self) -> None:
        """No resources to clean up."""
        pass
