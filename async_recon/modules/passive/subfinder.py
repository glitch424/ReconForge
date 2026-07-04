import asyncio
import logging
from async_recon.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class SubfinderPlugin(BasePlugin):
    """Subfinder wrapper for passive subdomain enumeration."""

    def __init__(self) -> None:
        super().__init__("subfinder")

    async def initialize(self) -> None:
        """Check if subfinder is installed and available in PATH."""
        try:
            process = await asyncio.create_subprocess_exec(
                "subfinder",
                "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            if process.returncode != 0:
                logger.warning("subfinder command failed during initialization.")
        except FileNotFoundError:
            logger.warning(
                "subfinder binary not found in PATH. Plugin will be disabled."
            )
            raise

    async def run(self, target: str) -> None:
        """Run subfinder against the target."""
        logger.info(f"Running subfinder against {target}")
        try:
            # -silent: only output domains, -d: domain to find subdomains for
            process = await asyncio.create_subprocess_exec(
                "subfinder",
                "-d",
                target,
                "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(
                    f"subfinder returned non-zero exit code {process.returncode}"
                )
                if stderr:
                    logger.error(f"subfinder stderr: {stderr.decode().strip()}")
                return

            if stdout:
                lines = stdout.decode().splitlines()
                for line in lines:
                    subdomain = line.strip()
                    if subdomain:
                        self.results.append(
                            {
                                "target": target,
                                "subdomain": subdomain,
                                "source": self.name,
                            }
                        )

        except Exception as e:
            logger.error(f"Error running subfinder: {e}")

    async def cleanup(self) -> None:
        pass
