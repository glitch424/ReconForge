import asyncio
import logging
from async_recon.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class AssetfinderPlugin(BasePlugin):
    """Assetfinder wrapper for passive subdomain enumeration."""

    def __init__(self) -> None:
        super().__init__("assetfinder")

    async def initialize(self) -> None:
        """Check if assetfinder is installed and available in PATH."""
        try:
            process = await asyncio.create_subprocess_exec(
                "assetfinder",
                "-h",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            # assetfinder -h might return non-zero depending on version, just check if it exists
        except FileNotFoundError:
            logger.warning(
                "assetfinder binary not found in PATH. Plugin will be disabled."
            )
            raise

    async def run(self, target: str) -> None:
        """Run assetfinder against the target."""
        logger.info(f"Running assetfinder against {target}")
        try:
            process = await asyncio.create_subprocess_exec(
                "assetfinder",
                "--subs-only",
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(
                    f"assetfinder returned non-zero exit code {process.returncode}"
                )
                if stderr:
                    logger.error(f"assetfinder stderr: {stderr.decode().strip()}")
                # Proceed even with non-zero exit code, some tools do this if no results or partial errors

            if stdout:
                lines = stdout.decode().splitlines()
                for line in lines:
                    subdomain = line.strip()
                    if subdomain and subdomain.endswith(target):
                        self.results.append(
                            {
                                "target": target,
                                "subdomain": subdomain,
                                "source": self.name,
                            }
                        )

        except Exception as e:
            logger.error(f"Error running assetfinder: {e}")

    async def cleanup(self) -> None:
        pass
