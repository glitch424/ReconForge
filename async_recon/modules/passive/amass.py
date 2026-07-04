import asyncio
import logging
from typing import Any, Dict, List
from async_recon.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class AmassPlugin(BasePlugin):
    """Amass wrapper for passive subdomain enumeration."""

    def __init__(self) -> None:
        super().__init__("amass")

    async def initialize(self) -> None:
        """Check if amass is installed and available in PATH."""
        try:
            process = await asyncio.create_subprocess_exec(
                "amass",
                "enum",
                "-h",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
        except FileNotFoundError:
            logger.warning("amass binary not found in PATH. Plugin will be disabled.")
            raise

    async def run(self, target: str) -> List[Dict[str, Any]]:
        """Run amass in passive mode against the target."""
        logger.info(f"Running amass (passive) against {target}")
        results: List[Dict[str, Any]] = []
        try:
            # -passive -norecursive -noalts -d domain
            process = await asyncio.create_subprocess_exec(
                "amass",
                "enum",
                "-passive",
                "-norecursive",
                "-noalts",
                "-d",
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Amass passive can take a while, use a reasonable timeout handled by the plugin manager or here
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"amass returned non-zero exit code {process.returncode}")
                if stderr:
                    logger.debug(f"amass stderr: {stderr.decode().strip()}")

            if stdout:
                lines = stdout.decode().splitlines()
                for line in lines:
                    subdomain = line.strip()
                    # Amass might output extra info, simple filter to ensure it's a subdomain
                    if (
                        subdomain
                        and " " not in subdomain
                        and subdomain.endswith(target)
                    ):
                        results.append(
                            {
                                "target": target,
                                "subdomain": subdomain,
                                "source": self.name,
                            }
                        )

        except Exception as e:
            logger.error(f"Error running amass: {e}")
        return results

    async def cleanup(self) -> None:
        pass
