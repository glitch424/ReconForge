"""Scanner engine — pure orchestration.

Responsible only for task scheduling, concurrency limiting, timeouts,
retries, and progress reporting via Rich. Contains NO probing, port
scanning, or technology detection logic — those live in plugins.

Data flows:  plugins → engine.run_stage() → database store
"""

import asyncio
import logging
from typing import Any, Dict, List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

from async_recon.config.settings import ScannerSettings
from async_recon.database.store import DatabaseStore
from async_recon.plugins.base import BasePlugin

logger = logging.getLogger(__name__)
console = Console()

class ScannerEngine:
    """Orchestrates active recon stages with concurrency, timeouts, and retries."""

    def __init__(
        self,
        settings: ScannerSettings,
        db: DatabaseStore,
    ) -> None:
        self.settings = settings
        self.db = db
        self._semaphore = asyncio.Semaphore(settings.http_concurrency)

    # ------------------------------------------------------------------
    # Public orchestration API
    # ------------------------------------------------------------------

    async def run_stage(
        self,
        stage_name: str,
        plugin: BasePlugin,
        targets: List[str],
        timeout: int | None = None,
    ) -> List[Dict[str, Any]]:
        """Run a single plugin across a list of targets with progress tracking.

        Args:
            stage_name: Human-readable stage label for logging/progress.
            plugin: An initialized BasePlugin instance.
            targets: List of targets (URLs, domains, etc.) to process.
            timeout: Overall stage timeout in seconds; defaults to settings.stage_timeout.

        Returns:
            The plugin's collected results after all targets are processed.
        """
        effective_timeout = timeout or self.settings.stage_timeout
        logger.info(
            f"Starting stage '{stage_name}' with {len(targets)} targets "
            f"(timeout={effective_timeout}s)"
        )

        results: List[Dict[str, Any]] = []
        try:
            async with asyncio.timeout(effective_timeout):
                results = await self._execute_with_progress(stage_name, plugin, targets)
        except TimeoutError:
            logger.error(f"Stage '{stage_name}' timed out after {effective_timeout}s")

        logger.info(f"Stage '{stage_name}' completed with {len(results)} results.")
        return results

    async def run_stage_safe(
        self,
        stage_name: str,
        plugin: BasePlugin,
        targets: List[str],
        timeout: int | None = None,
    ) -> List[Dict[str, Any]]:
        """Like run_stage, but catches all exceptions so the scan continues."""
        try:
            return await self.run_stage(stage_name, plugin, targets, timeout)
        except Exception as e:
            logger.error(f"Stage '{stage_name}' failed with unexpected error: {e}")
            return []

    async def execute_plugin_stage(
        self,
        stage_name: str,
        plugin: BasePlugin,
        targets: List[str],
        timeout: int | None = None,
    ) -> List[Dict[str, Any]]:
        """Safely initialize, execute, and cleanup an active plugin."""
        try:
            await plugin.initialize()
            return await self.run_stage_safe(stage_name, plugin, targets, timeout)
        except FileNotFoundError:
            console.print(f"  [yellow]⚠[/yellow] {plugin.name} not found — stage '{stage_name}' skipped")
            return []
        finally:
            try:
                await plugin.cleanup()
            except Exception as e:
                logger.error(f"Error during cleanup of plugin '{plugin.name}': {e}")

    # ------------------------------------------------------------------
    # Store helpers — persist plugin results to DB
    # ------------------------------------------------------------------

    async def store_port_results(
        self,
        results: List[Dict[str, Any]],
        subdomain_id_map: Dict[str, int],
    ) -> None:
        """Persist port scan results to the database."""
        for r in results:
            host = r.get("host", "")
            sub_id = subdomain_id_map.get(host)
            if sub_id is None:
                logger.debug(f"No subdomain ID for host {host}, skipping port result")
                continue
            await self.db.add_port(
                subdomain_id=sub_id,
                port=r["port"],
                protocol=r.get("protocol", "tcp"),
                service=r.get("service", ""),
            )

    async def store_http_results(
        self,
        results: List[Dict[str, Any]],
        subdomain_id_map: Dict[str, int],
        url_to_subdomain: Dict[str, str],
    ) -> None:
        """Persist HTTP probe results to the database."""
        for r in results:
            url = r.get("url", "")
            subdomain = url_to_subdomain.get(url, "")
            sub_id = subdomain_id_map.get(subdomain)
            if sub_id is None:
                logger.debug(f"No subdomain ID for URL {url}, skipping HTTP result")
                continue
            await self.db.add_http_record(
                subdomain_id=sub_id,
                port=r.get("port", 443 if url.startswith("https") else 80),
                url=url,
                status_code=r.get("status_code", 0),
                title=r.get("title", ""),
                content_length=r.get("content_length", 0),
                redirect_url=r.get("redirect_url", ""),
                server=r.get("server", ""),
                content_type=r.get("content_type", ""),
                tls_issuer=r.get("tls_issuer", ""),
                tls_subject=r.get("tls_subject", ""),
                tls_not_after=r.get("tls_not_after", ""),
            )

    async def store_tech_results(
        self,
        results: List[Dict[str, Any]],
        subdomain_id_map: Dict[str, int],
        url_to_subdomain: Dict[str, str],
    ) -> None:
        """Persist technology detection results to the database."""
        for r in results:
            url = r.get("url", "")
            subdomain = url_to_subdomain.get(url, "")
            sub_id = subdomain_id_map.get(subdomain)
            if sub_id is None:
                logger.debug(f"No subdomain ID for URL {url}, skipping tech result")
                continue
            await self.db.add_tech_record(
                subdomain_id=sub_id,
                category=r.get("category", ""),
                name=r.get("name", ""),
                version=r.get("version", ""),
                confidence=r.get("confidence", 100),
            )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _execute_with_progress(
        self,
        stage_name: str,
        plugin: BasePlugin,
        targets: List[str],
    ) -> List[Dict[str, Any]]:
        """Run a plugin across targets with a Rich progress bar."""
        all_results: List[Dict[str, Any]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
        ) as progress:
            task_id: TaskID = progress.add_task(stage_name, total=len(targets))

            async def _run_one(t: str) -> List[Dict[str, Any]]:
                async with self._semaphore:
                    try:
                        return await asyncio.wait_for(
                            plugin.run(t),
                            timeout=self.settings.http_timeout,
                        )
                    except TimeoutError:
                        logger.warning(
                            f"Individual target timeout in '{stage_name}': {t}"
                        )
                    except Exception as e:
                        logger.warning(f"Error in '{stage_name}' for target {t}: {e}")
                    finally:
                        progress.advance(task_id)
                return []

            tasks = [asyncio.create_task(_run_one(t)) for t in targets]
            gather_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in gather_results:
                if isinstance(result, Exception):
                    logger.error(
                        f"Target in stage '{stage_name}' failed with unexpected error: {result}"
                    )
                elif isinstance(result, list):
                    all_results.extend(result)
                else:
                    logger.warning(f"Plugin returned unexpected type: {type(result)}")

        return all_results
