import asyncio
import logging
from collections.abc import Callable
from typing import Any, Dict, List

from async_recon.plugins.base import BasePlugin
from async_recon.modules.passive.subfinder import SubfinderPlugin
from async_recon.modules.passive.assetfinder import AssetfinderPlugin
from async_recon.modules.passive.amass import AmassPlugin

logger = logging.getLogger(__name__)


class PluginManager:
    def __init__(self) -> None:
        self.available_plugins: List[Callable[[], BasePlugin]] = [
            SubfinderPlugin,
            AssetfinderPlugin,
            AmassPlugin,
        ]
        self.active_plugins: List[BasePlugin] = []

    async def initialize_plugins(self) -> None:
        """Initialize all available plugins, filtering out those that fail (e.g., missing binaries)."""
        logger.info("Initializing plugins...")
        for plugin_class in self.available_plugins:
            plugin = plugin_class()
            try:
                await plugin.initialize()
                self.active_plugins.append(plugin)
                logger.info(f"Plugin '{plugin.name}' initialized successfully.")
            except Exception as e:
                logger.warning(
                    f"Plugin '{plugin.name}' failed to initialize and will be disabled: {e}"
                )

    async def run_passive_plugins(self, target: str) -> List[Dict[str, Any]]:
        """Run all active passive plugins concurrently and aggregate results."""
        logger.info(f"Running passive plugins for target: {target}")
        tasks = []
        for plugin in self.active_plugins:
            # We assume all currently loaded plugins are passive for this milestone
            tasks.append(asyncio.create_task(plugin.run(target)))

        gather_results = await asyncio.gather(*tasks, return_exceptions=True)

        all_results = []
        for plugin, result in zip(self.active_plugins, gather_results):
            if isinstance(result, Exception):
                logger.error(
                    f"Plugin '{plugin.name}' encountered an unexpected error: {result}"
                )
            elif isinstance(result, list):
                all_results.extend(result)
                logger.debug(f"Plugin '{plugin.name}' found {len(result)} results.")
            else:
                logger.warning(
                    f"Plugin '{plugin.name}' returned an unexpected type: {type(result)}"
                )

        return all_results

    async def cleanup_plugins(self) -> None:
        """Clean up all active plugins."""
        for plugin in self.active_plugins:
            try:
                await plugin.cleanup()
            except Exception as e:
                logger.error(f"Error during cleanup of plugin '{plugin.name}': {e}")
