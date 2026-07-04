from abc import ABC, abstractmethod
from typing import Any, Dict


class BasePlugin(ABC):
    """Abstract base class for all recon plugins."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.results: list[Dict[str, Any]] = []

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize plugin, check dependencies, etc."""
        pass

    @abstractmethod
    async def run(self, target: str) -> None:
        """Execute the plugin against the target."""
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources after execution."""
        pass

    def collect_results(self) -> list[Dict[str, Any]]:
        """Return the collected results."""
        return self.results
