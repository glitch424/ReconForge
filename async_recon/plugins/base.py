from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BasePlugin(ABC):
    """Abstract base class for all recon plugins."""

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize plugin, check dependencies, etc."""
        pass

    @abstractmethod
    async def run(self, target: str) -> List[Dict[str, Any]]:
        """Execute the plugin against the target and return results."""
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources after execution."""
        pass
