import pytest
from typing import Any
from async_recon.plugins.base import BasePlugin


class DummyPlugin(BasePlugin):
    async def initialize(self) -> None:
        pass

    async def run(self, target: str) -> list[dict[str, Any]]:
        return [{"target": target, "found": True}]

    async def cleanup(self) -> None:
        pass


@pytest.mark.asyncio
async def test_base_plugin() -> None:
    plugin = DummyPlugin("dummy")
    await plugin.initialize()
    results = await plugin.run("example.com")
    await plugin.cleanup()
    assert len(results) == 1
    assert results[0]["target"] == "example.com"
