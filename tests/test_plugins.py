import pytest
from async_recon.plugins.base import BasePlugin


class DummyPlugin(BasePlugin):
    async def initialize(self) -> None:
        pass

    async def run(self, target: str) -> None:
        self.results.append({"target": target, "found": True})

    async def cleanup(self) -> None:
        pass


@pytest.mark.asyncio
async def test_base_plugin() -> None:
    plugin = DummyPlugin("dummy")
    await plugin.initialize()
    await plugin.run("example.com")
    await plugin.cleanup()
    results = plugin.collect_results()
    assert len(results) == 1
    assert results[0]["target"] == "example.com"
