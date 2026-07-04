from collections.abc import Generator

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from async_recon.modules.passive.subfinder import SubfinderPlugin
from async_recon.modules.passive.assetfinder import AssetfinderPlugin
from async_recon.modules.passive.amass import AmassPlugin
from async_recon.plugins.manager import PluginManager


@pytest.fixture
def mock_subprocess() -> Generator[MagicMock, None, None]:
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (b"", b"")
        process_mock.returncode = 0
        mock_exec.return_value = process_mock
        yield mock_exec


@pytest.mark.asyncio
async def test_subfinder_plugin(mock_subprocess: MagicMock) -> None:
    mock_subprocess.return_value.communicate.return_value = (
        b"sub1.example.com\nsub2.example.com\n",
        b"",
    )
    plugin = SubfinderPlugin()
    await plugin.initialize()
    await plugin.run("example.com")
    results = plugin.collect_results()
    assert len(results) == 2
    assert results[0]["subdomain"] == "sub1.example.com"


@pytest.mark.asyncio
async def test_assetfinder_plugin(mock_subprocess: MagicMock) -> None:
    mock_subprocess.return_value.communicate.return_value = (
        b"api.example.com\nnot-matching.com\n",
        b"",
    )
    plugin = AssetfinderPlugin()
    await plugin.initialize()
    await plugin.run("example.com")
    results = plugin.collect_results()
    assert len(results) == 1
    assert results[0]["subdomain"] == "api.example.com"


@pytest.mark.asyncio
async def test_amass_plugin(mock_subprocess: MagicMock) -> None:
    mock_subprocess.return_value.communicate.return_value = (b"dev.example.com\n", b"")
    plugin = AmassPlugin()
    await plugin.initialize()
    await plugin.run("example.com")
    results = plugin.collect_results()
    assert len(results) == 1
    assert results[0]["subdomain"] == "dev.example.com"


@pytest.mark.asyncio
async def test_plugin_manager(mock_subprocess: MagicMock) -> None:
    # Setup mock to return some valid subdomains
    mock_subprocess.return_value.communicate.return_value = (
        b"test.example.com\n",
        b"",
    )

    manager = PluginManager()
    await manager.initialize_plugins()
    assert len(manager.active_plugins) == 3

    results = await manager.run_passive_plugins("example.com")
    # 3 plugins * 1 result each
    assert len(results) == 3
