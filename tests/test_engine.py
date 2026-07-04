"""Tests for the scanner engine.

The engine is a pure orchestrator — we verify scheduling, concurrency,
timeout behavior, and DB persistence with mocked plugins and DB.
"""

from collections.abc import AsyncGenerator
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from async_recon.config.settings import ScannerSettings
from async_recon.database.store import DatabaseStore
from async_recon.plugins.base import BasePlugin
from async_recon.scanner.engine import ScannerEngine


class StubPlugin(BasePlugin):
    """A simple plugin that records what targets it was called with."""

    def __init__(self) -> None:
        super().__init__("stub")
        self._ran_targets: List[str] = []

    async def initialize(self) -> None:
        pass

    async def run(self, target: str) -> None:
        self._ran_targets.append(target)
        self.results.append({"url": target, "status_code": 200})

    async def cleanup(self) -> None:
        pass


class SlowPlugin(BasePlugin):
    """A plugin that sleeps to test timeout behavior."""

    def __init__(self) -> None:
        super().__init__("slow")

    async def initialize(self) -> None:
        pass

    async def run(self, target: str) -> None:
        import asyncio

        await asyncio.sleep(100)

    async def cleanup(self) -> None:
        pass


@pytest.fixture
async def db_store() -> AsyncGenerator[DatabaseStore, None]:
    store = DatabaseStore(":memory:")
    await store.connect()
    await store.init_schema()
    yield store
    await store.disconnect()


@pytest.fixture
def settings() -> ScannerSettings:
    return ScannerSettings(
        http_concurrency=5,
        http_timeout=2,
        stage_timeout=5,
    )


@pytest.fixture
def engine(settings: ScannerSettings, db_store: DatabaseStore) -> ScannerEngine:
    return ScannerEngine(settings=settings, db=db_store)


@pytest.mark.asyncio
async def test_run_stage(engine: ScannerEngine) -> None:
    """Test that run_stage executes a plugin against all targets."""
    plugin = StubPlugin()
    targets = ["http://a.com", "http://b.com", "http://c.com"]

    with patch("async_recon.scanner.engine.Progress"):
        results = await engine.run_stage("test", plugin, targets)

    assert len(results) == 3
    assert plugin._ran_targets == targets


@pytest.mark.asyncio
async def test_run_stage_safe_handles_error(engine: ScannerEngine) -> None:
    """Test that run_stage_safe catches exceptions and returns empty list."""
    plugin = MagicMock(spec=BasePlugin)
    plugin.run = AsyncMock(side_effect=RuntimeError("boom"))
    plugin.collect_results = MagicMock(return_value=[])

    with patch("async_recon.scanner.engine.Progress"):
        results = await engine.run_stage_safe("failing", plugin, ["http://x.com"])

    assert results == []


@pytest.mark.asyncio
async def test_run_stage_timeout(engine: ScannerEngine) -> None:
    """Test that stage-level timeout is enforced."""
    engine.settings.stage_timeout = 1
    engine.settings.http_timeout = 10
    plugin = SlowPlugin()

    with patch("async_recon.scanner.engine.Progress"):
        results = await engine.run_stage("slow_stage", plugin, ["http://slow.com"])

    # Should return whatever results were collected (likely none)
    assert results == []


@pytest.mark.asyncio
async def test_store_port_results(
    engine: ScannerEngine, db_store: DatabaseStore
) -> None:
    """Test that port results are persisted to the DB."""
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    subdomain_map = {"www.example.com": sub_id}

    port_results: List[Dict[str, Any]] = [
        {"host": "www.example.com", "port": 80, "protocol": "tcp"},
        {"host": "www.example.com", "port": 443, "protocol": "tcp"},
    ]

    await engine.store_port_results(port_results, subdomain_map)

    ports = await db_store.get_ports(sub_id)
    assert len(ports) == 2
    assert {p.port for p in ports} == {80, 443}


@pytest.mark.asyncio
async def test_store_http_results(
    engine: ScannerEngine, db_store: DatabaseStore
) -> None:
    """Test that HTTP results are persisted to the DB."""
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    subdomain_map = {"www.example.com": sub_id}
    url_map = {"https://www.example.com": "www.example.com"}

    http_results: List[Dict[str, Any]] = [
        {
            "url": "https://www.example.com",
            "status_code": 200,
            "title": "Example",
            "server": "nginx",
        },
    ]

    await engine.store_http_results(http_results, subdomain_map, url_map)

    records = await db_store.get_http_records(sub_id)
    assert len(records) == 1
    assert records[0].status_code == 200
    assert records[0].title == "Example"


@pytest.mark.asyncio
async def test_store_port_results_missing_subdomain(
    engine: ScannerEngine,
) -> None:
    """Test that port results for unknown hosts are skipped gracefully."""
    port_results: List[Dict[str, Any]] = [
        {"host": "unknown.com", "port": 80, "protocol": "tcp"},
    ]
    # Should not raise — just log and skip
    await engine.store_port_results(port_results, {})
