from collections.abc import AsyncGenerator

import pytest

from async_recon.database.store import DatabaseStore


@pytest.fixture
async def db_store() -> AsyncGenerator[DatabaseStore, None]:
    store = DatabaseStore(":memory:")
    await store.connect()
    await store.init_schema()
    yield store
    await store.disconnect()


@pytest.mark.asyncio
async def test_add_subdomain(db_store: DatabaseStore) -> None:
    id1 = await db_store.add_subdomain("example.com", "www.example.com", "test")
    id2 = await db_store.add_subdomain("example.com", "api.example.com", "test")
    assert id1 != id2

    # Test deduplication
    id3 = await db_store.add_subdomain("example.com", "www.example.com", "other")
    assert id1 == id3


@pytest.mark.asyncio
async def test_get_unresolved_subdomains(db_store: DatabaseStore) -> None:
    await db_store.add_subdomain("example.com", "www.example.com", "test")
    unresolved = await db_store.get_unresolved_subdomains()
    assert len(unresolved) == 1
    assert unresolved[0].subdomain == "www.example.com"
    assert not unresolved[0].resolved


@pytest.mark.asyncio
async def test_mark_resolved(db_store: DatabaseStore) -> None:
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.mark_resolved(sub_id, is_wildcard=True)

    unresolved = await db_store.get_unresolved_subdomains()
    assert len(unresolved) == 0


@pytest.mark.asyncio
async def test_add_dns_record(db_store: DatabaseStore) -> None:
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.add_dns_record(sub_id, "A", "1.2.3.4")
    # Schema enforcement and foreign keys would fail if sub_id didn't exist
