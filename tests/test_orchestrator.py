"""Tests for the end-to-end scanner orchestrator."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from async_recon.scanner.orchestrator import run_scan


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock()
    db.connect = AsyncMock()
    db.init_schema = AsyncMock()
    db.disconnect = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_run_scan_no_targets() -> None:
    """run_scan with no targets should raise SystemExit."""
    with pytest.raises(SystemExit) as exc_info:
        await run_scan()
    assert exc_info.value.code == 1


@pytest.mark.asyncio
async def test_run_scan_invalid_target() -> None:
    """run_scan with invalid target should raise SystemExit."""
    with pytest.raises(SystemExit) as exc_info:
        await run_scan(target="not a valid target")
    assert exc_info.value.code == 1


@pytest.mark.asyncio
@patch("async_recon.scanner.orchestrator.DatabaseStore")
@patch("async_recon.scanner.orchestrator._scan_single_target")
async def test_run_scan_valid_target(
    mock_scan_single: AsyncMock,
    mock_db_cls: MagicMock,
    mock_db: MagicMock,
) -> None:
    """run_scan with valid target should initialize DB and run pipeline."""
    mock_db_cls.return_value = mock_db

    await run_scan(target="example.com")

    mock_db.connect.assert_awaited_once()
    mock_db.init_schema.assert_awaited_once()
    mock_scan_single.assert_awaited_once()
    mock_db.disconnect.assert_awaited_once()
