"""Tests for the Naabu port scanner plugin.

All subprocess calls are mocked — naabu binary is not required.
"""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from async_recon.modules.active.naabu import NaabuPlugin


@pytest.fixture
def mock_subprocess() -> Generator[MagicMock, None, None]:
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (b"", b"")
        process_mock.returncode = 0
        mock_exec.return_value = process_mock
        yield mock_exec


@pytest.fixture
def naabu() -> NaabuPlugin:
    return NaabuPlugin(timeout=10)


@pytest.mark.asyncio
async def test_initialize(mock_subprocess: MagicMock, naabu: NaabuPlugin) -> None:
    """Test that initialize checks for the naabu binary."""
    await naabu.initialize()
    mock_subprocess.assert_called()


@pytest.mark.asyncio
async def test_initialize_missing_binary(naabu: NaabuPlugin) -> None:
    """Test that initialize raises when naabu is not found."""
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError):
            await naabu.initialize()


def test_parse_output_host_port(naabu: NaabuPlugin) -> None:
    """Test parsing of host:port formatted output."""
    raw = "example.com:80\nexample.com:443\n"
    results = naabu._parse_output(raw, "example.com")
    assert len(results) == 2
    assert results[0]["port"] == 80
    assert results[1]["port"] == 443
    assert results[0]["host"] == "example.com"


def test_parse_output_port_only(naabu: NaabuPlugin) -> None:
    """Test parsing when output contains only port numbers."""
    raw = "80\n443\n8080\n"
    results = naabu._parse_output(raw, "example.com")
    assert len(results) == 3
    assert results[2]["port"] == 8080
    assert results[0]["host"] == "example.com"


def test_parse_output_empty(naabu: NaabuPlugin) -> None:
    """Test parsing of empty output."""
    results = naabu._parse_output("", "example.com")
    assert len(results) == 0


def test_parse_output_garbage_lines(naabu: NaabuPlugin) -> None:
    """Test that non-parseable lines are skipped gracefully."""
    raw = "example.com:80\nnot-a-port\n\nexample.com:443\n"
    results = naabu._parse_output(raw, "example.com")
    assert len(results) == 2


@pytest.mark.asyncio
async def test_run(mock_subprocess: MagicMock, naabu: NaabuPlugin) -> None:
    """Test full run flow with mocked subprocess."""
    mock_subprocess.return_value.communicate.return_value = (
        b"example.com:22\nexample.com:80\nexample.com:443\n",
        b"",
    )
    results = await naabu.run("example.com")
    assert len(results) == 3
    assert {r["port"] for r in results} == {22, 80, 443}
