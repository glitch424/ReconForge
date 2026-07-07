"""Tests for the Gowitness plugin."""

from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from async_recon.modules.active.gowitness import GowitnessPlugin


@pytest.fixture
def mock_subprocess() -> Generator[MagicMock, None, None]:
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (b"", b"")
        process_mock.returncode = 0
        mock_exec.return_value = process_mock
        yield mock_exec


@pytest.fixture
def gowitness() -> GowitnessPlugin:
    return GowitnessPlugin(output_dir="/tmp/screenshots", timeout=5)


@pytest.mark.asyncio
async def test_initialize(
    mock_subprocess: MagicMock, gowitness: GowitnessPlugin
) -> None:
    """Test that initialize checks for the gowitness binary."""
    await gowitness.initialize()
    mock_subprocess.assert_called_with("gowitness", "version", stdout=-1, stderr=-1)


@pytest.mark.asyncio
async def test_initialize_missing_binary(gowitness: GowitnessPlugin) -> None:
    """Test that initialize raises when gowitness is not found."""
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError):
            await gowitness.initialize()


def test_derive_output_path(gowitness: GowitnessPlugin) -> None:
    """Test URL to filename derivation matches gowitness behavior."""
    import sys

    if sys.platform == "win32":
        expected = "\\tmp\\screenshots\\https_example.com.png"
    else:
        expected = "/tmp/screenshots/https_example.com.png"

    path = gowitness._derive_output_path("https://example.com/")

    # Path normalisation for cross-platform tests
    assert path.replace("\\", "/") == expected.replace("\\", "/")

    path2 = gowitness._derive_output_path("http://sub.example.com:8080")
    if sys.platform == "win32":
        expected2 = "\\tmp\\screenshots\\http_sub.example.com:8080.png"
    else:
        expected2 = "/tmp/screenshots/http_sub.example.com:8080.png"

    assert path2.replace("\\", "/") == expected2.replace("\\", "/")


@pytest.mark.asyncio
async def test_execute(mock_subprocess: MagicMock, gowitness: GowitnessPlugin) -> None:
    """Test _execute runs the command and returns the expected path."""
    with patch("pathlib.Path.mkdir"):
        path = await gowitness._execute("https://example.com")
        assert "https_example.com.png" in path


@pytest.mark.asyncio
async def test_run_success(gowitness: GowitnessPlugin) -> None:
    """Test successful run returns a valid result dict."""
    with patch.object(gowitness, "_execute", return_value="/tmp/test.png") as mock_exec:
        with patch("pathlib.Path.exists", return_value=True):
            results = await gowitness.run("https://example.com")

    mock_exec.assert_called_once_with("https://example.com")
    assert len(results) == 1
    assert results[0]["url"] == "https://example.com"
    assert results[0]["file_path"] == "/tmp/test.png"
    assert results[0]["source"] == "gowitness"


@pytest.mark.asyncio
async def test_run_no_file(gowitness: GowitnessPlugin) -> None:
    """Test run returns empty list when file is not created."""
    with patch.object(gowitness, "_execute", return_value="/tmp/test.png"):
        with patch("pathlib.Path.exists", return_value=False):
            results = await gowitness.run("https://example.com")

    assert len(results) == 0


@pytest.mark.asyncio
async def test_run_timeout(gowitness: GowitnessPlugin) -> None:
    """Test run handles timeouts gracefully."""
    import asyncio

    with patch.object(gowitness, "_execute", side_effect=asyncio.TimeoutError):
        results = await gowitness.run("https://example.com")

    assert len(results) == 0
