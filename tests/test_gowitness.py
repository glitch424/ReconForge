"""Tests for the Gowitness plugin."""

from collections.abc import Generator
from pathlib import Path
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
def gowitness(tmp_path: Path) -> GowitnessPlugin:
    return GowitnessPlugin(output_dir=str(tmp_path / "screenshots"), timeout=5)


@pytest.mark.asyncio
async def test_initialize(
    mock_subprocess: MagicMock, gowitness: GowitnessPlugin
) -> None:
    """Test that initialize checks for the gowitness binary."""
    await gowitness.initialize()
    mock_subprocess.assert_called_with(
        "gowitness", "version", stdout=-1, stderr=-1
    )


@pytest.mark.asyncio
async def test_initialize_missing_binary(gowitness: GowitnessPlugin) -> None:
    """Test that initialize raises when gowitness is not found."""
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError):
            await gowitness.initialize()


@pytest.mark.asyncio
async def test_execute_success(
    mock_subprocess: MagicMock, gowitness: GowitnessPlugin, tmp_path: Path
) -> None:
    """Test _execute runs the correct command and detects the new screenshot."""
    url = "https://example.com"
    output_dir = tmp_path / "screenshots"

    # We want the mocked process.communicate() to simulate creating a screenshot file
    async def side_effect_communicate(*args: Any, **kwargs: Any) -> tuple[bytes, bytes]:
        output_dir.mkdir(parents=True, exist_ok=True)
        # Simulate gowitness creating a screenshot
        (output_dir / "example_com.png").touch()
        return (b"", b"")

    mock_subprocess.return_value.communicate.side_effect = side_effect_communicate

    path = await gowitness._execute(url)

    mock_subprocess.assert_called_once_with(
        "gowitness",
        "scan",
        "single",
        "-u",
        url,
        "--screenshot-path",
        str(output_dir),
        "--screenshot-format",
        "png",
        "--write-none",
        stdout=-1,
        stderr=-1,
    )

    assert path == str((output_dir / "example_com.png").resolve())


@pytest.mark.asyncio
async def test_execute_no_file_created(
    mock_subprocess: MagicMock, gowitness: GowitnessPlugin, tmp_path: Path
) -> None:
    """Test _execute returns empty string if no file is created."""
    url = "https://example.com"
    path = await gowitness._execute(url)
    assert path == ""


@pytest.mark.asyncio
async def test_execute_subprocess_failure(
    mock_subprocess: MagicMock, gowitness: GowitnessPlugin, tmp_path: Path
) -> None:
    """Test _execute handles non-zero exit codes."""
    url = "https://example.com"
    mock_subprocess.return_value.returncode = 1
    mock_subprocess.return_value.communicate.return_value = (b"", b"error")

    path = await gowitness._execute(url)
    assert path == ""


@pytest.mark.asyncio
async def test_run_success(gowitness: GowitnessPlugin, tmp_path: Path) -> None:
    """Test successful run returns a valid result dict."""
    # Mock _execute to return a valid file path
    dummy_file = tmp_path / "dummy.png"
    dummy_file.touch()

    with patch.object(gowitness, "_execute", return_value=str(dummy_file)) as mock_exec:
        results = await gowitness.run("https://example.com")

    mock_exec.assert_called_once_with("https://example.com")
    assert len(results) == 1
    assert results[0]["url"] == "https://example.com"
    assert results[0]["file_path"] == str(dummy_file)
    assert results[0]["source"] == "gowitness"


@pytest.mark.asyncio
async def test_run_no_file(gowitness: GowitnessPlugin) -> None:
    """Test run returns empty list when file is not created or doesn't exist."""
    # _execute returns empty string when no file found
    with patch.object(gowitness, "_execute", return_value=""):
        results = await gowitness.run("https://example.com")

    assert len(results) == 0


@pytest.mark.asyncio
async def test_run_timeout(gowitness: GowitnessPlugin) -> None:
    """Test run handles timeouts gracefully."""
    import asyncio

    with patch.object(gowitness, "_execute", side_effect=asyncio.TimeoutError):
        results = await gowitness.run("https://example.com")

    assert len(results) == 0
