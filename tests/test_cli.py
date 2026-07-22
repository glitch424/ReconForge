"""CLI command tests.

Tests verify that the CLI layer correctly delegates to the orchestrator
and that error handling / exit codes work as expected.
"""

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from async_recon.cli.main import app

runner = CliRunner()


def test_scan_no_target() -> None:
    """scan with no target or file should exit with code 1."""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
    assert "You must provide a target or a file" in result.stdout


def test_scan_with_target() -> None:
    """scan with a valid target should delegate to the orchestrator."""
    with patch(
        "async_recon.scanner.orchestrator.run_scan",
        new_callable=AsyncMock,
    ) as mock_run:
        result = runner.invoke(app, ["scan", "example.com"])
        assert result.exit_code == 0
        mock_run.assert_awaited_once()


def test_scan_with_file_option() -> None:
    """scan with --file should delegate to the orchestrator."""
    with patch(
        "async_recon.scanner.orchestrator.run_scan",
        new_callable=AsyncMock,
    ) as mock_run:
        result = runner.invoke(app, ["scan", "--file", "targets.txt"])
        assert result.exit_code == 0
        mock_run.assert_awaited_once()


def test_report_command() -> None:
    """report command should delegate to generate_report."""
    with patch(
        "async_recon.scanner.orchestrator.generate_report",
        new_callable=AsyncMock,
    ) as mock_report:
        result = runner.invoke(app, ["report", "example.com"])
        assert result.exit_code == 0
        mock_report.assert_awaited_once()


def test_plugins_list_command() -> None:
    """plugins-list should display the plugin registry table."""
    result = runner.invoke(app, ["plugins-list"])
    assert result.exit_code == 0
    assert "subfinder" in result.stdout
    assert "naabu" in result.stdout
    assert "gowitness" in result.stdout


def test_config_show_command() -> None:
    """config-show should display configuration without errors."""
    result = runner.invoke(app, ["config-show"])
    assert result.exit_code == 0
    assert "http_concurrency" in result.stdout
