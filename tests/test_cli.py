from typer.testing import CliRunner
from async_recon.cli.main import app

runner = CliRunner()


def test_scan_no_target() -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
    assert "You must provide a target or a file" in result.stdout


def test_scan_with_target() -> None:
    result = runner.invoke(app, ["scan", "example.com"])
    assert result.exit_code == 0
    assert "Scan finished (stub)" in result.stdout


def test_report_command() -> None:
    result = runner.invoke(app, ["report", "latest"])
    assert result.exit_code == 0
    assert "Generating report for: latest" in result.stdout


def test_plugins_list_command() -> None:
    result = runner.invoke(app, ["plugins-list"])
    assert result.exit_code == 0
    assert "Available plugins" in result.stdout


def test_config_show_command() -> None:
    result = runner.invoke(app, ["config-show"])
    assert result.exit_code == 0
