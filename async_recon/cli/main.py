"""ReconForge CLI — entry point for all user-facing commands.

Commands:
    recon scan <target>       Run a full reconnaissance scan
    recon scan -f targets.txt Scan multiple targets from a file
    recon report <target>     Generate reports from existing scan data
    recon plugins-list        Show available plugins and their status
    recon config-show         Display current configuration

The CLI delegates all business logic to the orchestrator and other
existing components.  It never touches plugins, the database, or the
reporter directly.
"""

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from async_recon.config.settings import Settings
from async_recon.core.logger import setup_logger

app = typer.Typer(
    name="recon",
    help="ReconForge — A modular, asynchronous reconnaissance framework.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: Optional[str] = typer.Argument(
        None, help="Target domain or IP address to scan"
    ),
    file: Optional[str] = typer.Option(
        None, "--file", "-f", help="Path to a file containing targets (one per line)"
    ),
    config_file: str = typer.Option(
        "async_recon/config/default.yaml",
        "--config",
        "-c",
        help="Path to YAML configuration file",
    ),
    output_dir: str = typer.Option(
        "reports", "--output", "-o", help="Output directory for reports"
    ),
    db_path: str = typer.Option(
        "recon.db", "--db", help="Path to SQLite database file"
    ),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging"),
) -> None:
    """Run a full reconnaissance scan against a target or list of targets."""
    setup_logger(debug=debug)

    if not target and not file:
        console.print(
            "[bold red]Error:[/bold red] You must provide a target or "
            "a file with targets (--file / -f)."
        )
        raise typer.Exit(code=1)

    settings = Settings.load(config_path=config_file)

    from async_recon.scanner.orchestrator import run_scan as _run_scan

    try:
        asyncio.run(
            _run_scan(
                target=target,
                file=file,
                settings=settings,
                output_dir=output_dir,
                db_path=db_path,
            )
        )
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, (int, str)) and str(exc.code).isdigit() else 1
        raise typer.Exit(code=code)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted.[/bold yellow]")
        raise typer.Exit(code=130)


@app.command()
def report(
    target: str = typer.Argument(..., help="Target domain to generate reports for"),
    output_dir: str = typer.Option(
        "reports", "--output", "-o", help="Output directory for reports"
    ),
    db_path: str = typer.Option(
        "recon.db", "--db", help="Path to SQLite database file"
    ),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging"),
) -> None:
    """Generate HTML and JSON reports from existing scan data."""
    setup_logger(debug=debug)

    from async_recon.scanner.orchestrator import generate_report

    try:
        asyncio.run(
            generate_report(
                target=target,
                output_dir=output_dir,
                db_path=db_path,
            )
        )
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, (int, str)) and str(exc.code).isdigit() else 1
        raise typer.Exit(code=code)


@app.command(name="plugins-list")
def plugins_list(
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging"),
) -> None:
    """List all available plugins and their availability status."""
    setup_logger(debug=debug)

    from async_recon.plugins.registry import PLUGIN_REGISTRY

    table = Table(
        title="ReconForge Plugins",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Plugin", style="bold")
    table.add_column("Type")
    table.add_column("Binary Required")
    table.add_column("Description")

    for entry in PLUGIN_REGISTRY:
        table.add_row(
            entry["name"],
            entry["type"],
            entry.get("binary", "—"),
            entry["description"],
        )

    console.print(table)


@app.command(name="config-show")
def config_show(
    config_file: str = typer.Option(
        "async_recon/config/default.yaml",
        "--config",
        "-c",
        help="Path to YAML configuration file",
    ),
) -> None:
    """Display the current configuration."""
    settings = Settings.load(config_path=config_file)
    data = settings.model_dump()

    table = Table(
        title="ReconForge Configuration",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Section", style="bold")
    table.add_column("Setting")
    table.add_column("Value", style="green")

    for section, values in data.items():
        if isinstance(values, dict):
            for key, val in values.items():
                table.add_row(section, key, str(val))
        else:
            table.add_row("", section, str(values))

    console.print(table)


def main() -> None:
    """Entry point for the ``recon`` console script."""
    app()


if __name__ == "__main__":
    main()
