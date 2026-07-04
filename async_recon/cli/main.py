import typer
from rich.console import Console

from async_recon.core.logger import setup_logger
from async_recon.config.settings import Settings

app = typer.Typer(help="ReconForge: Async Recon Framework")
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(None, help="Target domain or IP to scan"),
    file: str = typer.Option(
        None, "--file", "-f", help="Path to file containing targets"
    ),
    config_file: str = typer.Option(
        "async_recon/config/default.yaml", "--config", "-c", help="Path to config file"
    ),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging"),
) -> None:
    """Run a recon scan against a target or list of targets."""
    logger = setup_logger(debug=debug)
    logger.info("Starting ReconForge scan...")

    settings = Settings.load(config_path=config_file)
    if debug:
        logger.debug(f"Loaded config: {settings.model_dump()}")

    if not target and not file:
        logger.error("You must provide a target or a file with targets.")
        raise typer.Exit(code=1)

    # In milestone 1 we just stub the logic.
    logger.info(f"Target: {target}, File: {file}")
    console.print("[bold green]Scan finished (stub).[/bold green]")


@app.command()
def report(
    id: str = typer.Argument(
        ..., help="ID of the scan or 'latest' to generate report for"
    ),
) -> None:
    """Generate a report for a scan."""
    console.print(f"[bold blue]Generating report for: {id} (stub)[/bold blue]")


@app.command()
def plugins_list() -> None:
    """List available plugins."""
    console.print("[bold magenta]Available plugins (stub):[/bold magenta]")
    console.print("- subfinder")
    console.print("- assetfinder")


@app.command()
def config_show() -> None:
    """Show current configuration."""
    settings = Settings.load()
    console.print(settings.model_dump())


if __name__ == "__main__":
    app()
