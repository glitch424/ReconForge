"""End-to-end scan orchestrator.

Chains every recon stage in the correct order:

    Target Validation → Passive Recon → DNS Resolution → Port Scanning →
    HTTP Probing → Technology Detection → Screenshot Capture →
    Database Persistence → Asset Correlation → Report Generation

The CLI invokes ``run_scan()`` and nothing else.  All business logic
lives here or in the components this module delegates to.  The
orchestrator itself contains no probing, detection, or parsing code.
"""

import logging
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel

from async_recon.config.settings import Settings
from async_recon.database.store import DatabaseStore
from async_recon.modules.active.gowitness import GowitnessPlugin
from async_recon.modules.active.http_prober import HttpProber
from async_recon.modules.active.naabu import NaabuPlugin
from async_recon.modules.active.tech_detect import TechDetector
from async_recon.modules.correlation.correlator import AssetCorrelator
from async_recon.plugins.manager import PluginManager
from async_recon.reporting.exporter import ReportExporter
from async_recon.scanner.dns_resolver import DNSResolver
from async_recon.scanner.engine import ScannerEngine
from async_recon.utils.helpers import parse_targets

logger = logging.getLogger(__name__)
console = Console()


async def run_scan(
    target: str | None = None,
    file: str | None = None,
    settings: Settings | None = None,
    output_dir: str = "reports",
    db_path: str = "recon.db",
) -> None:
    """Execute the complete reconnaissance pipeline.

    Args:
        target: A single domain or IP to scan.
        file: Path to a newline-delimited file of targets.
        settings: Loaded Settings object; uses defaults if None.
        output_dir: Directory for JSON/HTML reports.
        db_path: SQLite database path.

    Raises:
        SystemExit: On fatal errors (no targets, DB failure).
    """
    settings = settings or Settings()

    # ── 1. Target validation ────────────────────────────────────────
    try:
        targets = parse_targets(target=target, file_path=file)
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1) from exc

    if not targets:
        console.print("[bold red]Error:[/bold red] No valid targets provided.")
        raise SystemExit(1)

    console.print(
        Panel(
            f"[bold cyan]ReconForge[/bold cyan] — scanning "
            f"[bold]{len(targets)}[/bold] target(s)",
            subtitle="v1.0.0",
        )
    )

    # ── 2. Database setup ───────────────────────────────────────────
    db = DatabaseStore(db_path=db_path)
    try:
        await db.connect()
        await db.init_schema()
    except Exception as exc:
        console.print(f"[bold red]Database error:[/bold red] {exc}")
        raise SystemExit(1) from exc

    try:
        engine = ScannerEngine(settings=settings.scanner, db=db)

        for scan_target in targets:
            await _scan_single_target(
                scan_target,
                engine=engine,
                db=db,
                settings=settings,
                output_dir=output_dir,
            )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
        console.print("[dim]Partial results have been saved to the database.[/dim]")
    finally:
        await db.disconnect()


async def _scan_single_target(
    target: str,
    *,
    engine: ScannerEngine,
    db: DatabaseStore,
    settings: Settings,
    output_dir: str,
) -> None:
    """Run the full pipeline for one target domain/IP."""
    console.print(f"\n[bold green]▶ Target:[/bold green] {target}")

    # ── 3. Passive recon (subdomain enumeration) ────────────────────
    console.print("[dim]  Stage 1/7: Passive subdomain enumeration...[/dim]")
    pm = PluginManager()
    await pm.initialize_plugins()

    subdomain_results: List[Dict[str, Any]] = []
    if pm.active_plugins:
        subdomain_results = await pm.run_passive_plugins(target)
        console.print(
            f"  [green]✓[/green] Discovered "
            f"[bold]{len(subdomain_results)}[/bold] subdomains"
        )
    else:
        console.print(
            "  [yellow]⚠[/yellow] No passive plugins available — "
            "using target domain only"
        )
        subdomain_results = [
            {"target": target, "subdomain": target, "source": "user_input"}
        ]

    await pm.cleanup_plugins()

    # Persist subdomains and build ID map
    subdomain_id_map: Dict[str, int] = {}
    for r in subdomain_results:
        sub = r.get("subdomain", "")
        if sub:
            sub_id = await db.add_subdomain(
                target=target, subdomain=sub, source=r.get("source", "unknown")
            )
            subdomain_id_map[sub] = sub_id

    if not subdomain_id_map:
        console.print(
            "  [yellow]⚠[/yellow] No subdomains found — skipping active stages"
        )
        return

    all_subdomains = list(subdomain_id_map.keys())

    # ── 4. DNS resolution ───────────────────────────────────────────
    console.print("[dim]  Stage 2/7: DNS resolution...[/dim]")
    resolver = DNSResolver()
    resolved_count = 0
    for sub in all_subdomains:
        try:
            dns_results = await resolver.resolve_all(sub)
            has_records = False
            for rtype, values in dns_results.items():
                for val in values:
                    sub_id = subdomain_id_map[sub]
                    await db.add_dns_record(sub_id, rtype, val)
                    has_records = True
            if has_records:
                await db.mark_resolved(subdomain_id_map[sub])
                resolved_count += 1
        except Exception as exc:
            logger.warning(f"DNS resolution failed for {sub}: {exc}")

    console.print(
        f"  [green]✓[/green] Resolved "
        f"[bold]{resolved_count}[/bold]/{len(all_subdomains)} subdomains"
    )

    # ── 5. Port scanning ────────────────────────────────────────────
    console.print("[dim]  Stage 3/7: Port scanning...[/dim]")
    try:
        naabu = NaabuPlugin(timeout=settings.scanner.port_scan_timeout)
        await naabu.initialize()
        port_results = await engine.run_stage_safe(
            "Port Scanning",
            naabu,
            all_subdomains,
            timeout=settings.scanner.port_scan_timeout,
        )
        await engine.store_port_results(port_results, subdomain_id_map)
        console.print(
            f"  [green]✓[/green] Found " f"[bold]{len(port_results)}[/bold] open ports"
        )
    except FileNotFoundError:
        port_results = []
        console.print("  [yellow]⚠[/yellow] naabu not found — port scanning skipped")
    except Exception as exc:
        port_results = []
        logger.error(f"Port scanning stage failed: {exc}")
        console.print("  [yellow]⚠[/yellow] Port scanning failed — continuing")

    # ── 6. HTTP probing ─────────────────────────────────────────────
    console.print("[dim]  Stage 4/7: HTTP probing...[/dim]")
    http_prober = HttpProber(timeout=settings.scanner.http_timeout)
    await http_prober.initialize()

    # Build URL list: probe both http and https for each subdomain
    url_targets: List[str] = []
    url_to_subdomain: Dict[str, str] = {}
    for sub in all_subdomains:
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            url_targets.append(url)
            url_to_subdomain[url] = sub

    http_results = await engine.run_stage_safe(
        "HTTP Probing",
        http_prober,
        url_targets,
    )
    await engine.store_http_results(http_results, subdomain_id_map, url_to_subdomain)
    console.print(
        f"  [green]✓[/green] Probed " f"[bold]{len(http_results)}[/bold] HTTP endpoints"
    )

    # ── 7. Technology detection ──────────────────────────────────────
    console.print("[dim]  Stage 5/7: Technology detection...[/dim]")
    tech_detector = TechDetector(timeout=settings.scanner.tech_detect_timeout)
    await tech_detector.initialize()

    # Only probe URLs that returned a valid HTTP response
    live_urls = [r["url"] for r in http_results if r.get("status_code", 0) > 0]
    tech_results = await engine.run_stage_safe(
        "Technology Detection",
        tech_detector,
        live_urls,
        timeout=settings.scanner.stage_timeout,
    )
    await engine.store_tech_results(tech_results, subdomain_id_map, url_to_subdomain)
    console.print(
        f"  [green]✓[/green] Detected " f"[bold]{len(tech_results)}[/bold] technologies"
    )

    # ── 8. Screenshot capture ────────────────────────────────────────
    console.print("[dim]  Stage 6/7: Screenshot capture...[/dim]")
    try:
        gowitness = GowitnessPlugin(
            output_dir="screenshots", timeout=settings.scanner.http_timeout
        )
        await gowitness.initialize()
        screenshot_results = await engine.run_stage_safe(
            "Screenshots",
            gowitness,
            live_urls,
        )
        # Persist screenshot metadata
        for sr in screenshot_results:
            url = sr.get("url", "")
            sub = url_to_subdomain.get(url, "")
            match_sub_id = subdomain_id_map.get(sub)
            if match_sub_id is not None:
                await db.add_screenshot(
                    subdomain_id=match_sub_id,
                    url=url,
                    file_path=sr.get("file_path", ""),
                )
        console.print(
            f"  [green]✓[/green] Captured "
            f"[bold]{len(screenshot_results)}[/bold] screenshots"
        )
    except FileNotFoundError:
        console.print("  [yellow]⚠[/yellow] gowitness not found — screenshots skipped")
    except Exception as exc:
        logger.error(f"Screenshot stage failed: {exc}")
        console.print("  [yellow]⚠[/yellow] Screenshot capture failed — continuing")

    # ── 9. Correlation + Reporting ───────────────────────────────────
    console.print("[dim]  Stage 7/7: Correlation & report generation...[/dim]")
    try:
        correlator = AssetCorrelator(db=db)
        model = await correlator.correlate(target)

        exporter = ReportExporter(output_dir=output_dir)
        json_path = exporter.export_json(model)
        html_path = exporter.export_html(model)

        console.print(
            f"  [green]✓[/green] JSON report: [link=file://{json_path}]{json_path}[/link]"
        )
        console.print(
            f"  [green]✓[/green] HTML report: [link=file://{html_path}]{html_path}[/link]"
        )
    except Exception as exc:
        logger.error(f"Report generation failed: {exc}")
        console.print(
            "  [red]✗[/red] Report generation failed — "
            "data is preserved in the database"
        )

    # ── Summary ──────────────────────────────────────────────────────
    console.print(
        Panel(
            f"[bold green]Scan complete for {target}[/bold green]\n"
            f"  Subdomains: {len(subdomain_id_map)}  |  "
            f"DNS resolved: {resolved_count}  |  "
            f"Open ports: {len(port_results)}  |  "
            f"HTTP endpoints: {len(http_results)}  |  "
            f"Technologies: {len(tech_results)}",
            title="Summary",
        )
    )


async def generate_report(
    target: str,
    output_dir: str = "reports",
    db_path: str = "recon.db",
) -> None:
    """Generate reports from existing scan data for a target.

    Args:
        target: The target domain to generate reports for.
        output_dir: Output directory for report files.
        db_path: Path to the SQLite database with scan data.
    """
    db = DatabaseStore(db_path=db_path)
    try:
        await db.connect()
        await db.init_schema()

        # Verify the target has data
        subdomains = await db.get_all_subdomains(target)
        if not subdomains:
            console.print(
                f"[bold red]Error:[/bold red] No scan data found for "
                f"target '{target}'. Run a scan first."
            )
            raise SystemExit(1)

        correlator = AssetCorrelator(db=db)
        model = await correlator.correlate(target)

        exporter = ReportExporter(output_dir=output_dir)
        json_path = exporter.export_json(model)
        html_path = exporter.export_html(model)

        console.print(f"[green]✓[/green] JSON report: {json_path}")
        console.print(f"[green]✓[/green] HTML report: {html_path}")
    finally:
        await db.disconnect()
