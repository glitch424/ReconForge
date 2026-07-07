"""Report exporter — consumes AssetModel, produces HTML and JSON reports.

Responsibilities:
  - Accept an AssetModel (produced by AssetCorrelator)
  - Export machine-readable JSON via Pydantic's model_dump
  - Export human-readable HTML via Jinja2 templates
  - Write output files to a caller-specified directory

This layer intentionally:
  - Has NO access to the database (DatabaseStore)
  - Has NO knowledge of plugins, the scanner engine, or network I/O
  - Contains NO business logic — it is a pure presentation layer
  - Delegates all template rendering to Jinja2 (prevents XSS via auto-escape)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

from async_recon.modules.correlation.models import AssetModel

logger = logging.getLogger(__name__)

# Path to the templates directory (sibling of this module)
_TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportExporter:
    """Generates HTML and JSON reports from an AssetModel.

    Args:
        output_dir: Directory where report files are written.
            Created if it does not exist.
        templates_dir: Override for the Jinja2 templates directory.
            Defaults to the bundled templates/ directory.
    """

    def __init__(
        self,
        output_dir: str = "reports",
        templates_dir: str | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self._templates_dir = Path(templates_dir) if templates_dir else _TEMPLATES_DIR

        self._jinja_env = Environment(
            loader=FileSystemLoader(str(self._templates_dir)),
            autoescape=select_autoescape(["html", "htm"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def export_json(self, model: AssetModel, filename: str | None = None) -> Path:
        """Serialize the AssetModel to a JSON file.

        Args:
            model: The correlated asset model to export.
            filename: Optional filename override. Defaults to
                '<target>_<timestamp>.json'.

        Returns:
            The absolute path of the written JSON file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            ts = self._timestamp()
            safe_target = model.target.replace(".", "_")
            filename = f"{safe_target}_{ts}.json"

        output_path = self.output_dir / filename

        # model_dump(mode="json") ensures datetime fields are serialised as
        # ISO-8601 strings — no custom JSON encoder needed.
        payload: Dict[str, Any] = model.model_dump(mode="json")
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        logger.info(f"JSON report written to: {output_path}")
        return output_path

    def export_html(self, model: AssetModel, filename: str | None = None) -> Path:
        """Render the AssetModel to an HTML report using Jinja2.

        Args:
            model: The correlated asset model to export.
            filename: Optional filename override. Defaults to
                '<target>_<timestamp>.html'.

        Returns:
            The absolute path of the written HTML file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            ts = self._timestamp()
            safe_target = model.target.replace(".", "_")
            filename = f"{safe_target}_{ts}.html"

        output_path = self.output_dir / filename

        template = self._jinja_env.get_template("report.html")
        html = template.render(
            model=model,
            generated_at=model.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

        output_path.write_text(html, encoding="utf-8")

        logger.info(f"HTML report written to: {output_path}")
        return output_path

    @staticmethod
    def _timestamp() -> str:
        """Return a compact UTC timestamp string for use in filenames."""
        return datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
