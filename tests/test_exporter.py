"""Tests for the ReportExporter."""

import json
from datetime import datetime, timezone
from tempfile import TemporaryDirectory

from async_recon.modules.correlation.models import (
    AssetModel,
    AssetSubdomain,
    AssetHttpEndpoint,
)
from async_recon.reporting.exporter import ReportExporter


def _make_dummy_model() -> AssetModel:
    return AssetModel(
        target="example.com",
        generated_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        subdomains=[
            AssetSubdomain(
                subdomain="www.example.com",
                source="test",
                http_endpoints=[
                    AssetHttpEndpoint(
                        url="https://www.example.com",
                        port=443,
                        status_code=200,
                        title="Test Page",
                    )
                ],
            )
        ],
        total_subdomains=1,
        live_subdomains=1,
        total_open_ports=0,
        total_http_endpoints=1,
    )


def test_export_json() -> None:
    """Test exporting an AssetModel to JSON."""
    with TemporaryDirectory() as tmpdir:
        exporter = ReportExporter(output_dir=tmpdir)
        model = _make_dummy_model()

        path = exporter.export_json(model, "test_report.json")

        assert path.exists()
        assert path.name == "test_report.json"

        data = json.loads(path.read_text("utf-8"))
        assert data["target"] == "example.com"
        assert data["total_subdomains"] == 1
        assert data["subdomains"][0]["subdomain"] == "www.example.com"
        # Ensure datetimes are serialized as ISO strings
        assert "2025-01-01T12:00:00Z" in data["generated_at"]


def test_export_html() -> None:
    """Test rendering an AssetModel to HTML via Jinja2."""
    with TemporaryDirectory() as tmpdir:
        exporter = ReportExporter(output_dir=tmpdir)
        model = _make_dummy_model()

        path = exporter.export_html(model, "test_report.html")

        assert path.exists()
        assert path.name == "test_report.html"

        html = path.read_text("utf-8")
        assert "<html" in html
        assert "<title>ReconForge Report – example.com</title>" in html
        assert "www.example.com" in html
        assert "Test Page" in html


def test_timestamp_generation() -> None:
    """Test that default filenames use a timestamp."""
    with TemporaryDirectory() as tmpdir:
        exporter = ReportExporter(output_dir=tmpdir)
        model = _make_dummy_model()

        path = exporter.export_json(model)
        assert path.exists()
        assert path.name.startswith("example_com_")
        assert path.name.endswith(".json")
