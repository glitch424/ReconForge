"""Configuration schema and YAML loading.

All settings are Pydantic models loaded from YAML. Every value that
controls concurrency, timeouts, or retries lives here — nothing is
hardcoded in the plugins or scanner engine.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class LogSettings(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    dir: str = "logs"


class PluginSettings(BaseModel):
    """Global defaults for plugin execution."""

    timeout: int = 300
    retries: int = 2
    concurrency: int = 10


class ScannerSettings(BaseModel):
    """Scanner engine orchestration knobs."""

    http_concurrency: int = 20
    http_timeout: int = 15
    port_scan_timeout: int = 600
    tech_detect_timeout: int = 30
    stage_timeout: int = 900
    retry_delay: float = 1.0
    max_retries: int = 2


class Settings(BaseModel):
    """Root configuration object."""

    log: LogSettings = Field(default_factory=LogSettings)
    plugins: PluginSettings = Field(default_factory=PluginSettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)

    @classmethod
    def load(cls, config_path: str = "async_recon/config/default.yaml") -> "Settings":
        """Load settings from a YAML file."""
        path = Path(config_path)
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)
