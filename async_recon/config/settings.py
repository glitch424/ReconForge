from pathlib import Path
from pydantic import BaseModel, Field
import yaml


class LogSettings(BaseModel):
    level: str = "INFO"
    dir: str = "logs"


class PluginSettings(BaseModel):
    timeout: int = 300
    retries: int = 2
    concurrency: int = 10


class ScannerSettings(BaseModel):
    pass


class Settings(BaseModel):
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
