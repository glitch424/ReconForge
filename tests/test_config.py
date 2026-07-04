import yaml
from pathlib import Path
from async_recon.config.settings import Settings


def test_settings_default() -> None:
    settings = Settings()
    assert settings.log.level == "INFO"
    assert settings.plugins.timeout == 300


def test_settings_load(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_data = {"log": {"level": "DEBUG"}, "plugins": {"timeout": 100}}
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)

    settings = Settings.load(str(config_file))
    assert settings.log.level == "DEBUG"
    assert settings.plugins.timeout == 100


def test_settings_load_non_existent() -> None:
    settings = Settings.load("non_existent_file.yaml")
    assert settings.log.level == "INFO"
