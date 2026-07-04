import pytest
from pathlib import Path


@pytest.fixture
def temp_targets_file(tmp_path: Path) -> Path:
    p = tmp_path / "targets.txt"
    p.write_text("example.com\n192.168.1.1\ninvalid-domain!\n")
    return p
