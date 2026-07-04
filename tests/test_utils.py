import pytest
from pathlib import Path
from async_recon.utils.helpers import is_valid_domain, is_valid_ip, parse_targets


def test_is_valid_domain() -> None:
    assert is_valid_domain("example.com")
    assert is_valid_domain("sub.example.com")
    assert not is_valid_domain("invalid domain")
    assert not is_valid_domain("-invalid.com")


def test_is_valid_ip() -> None:
    assert is_valid_ip("192.168.1.1")
    assert is_valid_ip("8.8.8.8")
    assert not is_valid_ip("256.256.256.256")
    assert not is_valid_ip("192.168.1")


def test_parse_targets_string() -> None:
    targets = parse_targets(target="example.com")
    assert targets == ["example.com"]


def test_parse_targets_invalid_string() -> None:
    with pytest.raises(ValueError):
        parse_targets(target="invalid!")


def test_parse_targets_file(temp_targets_file: Path) -> None:
    targets = parse_targets(file_path=str(temp_targets_file))
    assert set(targets) == {"example.com", "192.168.1.1"}
