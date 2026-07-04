import re
from pathlib import Path
from typing import List

# Simple regex for domain and IP validation
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def is_valid_domain(target: str) -> bool:
    """Check if the target is a valid domain name."""
    return bool(DOMAIN_REGEX.match(target))


def is_valid_ip(target: str) -> bool:
    """Check if the target is a valid IPv4 address."""
    return bool(IP_REGEX.match(target))


def parse_targets(target: str | None = None, file_path: str | None = None) -> List[str]:
    """Parse targets from a single string or a file."""
    targets: set[str] = set()
    if target:
        if is_valid_domain(target) or is_valid_ip(target):
            targets.add(target)
        else:
            raise ValueError(f"Invalid target: {target}")

    if file_path:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                t = line.strip()
                if t and (is_valid_domain(t) or is_valid_ip(t)):
                    targets.add(t)

    return list(targets)
