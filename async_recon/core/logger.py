import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler


def setup_logger(
    name: str = "recon", log_dir: str = "logs", debug: bool = False
) -> logging.Logger:
    """Setup a structured logger with console and file output."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Prevent adding multiple handlers if setup is called multiple times
    if logger.handlers:
        return logger

    # Console handler using Rich
    console_handler = RichHandler(rich_tracebacks=True, markup=True)
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    console_format = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # File handler
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        log_path / f"{name}.log", maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)

    return logger
