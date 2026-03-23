"""Rich-based logger setup."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler


def setup_logger(log_level: str = "INFO", output_dir: str = "./output") -> logging.Logger:
    """Configure and return toolkit logger.

    Args:
        log_level: Console and file log level.
        output_dir: Directory where toolkit.log should be written.

    Returns:
        Configured root logger instance.
    """

    logger = logging.getLogger("osint_exposure_toolkit")
    logger.setLevel(log_level.upper())
    logger.handlers.clear()
    logger.propagate = False

    log_folder = Path(output_dir)
    log_folder.mkdir(parents=True, exist_ok=True)
    logfile = log_folder / "toolkit.log"

    console_handler = RichHandler(
        markup=True,
        rich_tracebacks=True,
        show_path=False,
    )
    console_handler.setLevel(log_level.upper())
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setLevel(log_level.upper())
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger
