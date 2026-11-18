"""Server log helpers."""

import logging
import logging.handlers
import os


def configure(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("sft.server")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger

    handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "server.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"
    ))
    logger.addHandler(handler)
    logger.propagate = False
    return logger