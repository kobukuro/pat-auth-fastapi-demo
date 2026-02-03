"""
Application logging configuration.

This module provides unified logging configuration for the PAT Auth API.
It sets up structured logging that captures detailed error information
for debugging while returning safe, user-friendly messages to clients.
"""
import logging
import sys


def setup_logging() -> logging.Logger:
    """
    Configure and return the application logger.

    The logger outputs to stdout with a structured format including:
    - Timestamp
    - Logger name
    - Log level
    - Message

    This configuration is suitable for both development and production
    environments when running with uvicorn/gunicorn.

    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger("pat_auth")
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if called multiple times
    if not logger.handlers:
        # Console handler with detailed format for development/debugging
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)

        # Structured log format
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
