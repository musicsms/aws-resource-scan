"""Logging utilities for AWS Resource Scanner.

This module provides logging configuration with rich console output.
"""
import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

# Create console for rich output
console = Console()


def setup_logger(
    name: str = "aws_scanner", level: int = logging.INFO, log_file: Optional[str] = None
) -> logging.Logger:
    """Set up and configure logger with rich handler.

    Args:
        name: Logger name
        level: Logging level (default: logging.INFO)
        log_file: Optional file path to write logs to

    Returns:
        logging.Logger: Configured logger instance
    """
    # Configure rich handler
    rich_handler = RichHandler(
        rich_tracebacks=True,
        console=console,
        tracebacks_show_locals=False,
        show_time=True,
        markup=True,
    )

    # Basic configuration
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%Y-%m-%d %H:%M:%S]",
        handlers=[rich_handler],
    )

    # Get logger instance
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


# Create default logger
logger = setup_logger()


def log_exception(exception: Exception, context: Optional[str] = None) -> None:
    """Log an exception with context information.

    Args:
        exception: The exception to log
        context: Optional context information
    """
    if context:
        logger.error(f"Error in {context}: {str(exception)}")
    else:
        logger.error(f"Error: {str(exception)}")

    if isinstance(exception, Exception) and logger.level <= logging.DEBUG:
        logger.exception(exception)


def log_aws_error(
    error: Exception, service: str, action: str, resource_id: Optional[str] = None
) -> None:
    """Log an AWS-specific error with detailed context.

    Args:
        error: The AWS error/exception
        service: AWS service name (e.g., 'ec2', 's3')
        action: The action being performed (e.g., 'describe', 'list')
        resource_id: Optional resource identifier
    """
    resource_info = f" for resource '{resource_id}'" if resource_id else ""
    logger.error(f"AWS {service} error during {action}{resource_info}: {str(error)}")

    if logger.level <= logging.DEBUG:
        logger.exception(error) 