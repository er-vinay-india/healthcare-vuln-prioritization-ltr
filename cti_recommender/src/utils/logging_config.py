"""
Structured Logging Configuration for CTI Recommender
Supports both human-readable and JSON logging with rotation
"""
import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional

try:
    from pythonjsonlogger import jsonlogger
    JSON_LOGGER_AVAILABLE = True
except ImportError:
    JSON_LOGGER_AVAILABLE = False

from config import settings


def setup_logging(
    name: str,
    level: Optional[str] = None,
    structured: Optional[bool] = None,
    console: bool = True,
    file: bool = True
) -> logging.Logger:
    """
    Configure structured logging with console and file handlers
    
    Args:
        name: Logger name (typically __name__ of the module)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
               Defaults to settings.LOG_LEVEL
        structured: Enable JSON formatted logs. Defaults to settings.STRUCTURED_LOGGING
        console: Enable console output (stdout)
        file: Enable file output with rotation
        
    Returns:
        Configured logger instance
        
    Example:
        >>> logger = setup_logging(__name__)
        >>> logger.info("Application started", extra={"version": "1.0.0"})
    """
    logger = logging.getLogger(name)
    
    # Use settings defaults if not specified
    log_level = level or settings.LOG_LEVEL
    use_structured = structured if structured is not None else settings.STRUCTURED_LOGGING
    
    logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Determine formatter
    if use_structured and JSON_LOGGER_AVAILABLE:
        formatter = jsonlogger.JsonFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s %(pathname)s %(lineno)d',
            rename_fields={
                'levelname': 'level',
                'asctime': 'timestamp',
                'pathname': 'file',
                'lineno': 'line'
            },
            datefmt=settings.LOG_DATE_FORMAT
        )
    else:
        formatter = logging.Formatter(
            settings.LOG_FORMAT,
            datefmt=settings.LOG_DATE_FORMAT
        )
    
    # Console handler (stdout)
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler with rotation
    if file:
        log_dir = settings.get_log_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"{name.replace('.', '_')}.log"
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=settings.LOG_MAX_BYTES,
            backupCount=settings.LOG_BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get or create a logger with default configuration
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
        
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing CVE", extra={"cve_id": "CVE-2024-1234"})
    """
    logger = logging.getLogger(name)
    
    # Only configure if not already configured
    if not logger.handlers:
        setup_logging(name)
    
    return logger


class LoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter for adding contextual information to all log messages
    
    Example:
        >>> adapter = LoggerAdapter(logger, {"request_id": "abc-123"})
        >>> adapter.info("User logged in", extra={"user_id": 42})
        # Logs: {..., "request_id": "abc-123", "user_id": 42}
    """
    
    def process(self, msg, kwargs):
        """Add extra context to log messages"""
        if 'extra' in kwargs:
            kwargs['extra'].update(self.extra)
        else:
            kwargs['extra'] = self.extra
        return msg, kwargs


def configure_root_logger():
    """
    Configure the root logger with default settings
    Called automatically on module import
    """
    root = logging.getLogger()
    root.setLevel(settings.LOG_LEVEL)
    
    # Only add handler if none exist
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                settings.LOG_FORMAT,
                datefmt=settings.LOG_DATE_FORMAT
            )
        )
        root.addHandler(handler)


# Configure root logger on import
configure_root_logger()


# Logging utilities
def log_exception(logger: logging.Logger, exc: Exception, context: dict = None):
    """
    Log exception with context information
    
    Args:
        logger: Logger instance
        exc: Exception to log
        context: Additional context dictionary
        
    Example:
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     log_exception(logger, e, {"cve_id": "CVE-2024-1234"})
    """
    extra = context or {}
    extra.update({
        'exception_type': type(exc).__name__,
        'exception_message': str(exc)
    })
    logger.error(f"Exception occurred: {exc}", extra=extra, exc_info=True)


def log_performance(logger: logging.Logger, operation: str, duration: float, context: dict = None):
    """
    Log performance metrics
    
    Args:
        logger: Logger instance
        operation: Operation name
        duration: Duration in seconds
        context: Additional context
        
    Example:
        >>> import time
        >>> start = time.time()
        >>> process_cves()
        >>> log_performance(logger, "process_cves", time.time() - start, {"count": 1000})
    """
    extra = context or {}
    extra.update({
        'operation': operation,
        'duration_seconds': round(duration, 3),
        'duration_ms': round(duration * 1000, 1)
    })
    logger.info(f"Performance: {operation} completed in {duration:.3f}s", extra=extra)
