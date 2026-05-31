# logger.py - Centralized Logging System
import logging
import logging.handlers
import sys
from pathlib import Path
from config import get_config

class LoggerManager:
    """Manages application logging"""
    
    _instance = None
    _logger = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LoggerManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._setup_logger()
    
    def _setup_logger(self):
        """Initialize logger with config"""
        config = get_config()
        log_config = config.logging
        
        # Create logger
        self._logger = logging.getLogger('OSINT-Scanner')
        self._logger.setLevel(getattr(logging, log_config.level))
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        simple_formatter = logging.Formatter(
            '[%(levelname)s] %(message)s'
        )
        
        # Remove existing handlers
        self._logger.handlers = []
        
        # File handler
        if log_config.enable_file_logging:
            Path(log_config.log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_config.log_file,
                maxBytes=log_config.max_log_file_size,
                backupCount=log_config.backup_count
            )
            file_handler.setLevel(getattr(logging, log_config.level))
            file_handler.setFormatter(detailed_formatter)
            self._logger.addHandler(file_handler)
        
        # Console handler
        if log_config.enable_console_logging:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, log_config.level))
            console_handler.setFormatter(simple_formatter)
            self._logger.addHandler(console_handler)
    
    @staticmethod
    def get_logger():
        """Get logger instance"""
        manager = LoggerManager()
        return manager._logger

def get_logger():
    """Convenience function to get logger"""
    return LoggerManager.get_logger()

# Module-level logger
logger = get_logger()
