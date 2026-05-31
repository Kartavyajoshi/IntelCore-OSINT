# api_utils.py - API Rate Limiting, Retries, and Error Handling
import requests
import time
from functools import wraps
from typing import Callable, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import threading
from config import get_config
from logger import get_logger

logger = get_logger()

class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, requests_per_second: float = 5.0):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if needed to respect rate limit"""
        with self.lock:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                logger.debug(f"[RATE LIMIT] Waiting {sleep_time:.2f}s")
                time.sleep(sleep_time)
            self.last_request_time = time.time()

class APIErrorHandler:
    """Handles API errors with exponential backoff"""
    
    # Retry strategy for different HTTP codes
    RETRYABLE_STATUS_CODES = {
        408,  # Request Timeout
        429,  # Too Many Requests
        500,  # Internal Server Error
        502,  # Bad Gateway
        503,  # Service Unavailable
        504   # Gateway Timeout
    }
    
    @staticmethod
    def is_retryable_error(status_code: int) -> bool:
        """Check if error is retryable"""
        return status_code in APIErrorHandler.RETRYABLE_STATUS_CODES
    
    @staticmethod
    def get_backoff_time(attempt: int, base_delay: float = 2.0) -> float:
        """Calculate exponential backoff with jitter"""
        import random
        delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
        return min(delay, 60)  # Cap at 60 seconds

def retry_with_backoff(max_attempts: int = 3, base_delay: float = 2.0):
    """Decorator for retrying API calls with exponential backoff"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    logger.debug(f"[API CALL] {func.__name__} (attempt {attempt + 1}/{max_attempts})")
                    result = func(*args, **kwargs)
                    
                    # Check if result is a response object with status_code
                    if hasattr(result, 'status_code'):
                        if result.status_code == 200 or result.status_code == 201:
                            return result
                        elif APIErrorHandler.is_retryable_error(result.status_code):
                            if attempt < max_attempts - 1:
                                backoff = APIErrorHandler.get_backoff_time(attempt, base_delay)
                                logger.warning(
                                    f"[RETRY] Status {result.status_code}, waiting {backoff:.1f}s"
                                )
                                time.sleep(backoff)
                                continue
                            last_exception = f"HTTP {result.status_code}"
                        else:
                            return result
                    else:
                        return result
                
                except requests.Timeout as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        backoff = APIErrorHandler.get_backoff_time(attempt, base_delay)
                        logger.warning(f"[TIMEOUT] Retrying in {backoff:.1f}s")
                        time.sleep(backoff)
                    else:
                        logger.error(f"[TIMEOUT] Max retries exceeded")
                
                except requests.ConnectionError as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        backoff = APIErrorHandler.get_backoff_time(attempt, base_delay)
                        logger.warning(f"[CONNECTION ERROR] Retrying in {backoff:.1f}s")
                        time.sleep(backoff)
                    else:
                        logger.error(f"[CONNECTION ERROR] Max retries exceeded")
                
                except Exception as e:
                    logger.error(f"[ERROR] {func.__name__}: {e}")
                    raise
            
            logger.error(f"[FAILED] {func.__name__} after {max_attempts} attempts")
            raise Exception(f"{func.__name__} failed after {max_attempts} attempts: {last_exception}")
        
        return wrapper
    return decorator

class APISession:
    """Enhanced requests session with retry, rate limiting, and timeout"""
    
    def __init__(self, rate_limit: float = 5.0, timeout: int = 30):
        self.session = requests.Session()
        self.rate_limiter = RateLimiter(rate_limit)
        self.timeout = timeout
        self.config = get_config()
        self._setup_session()
    
    def _setup_session(self):
        """Setup session with retry strategy"""
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=self.config.api.retry_attempts,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update({
            'User-Agent': 'OSINT-Scanner/1.0 (Security Research)'
        })
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request with rate limiting and timeout"""
        self.rate_limiter.wait()
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request with rate limiting and timeout"""
        self.rate_limiter.wait()
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        return self.session.post(url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """HEAD request with rate limiting and timeout"""
        self.rate_limiter.wait()
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        return self.session.head(url, **kwargs)
    
    def close(self):
        """Close session"""
        self.session.close()

class ValidationUtils:
    """Input validation utilities"""
    
    @staticmethod
    def validate_domain(domain: str) -> Tuple[bool, str]:
        """Validate domain or IP format"""
        import re
        import ipaddress
        
        domain = domain.strip().lower()
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Check if it's an IP address first
        try:
            ip = ipaddress.ip_address(domain)
            return True, str(ip)
        except ValueError:
            pass
            
        # Basic domain regex
        domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]{2,}$'
        
        if not re.match(domain_pattern, domain):
            return False, f"Invalid domain or IP format: {domain}"
        
        if len(domain) > 253:
            return False, "Domain too long (max 253 characters)"
        
        return True, domain
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """Validate email format"""
        import re
        
        email = email.strip().lower()
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return False, f"Invalid email format: {email}"
        
        return True, email
    
    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input"""
        if not input_str:
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(c for c in input_str if ord(c) >= 32 or c in '\n\r\t')
        
        # Limit length
        return sanitized[:max_length].strip()

# Global API session
_api_session = None

def get_api_session() -> APISession:
    """Get global API session"""
    global _api_session
    if _api_session is None:
        config = get_config()
        _api_session = APISession(
            rate_limit=5.0,
            timeout=config.api.timeout
        )
    return _api_session
