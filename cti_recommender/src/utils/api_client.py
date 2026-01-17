"""
Resilient HTTP API Client with Retry Logic and Circuit Breaker
Provides robust HTTP communication with automatic retries and error handling
"""
import time
from typing import Dict, Any, Optional, Callable
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
    after_log
)
import logging

from config import settings

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


class CircuitBreaker:
    """
    Circuit breaker pattern implementation
    Prevents cascading failures by stopping requests to failing services
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type = requests.RequestException
    ):
        """
        Initialize circuit breaker
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            expected_exception: Exception type that triggers circuit
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection
        
        Args:
            func: Function to execute
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func
            
        Returns:
            Function result
            
        Raises:
            Exception: If circuit is open or function fails
        """
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker entering HALF_OPEN state")
            else:
                raise Exception(
                    f"Circuit breaker OPEN. Service unavailable. "
                    f"Will retry after {self.recovery_timeout}s"
                )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
            
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt recovery"""
        if self.last_failure_time is None:
            return True
        return time.time() - self.last_failure_time >= self.recovery_timeout
    
    def _on_success(self):
        """Handle successful request"""
        if self.state == CircuitState.HALF_OPEN:
            logger.info("Circuit breaker recovered, entering CLOSED state")
        self.failure_count = 0
        self.state = CircuitState.CLOSED
    
    def _on_failure(self):
        """Handle failed request"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.error(
                f"Circuit breaker OPENED after {self.failure_count} failures. "
                f"Service will be unavailable for {self.recovery_timeout}s"
            )


class ResilientAPIClient:
    """
    HTTP client with retries, exponential backoff, and circuit breaker
    
    Features:
    - Automatic retries with exponential backoff
    - Circuit breaker to prevent cascading failures
    - Connection pooling
    - Configurable timeouts
    - Request/response logging
    """
    
    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        max_retries: int = None,
        backoff_factor: float = None,
        circuit_breaker: bool = True
    ):
        """
        Initialize API client
        
        Args:
            base_url: Base URL for API (e.g., "https://api.example.com")
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts (defaults to settings.MAX_RETRIES)
            backoff_factor: Backoff multiplier (defaults to settings.RETRY_BACKOFF_FACTOR)
            circuit_breaker: Enable circuit breaker pattern
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries or settings.MAX_RETRIES
        self.backoff_factor = backoff_factor or settings.RETRY_BACKOFF_FACTOR
        
        # Create session with retry strategy
        self.session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=list(settings.RETRY_STATUS_CODES),
            allowed_methods=["GET", "POST", "PUT", "DELETE"],
            raise_on_status=False  # Let us handle status codes
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'CTI-Healthcare-Recommender/1.0',
            'Accept': 'application/json'
        })
        
        # Circuit breaker
        self.circuit_breaker = None
        if circuit_breaker:
            self.circuit_breaker = CircuitBreaker(
                failure_threshold=5,
                recovery_timeout=60.0,
                expected_exception=requests.RequestException
            )
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((
            requests.Timeout,
            requests.ConnectionError,
            requests.HTTPError
        )),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        after=after_log(logger, logging.INFO)
    )
    def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        GET request with retries and circuit breaker
        
        Args:
            endpoint: API endpoint (relative to base_url)
            params: Query parameters
            headers: Additional headers
            **kwargs: Additional arguments for requests.get
            
        Returns:
            Parsed JSON response
            
        Raises:
            requests.HTTPError: For HTTP errors
            requests.Timeout: For timeouts
            requests.ConnectionError: For connection errors
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        logger.debug(f"GET {url}", extra={"params": params})
        
        def _make_request():
            response = self.session.get(
                url,
                params=params,
                headers=request_headers,
                timeout=kwargs.get('timeout', self.timeout),
                **kwargs
            )
            response.raise_for_status()
            return response.json()
        
        if self.circuit_breaker:
            return self.circuit_breaker.call(_make_request)
        else:
            return _make_request()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((
            requests.Timeout,
            requests.ConnectionError,
            requests.HTTPError
        )),
        before_sleep=before_sleep_log(logger, logging.WARNING)
    )
    def post(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        POST request with retries and circuit breaker
        
        Args:
            endpoint: API endpoint
            data: Form data
            json: JSON body
            headers: Additional headers
            **kwargs: Additional arguments for requests.post
            
        Returns:
            Parsed JSON response
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        logger.debug(f"POST {url}")
        
        def _make_request():
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=request_headers,
                timeout=kwargs.get('timeout', self.timeout),
                **kwargs
            )
            response.raise_for_status()
            return response.json()
        
        if self.circuit_breaker:
            return self.circuit_breaker.call(_make_request)
        else:
            return _make_request()
    
    def close(self):
        """Close the session and release connections"""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Pre-configured clients for common APIs
def get_nvd_client() -> ResilientAPIClient:
    """Get configured NVD API client"""
    return ResilientAPIClient(
        base_url=settings.NVD_API_BASE,
        timeout=settings.NVD_TIMEOUT,
        circuit_breaker=True
    )


def get_epss_client() -> ResilientAPIClient:
    """Get configured EPSS API client"""
    return ResilientAPIClient(
        base_url=settings.EPSS_API_BASE,
        timeout=settings.EPSS_TIMEOUT,
        circuit_breaker=True
    )


def get_kev_client() -> ResilientAPIClient:
    """Get configured KEV catalog client"""
    return ResilientAPIClient(
        base_url=settings.KEV_CATALOG_URL.rsplit('/', 1)[0],  # Extract base URL
        timeout=settings.KEV_TIMEOUT,
        circuit_breaker=False  # Single endpoint, no need for circuit breaker
    )
