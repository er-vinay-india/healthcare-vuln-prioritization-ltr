"""Unit tests for API client"""
import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
from requests.exceptions import Timeout, ConnectionError, HTTPError

from src.utils.api_client import (
    ResilientAPIClient,
    CircuitBreaker,
    CircuitState,
    get_epss_client,
    get_nvd_client
)


class TestCircuitBreaker:
    """Tests for CircuitBreaker class"""
    
    def test_circuit_starts_closed(self):
        """Test circuit breaker starts in CLOSED state"""
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state == CircuitState.CLOSED
    
    def test_successful_call(self):
        """Test successful function call"""
        cb = CircuitBreaker()
        
        def success_func():
            return "success"
        
        result = cb.call(success_func)
        assert result == "success"
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0
    
    def test_circuit_opens_after_failures(self):
        """Test circuit opens after threshold failures"""
        cb = CircuitBreaker(failure_threshold=3)
        
        def failing_func():
            raise requests.RequestException("Error")
        
        # Trigger failures
        for i in range(3):
            with pytest.raises(requests.RequestException):
                cb.call(failing_func)
        
        assert cb.state == CircuitState.OPEN
        assert cb.failure_count == 3
    
    def test_circuit_rejects_when_open(self):
        """Test circuit rejects calls when OPEN"""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60)
        
        def failing_func():
            raise requests.RequestException("Error")
        
        # Open the circuit
        with pytest.raises(requests.RequestException):
            cb.call(failing_func)
        
        # Circuit should reject next call
        with pytest.raises(Exception) as exc_info:
            cb.call(failing_func)
        assert "Circuit breaker OPEN" in str(exc_info.value)


class TestResilientAPIClient:
    """Tests for ResilientAPIClient class"""
    
    def test_client_initialization(self):
        """Test client initialization"""
        client = ResilientAPIClient(
            base_url="https://api.example.com",
            timeout=30
        )
        assert client.base_url == "https://api.example.com"
        assert client.timeout == 30
        assert client.session is not None
    
    @patch('requests.Session.get')
    def test_successful_get_request(self, mock_get):
        """Test successful GET request"""
        # Mock successful response
        mock_response = Mock()
        mock_response.json.return_value = {"status": "success"}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        client = ResilientAPIClient(
            base_url="https://api.example.com",
            circuit_breaker=False  # Disable for simple test
        )
        
        result = client.get("test/endpoint", params={"key": "value"})
        
        assert result == {"status": "success"}
        mock_get.assert_called_once()
    
    @patch('requests.Session.get')
    def test_retry_on_timeout(self, mock_get):
        """Test retry logic on timeout"""
        # First two calls timeout, third succeeds
        mock_get.side_effect = [
            Timeout("Timeout 1"),
            Timeout("Timeout 2"),
            Mock(json=lambda: {"success": True}, raise_for_status=lambda: None)
        ]
        
        client = ResilientAPIClient(
            base_url="https://api.example.com",
            circuit_breaker=False
        )
        
        result = client.get("test")
        
        assert result == {"success": True}
        assert mock_get.call_count == 3
    
    @patch('requests.Session.post')
    def test_successful_post_request(self, mock_post):
        """Test successful POST request"""
        mock_response = Mock()
        mock_response.json.return_value = {"created": True}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        client = ResilientAPIClient(
            base_url="https://api.example.com",
            circuit_breaker=False
        )
        
        result = client.post("create", json={"name": "test"})
        
        assert result == {"created": True}
        mock_post.assert_called_once()
    
    def test_context_manager(self):
        """Test client can be used as context manager"""
        with ResilientAPIClient("https://api.example.com") as client:
            assert client.session is not None
        
        # Session should be closed after context
    
    def test_base_url_normalization(self):
        """Test base URL normalization"""
        client = ResilientAPIClient("https://api.example.com/")
        assert client.base_url == "https://api.example.com"
        
        client2 = ResilientAPIClient("https://api.example.com")
        assert client2.base_url == "https://api.example.com"


class TestPreConfiguredClients:
    """Tests for pre-configured API clients"""
    
    def test_get_nvd_client(self):
        """Test NVD client factory"""
        client = get_nvd_client()
        assert "nvd.nist.gov" in client.base_url.lower()
        assert client.circuit_breaker is not None
    
    def test_get_epss_client(self):
        """Test EPSS client factory"""
        client = get_epss_client()
        assert "first.org" in client.base_url.lower()
        assert client.circuit_breaker is not None
    
    @patch('src.utils.api_client.settings')
    def test_client_uses_settings(self, mock_settings):
        """Test clients use configuration settings"""
        mock_settings.EPSS_API_BASE = "https://test.api.com"
        mock_settings.EPSS_TIMEOUT = 45
        
        client = get_epss_client()
        assert client.timeout == 45
