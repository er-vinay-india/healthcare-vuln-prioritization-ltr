import pytest
from unittest.mock import MagicMock

from src.core.epss_fetcher import EPSSFetcher


class TestEPSSFetcherResilience:
    def test_fetch_batch_fail_fast_raises(self):
        fetcher = EPSSFetcher()
        fetcher.client = MagicMock()
        fetcher.client.get.side_effect = RuntimeError("api failure")

        with pytest.raises(RuntimeError, match="EPSS API error for batch"):
            fetcher._fetch_batch(["CVE-2023-0001"], fail_fast=True)

    def test_fetch_batch_non_fail_fast_returns_empty(self):
        fetcher = EPSSFetcher()
        fetcher.client = MagicMock()
        fetcher.client.get.side_effect = RuntimeError("api failure")

        result = fetcher._fetch_batch(["CVE-2023-0001"], fail_fast=False)
        assert result == {}

    def test_fetch_epss_bulk_empty_input_returns_empty(self):
        fetcher = EPSSFetcher()
        result = fetcher.fetch_epss_bulk([], use_cache=True, show_progress=False)
        assert result == {}
