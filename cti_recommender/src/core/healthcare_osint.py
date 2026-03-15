"""Healthcare open-source intelligence fetchers with cache-first integration.

This module adds optional data sources that can strengthen healthcare context:
- CISA ICS advisories
- openFDA device enforcement (recalls)
- openFDA device events

All fetchers are best-effort and return DataFrames. Failures return empty
DataFrames so existing pipelines can continue running.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Optional

import pandas as pd
import requests

from config.settings import settings

try:
    from src.utils.logging_config import get_logger as _get_logger
    logger = _get_logger("healthcare_osint")
except Exception:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("healthcare_osint")

CACHE_DIR = settings.get_cache_dir() / "healthcare_osint"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _requests_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": settings.HTTP_USER_AGENT,
            "Accept": "application/json, text/html",
        }
    )
    return session


def _cache_path(key: str) -> Path:
    safe = key.replace("/", "_").replace(" ", "_")
    return CACHE_DIR / f"{safe}.pkl.gz"


def _is_valid(path: Path, ttl_seconds: int) -> bool:
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age <= ttl_seconds


def _save_cache(df: pd.DataFrame, key: str) -> None:
    path = _cache_path(key)
    try:
        df.to_pickle(path, compression="gzip")
        logger.info("Saved healthcare OSINT cache: %s", path)
    except Exception:
        logger.exception("Failed to save healthcare OSINT cache: %s", path)


def _load_cache(key: str) -> Optional[pd.DataFrame]:
    path = _cache_path(key)
    if not path.exists():
        return None
    try:
        return pd.read_pickle(path, compression="gzip")
    except Exception:
        logger.exception("Failed to load healthcare OSINT cache: %s", path)
        return None


def fetch_cisa_ics_advisories(
    url: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> pd.DataFrame:
    """Fetch CISA ICS advisories from configured source.

    The endpoint is typically HTML, so this parser extracts advisory IDs from text.
    """
    urls_to_try = []
    if url:
        urls_to_try.append(url)
    else:
        urls_to_try.append(settings.CISA_ICS_ADVISORIES_URL)
        urls_to_try.extend(list(settings.CISA_ICS_ADVISORIES_FALLBACK_URLS))

    if session is None:
        session = _requests_session()

    advisory_ids: set[str] = set()

    for candidate_url in urls_to_try:
        try:
            response = session.get(candidate_url, timeout=settings.HEALTHCARE_OSINT_TIMEOUT)
            response.raise_for_status()
            text = response.text

            found_ids = set(
                re.findall(
                    r"\b(?:ICSA|ICSMA)-\d{2}-\d{3}-\d{2}[A-Z]?\b",
                    text,
                    flags=re.IGNORECASE,
                )
            )

            if not found_ids:
                logger.warning("No ICS advisory IDs parsed from %s", candidate_url)
                continue

            advisory_ids.update(i.upper() for i in found_ids)
            logger.info("Parsed %d ICS advisories from %s", len(found_ids), candidate_url)
        except Exception:
            logger.exception("Failed to fetch CISA ICS advisories from %s", candidate_url)

    if not advisory_ids:
        return pd.DataFrame(columns=["advisory_id", "source_url"])

    sorted_ids = sorted(advisory_ids)
    return pd.DataFrame(
        {
            "advisory_id": sorted_ids,
            "source_url": ["multi-source"] * len(sorted_ids),
        }
    )


def _fetch_openfda(
    base_url: str,
    api_key: Optional[str],
    max_records: int,
    session: Optional[requests.Session] = None,
) -> pd.DataFrame:
    if session is None:
        session = _requests_session()

    rows = []
    limit = min(100, max_records)
    skip = 0

    while skip < max_records:
        params = {"limit": limit, "skip": skip}
        if api_key:
            params["api_key"] = api_key

        try:
            response = session.get(base_url, params=params, timeout=settings.HEALTHCARE_OSINT_TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            results = payload.get("results", [])
            if not results:
                break
            rows.extend(results)

            if len(results) < limit:
                break
            skip += limit
        except Exception:
            logger.exception("Failed openFDA request: %s", base_url)
            break

    if not rows:
        return pd.DataFrame()

    return pd.json_normalize(rows)


def fetch_openfda_device_enforcement(
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    max_records: Optional[int] = None,
    session: Optional[requests.Session] = None,
) -> pd.DataFrame:
    """Fetch openFDA device enforcement (recall) records."""
    if not base_url:
        base_url = settings.OPENFDA_DEVICE_ENFORCEMENT_URL
    if api_key is None:
        api_key = settings.OPENFDA_API_KEY
    if max_records is None:
        max_records = settings.HEALTHCARE_OSINT_MAX_RECORDS

    return _fetch_openfda(base_url, api_key, max_records, session=session)


def fetch_openfda_device_events(
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    max_records: Optional[int] = None,
    session: Optional[requests.Session] = None,
) -> pd.DataFrame:
    """Fetch openFDA device event records."""
    if not base_url:
        base_url = settings.OPENFDA_DEVICE_EVENT_URL
    if api_key is None:
        api_key = settings.OPENFDA_API_KEY
    if max_records is None:
        max_records = settings.HEALTHCARE_OSINT_MAX_RECORDS

    return _fetch_openfda(base_url, api_key, max_records, session=session)


def get_cisa_ics_cached(ttl_days: Optional[int] = None) -> pd.DataFrame:
    """Get CISA ICS advisories with cache-first behavior."""
    ttl_days = ttl_days or settings.HEALTHCARE_OSINT_CACHE_TTL_DAYS
    key = "cisa_ics_advisories"
    path = _cache_path(key)
    ttl_seconds = int(ttl_days * 24 * 3600)

    if _is_valid(path, ttl_seconds):
        cached = _load_cache(key)
        if cached is not None:
            if not cached.empty:
                return cached
            logger.info("Cached CISA ICS advisories are empty, refreshing from source")

    df = fetch_cisa_ics_advisories()
    _save_cache(df, key)
    return df


def get_openfda_enforcement_cached(ttl_days: Optional[int] = None) -> pd.DataFrame:
    """Get openFDA device enforcement records with cache-first behavior."""
    ttl_days = ttl_days or settings.HEALTHCARE_OSINT_CACHE_TTL_DAYS
    key = "openfda_device_enforcement"
    path = _cache_path(key)
    ttl_seconds = int(ttl_days * 24 * 3600)

    if _is_valid(path, ttl_seconds):
        cached = _load_cache(key)
        if cached is not None:
            return cached

    df = fetch_openfda_device_enforcement()
    _save_cache(df, key)
    return df


def get_openfda_events_cached(ttl_days: Optional[int] = None) -> pd.DataFrame:
    """Get openFDA device event records with cache-first behavior."""
    ttl_days = ttl_days or settings.HEALTHCARE_OSINT_CACHE_TTL_DAYS
    key = "openfda_device_events"
    path = _cache_path(key)
    ttl_seconds = int(ttl_days * 24 * 3600)

    if _is_valid(path, ttl_seconds):
        cached = _load_cache(key)
        if cached is not None:
            return cached

    df = fetch_openfda_device_events()
    _save_cache(df, key)
    return df
