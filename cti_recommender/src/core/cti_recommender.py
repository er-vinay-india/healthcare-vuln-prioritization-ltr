"""CTI recommender core utilities extracted from the notebook.

Provides fetchers, caching helpers, scoring and simple EDA helpers so the
notebook can import a single canonical implementation.

This module intentionally keeps a simple file-cache using gzipped pandas
pickles to remain compatible with the existing workspace cache files.
"""
from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Optional, List, Dict

import pandas as pd
import requests
from dateutil.parser import parse as parse_date
from datetime import datetime, timezone
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.settings import settings

# Import EPSS fetcher for exploit prediction scores
try:
    from .epss_fetcher import EPSSFetcher
    HAS_EPSS = True
except ImportError:
    HAS_EPSS = False

try:
    from .healthcare_osint import (
        get_cisa_ics_cached,
        get_openfda_enforcement_cached,
        get_openfda_events_cached,
    )
    HAS_HEALTHCARE_OSINT = True
except ImportError:
    HAS_HEALTHCARE_OSINT = False

# Basic logger for the module
try:
    from src.utils.logging_config import get_logger as _get_logger
    logger = _get_logger("cti_recommender")
except Exception:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("cti_recommender")

# Defaults (can be overridden by passing args to functions)
NVD_API_URL = settings.NVD_API_BASE
CISA_KEV_URL = settings.KEV_CATALOG_CSV_URL
ATTACK_ENTERPRISE_URL = settings.MITRE_ATTACK_ENTERPRISE_URL
CHPL_API_BASE_URL = settings.CHPL_API_BASE
CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _requests_session(retries: int = 3, backoff_factor: float = 0.3, status_forcelist=(500, 502, 504)) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=status_forcelist, raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": settings.HTTP_USER_AGENT})
    return s


def _cache_path(key: str) -> Path:
    safe = key.replace("/", "_").replace(" ", "_")
    return CACHE_DIR / f"{safe}.pkl.gz"


def _is_valid(path: Path, ttl_seconds: int) -> bool:
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age <= ttl_seconds


def save_cache(df: pd.DataFrame, key: str) -> None:
    path = _cache_path(key)
    try:
        df.to_pickle(path, compression="gzip")
        logger.info("Saved cache: %s", path)
    except Exception:
        logger.exception("Failed to save cache: %s", path)


def load_cache(key: str) -> Optional[pd.DataFrame]:
    path = _cache_path(key)
    if not path.exists():
        return None
    try:
        return pd.read_pickle(path, compression="gzip")
    except Exception:
        logger.exception("Failed to read cache %s", path)
        return None


def fetch_nvd_recent_cves(days_back: int = 7, api_url: str = NVD_API_URL, api_key: Optional[str] = None, session: Optional[requests.Session] = None) -> pd.DataFrame:
    """Fetch recent CVEs from NVD (best-effort, single-page).
    
    Args:
        days_back: Number of days to look back
        api_url: NVD API URL
        api_key: NVD API key (optional, uses centralized settings if not provided)
        session: Requests session
    """
    logger.info("Fetching NVD CVEs for last %sd", days_back)
    if session is None:
        session = _requests_session()
    
    # Get API key from centralized settings if not provided
    if api_key is None:
        api_key = settings.NVD_API_KEY
    
    # Add API key header if available (increases rate limit from 5 to 50 requests/30s)
    if api_key:
        session.headers.update({"apiKey": api_key})
        logger.info("Using NVD API key (enhanced rate limits)")
    
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) - pd.Timedelta(days=days_back)
    pub_start = start.isoformat(timespec="seconds").replace("+00:00", "Z")
    pub_end = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    params = {"pubStartDate": pub_start, "pubEndDate": pub_end, "resultsPerPage": 2000}
    resp = session.get(api_url, params=params, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    records = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        published = cve.get("published")
        descriptions = cve.get("descriptions", [])
        desc = descriptions[0].get("value", "") if descriptions else ""
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            cvss_score = cvss_v31[0]["cvssData"].get("baseScore")
        else:
            cvss_v3 = metrics.get("cvssMetricV30", [])
            if cvss_v3:
                cvss_score = cvss_v3[0]["cvssData"].get("baseScore")
        records.append({"cve_id": cve_id, "published": published, "description": desc, "cvss": cvss_score})
    df = pd.DataFrame(records)
    logger.info("Fetched %d CVEs from NVD", len(df))
    return df


def fetch_nvd_date_range(start_date: str, end_date: str, api_url: str = NVD_API_URL, api_key: Optional[str] = None, session: Optional[requests.Session] = None) -> pd.DataFrame:
    """Fetch CVEs from NVD for a specific date range.
    
    Args:
        start_date: Start date in ISO format (YYYY-MM-DD or ISO 8601)
        end_date: End date in ISO format (YYYY-MM-DD or ISO 8601)
        api_url: NVD API URL
        api_key: NVD API key (optional, uses centralized settings if not provided)
        session: Requests session
    
    Returns:
        DataFrame with CVE data
    """
    logger.info(f"Fetching NVD CVEs from {start_date} to {end_date}")
    if session is None:
        session = _requests_session()
    
    # Get API key from centralized settings if not provided
    if api_key is None:
        api_key = settings.NVD_API_KEY
    
    # Add API key header if available
    if api_key:
        session.headers.update({"apiKey": api_key})
    
    # Format dates for NVD API
    if 'T' not in start_date:
        start_date = f"{start_date}T00:00:00.000Z"
    elif not start_date.endswith('Z'):
        start_date = start_date.replace("+00:00", "Z")
    
    if 'T' not in end_date:
        end_date = f"{end_date}T23:59:59.999Z"
    elif not end_date.endswith('Z'):
        end_date = end_date.replace("+00:00", "Z")
    
    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "resultsPerPage": 2000
    }
    
    all_records = []
    start_index = 0
    
    while True:
        params["startIndex"] = start_index
        
        try:
            resp = session.get(api_url, params=params, timeout=60)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            logger.exception(f"NVD API error fetching {start_date} to {end_date}: {e}")
            raise
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break
        
        # Parse CVE data
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            published = cve.get("published")
            modified = cve.get("lastModified")
            
            descriptions = cve.get("descriptions", [])
            desc = descriptions[0].get("value", "") if descriptions else ""
            
            # Extract CVSS score and vector
            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_vector = None
            
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                cvss_score = cvss_v31[0]["cvssData"].get("baseScore")
                cvss_vector = cvss_v31[0]["cvssData"].get("vectorString")
            else:
                cvss_v3 = metrics.get("cvssMetricV30", [])
                if cvss_v3:
                    cvss_score = cvss_v3[0]["cvssData"].get("baseScore")
                    cvss_vector = cvss_v3[0]["cvssData"].get("vectorString")
            
            # Extract CWE
            weaknesses = cve.get("weaknesses", [])
            cwe = None
            if weaknesses and weaknesses[0].get("description"):
                cwe = weaknesses[0]["description"][0].get("value")
            
            all_records.append({
                "cve_id": cve_id,
                "published": published,
                "modified": modified,
                "description": desc,
                "cvss": cvss_score,
                "cvss_vector": cvss_vector,
                "cwe": cwe
            })
        
        # Check if there are more results
        total_results = data.get("totalResults", 0)
        start_index += len(vulnerabilities)
        
        logger.info(f"Fetched {start_index}/{total_results} CVEs...")
        
        if start_index >= total_results:
            break
        
        # Rate limiting: wait between requests
        # With API key: 50 requests/30s = 0.6s between requests
        # Without API key: 5 requests/30s = 6s between requests
        time.sleep(0.7 if api_key else 6.5)
    
    df = pd.DataFrame(all_records)
    logger.info(f"Fetched {len(df)} total CVEs from NVD")
    return df


def fetch_cisa_kev(url: str = CISA_KEV_URL, session: Optional[requests.Session] = None) -> pd.DataFrame:
    logger.info("Fetching CISA KEV catalog")
    if session is None:
        session = _requests_session()
    resp = session.get(url, timeout=60)
    resp.raise_for_status()
    kev_df = pd.read_csv(pd.io.common.StringIO(resp.text))
    kev_df.columns = [c.strip().lower().replace(" ", "_") for c in kev_df.columns]
    possible_names = ["cve_id", "cveid", "cve", "vulnerability_id", "vuln_id", "vulnerability"]
    found = None
    for name in possible_names:
        if name in kev_df.columns:
            found = name
            break
    if not found:
        for col in kev_df.columns:
            if "cve" in col:
                found = col
                break
    if found:
        kev_df = kev_df.rename(columns={found: "cve_id"})
    else:
        kev_df["cve_id"] = None
    logger.info("Fetched KEV entries: %d", len(kev_df))
    return kev_df


def get_nvd_cached(days_back: int = 30, ttl_hours: float = 6.0) -> pd.DataFrame:
    key = f"nvd_{days_back}d"
    path = _cache_path(key)
    ttl = int(ttl_hours * 3600)
    if _is_valid(path, ttl):
        logger.info("Loading NVD from cache: %s", path)
        cached = load_cache(key)
        if cached is not None:
            return cached
    df = fetch_nvd_recent_cves(days_back=days_back)
    save_cache(df, key)
    return df


def get_kev_cached(ttl_days: int = 1) -> pd.DataFrame:
    key = "kev_catalog"
    path = _cache_path(key)
    ttl = int(ttl_days * 24 * 3600)
    if _is_valid(path, ttl):
        logger.info("Loading KEV from cache: %s", path)
        cached = load_cache(key)
        if cached is not None:
            return cached
    df = fetch_cisa_kev()
    save_cache(df, key)
    return df


# --- CHPL fetcher + cache helpers ---

def fetch_chpl_products(api_base: Optional[str] = None, api_key: Optional[str] = None, session: Optional[requests.Session] = None, page_size: int = 100, max_pages: Optional[int] = None) -> pd.DataFrame:
    """Fetch product list from CHPL using the documented /search/v3 endpoint.

    This implementation follows the CHPL OpenAPI docs: it calls GET /search/v3 with
    `pageNumber` (zero-based) and `pageSize` (max 100). The function uses the
    documented `API-Key` header when an API key is provided and pages until all
    records are retrieved (or `max_pages` is reached). Raw response bodies are
    saved to `cache` for debugging when non-200 or unexpected payloads are seen.

    Returns a DataFrame with columns 'product', 'developer' and raw data in 'raw'.
    """
    if not api_base:
        api_base = CHPL_API_BASE_URL

    logger.info("Fetching CHPL products from %s (using /search/v3)", api_base)
    if session is None:
        session = _requests_session()
    if api_key is None:
        api_key = settings.CHPL_API_KEY

    # Respect CHPL doc: max page size is 100
    if page_size is None or page_size <= 0:
        page_size = 100
    page_size = min(int(page_size), 100)

    products = []

    # Primary: call the documented /search/v3 endpoint
    try:
        base = api_base.rstrip("/")
        # ensure we call the v3 search explicitly
        search_url = base + "/search/v3"

        headers = {"Accept": "application/json"}
        if api_key:
            # Use the documented header name `API-Key`
            headers["API-Key"] = api_key

        page_num = 0
        record_count = None
        while True:
            params = {"searchTerm": "", "pageSize": page_size, "pageNumber": page_num}
            resp = session.get(search_url, params=params, headers=headers, timeout=60)

            # Save raw response for debugging; avoid writing secrets elsewhere
            cache_file_json = str(_cache_path(f"chpl_v3_search_page_{page_num}")) + '.json'
            try:
                with open(cache_file_json, 'w') as f:
                    f.write(resp.text)
            except Exception:
                logger.debug('Could not write CHPL raw v3 search page to cache')

            if not resp.ok:
                logger.warning('CHPL /search/v3 returned status %s (page=%s)', resp.status_code, page_num)
                break

            try:
                data = resp.json()
            except Exception:
                logger.warning('CHPL /search/v3 returned non-JSON response (page=%s)', page_num)
                break

            # ListingSearchResponse per docs: recordCount and results[]
            items = data.get('results') or data.get('products') or data.get('data') or []
            if not items:
                # no results on this page; stop
                break

            for it in items:
                product_name = None
                developer_name = None
                if isinstance(it, dict):
                    dev = it.get('developer') or {}
                    prod = it.get('product') or {}
                    product_name = (prod.get('name') if isinstance(prod, dict) else prod) or it.get('product') or it.get('name')
                    developer_name = (dev.get('name') if isinstance(dev, dict) else dev) or it.get('developer')
                products.append({"product": product_name, "developer": developer_name, "raw": it})

            record_count = data.get('recordCount', record_count)
            # stop if we've fetched all records
            if record_count is not None and (page_num + 1) * page_size >= int(record_count):
                break

            page_num += 1
            if max_pages is not None and page_num >= max_pages:
                break

        if products:
            logger.info('Fetched %d CHPL entries via /search/v3', len(products))
            found_any = True
    except Exception as e:
        logger.debug('CHPL /search/v3 fetch failed: %s', e)

    if not products:
        # Fallback: try the earlier wide probe across endpoints and header variants
        found_any = False
        page = 0
        last_exc = None
        
        # Define fallback endpoint variants to try
        endpoints = [
            "/search",
            "/products",
            "/certified_products",
            "/collections/certified_products",
        ]
        
        # Define header variants
        header_variants = [
            {"Accept": "application/json"},
        ]
        if api_key:
            header_variants.extend([
                {"Accept": "application/json", "API-Key": api_key},
                {"Accept": "application/json", "api_key": api_key},
                {"Accept": "application/json", "apiKey": api_key},
            ])
        
        # Define parameter variants
        param_variants = [
            lambda p: {"page": p, "pageSize": page_size},
            lambda p: {"pageNumber": p, "pageSize": page_size},
            lambda p: {"offset": p * page_size, "limit": page_size},
        ]
        
        # param_key_variants will add the API key as a query parameter in different forms if provided
        param_key_variants = [
            lambda p, params: params,
        ]
        if api_key:
            param_key_variants = [
                lambda p, params: params,
                lambda p, params: {**params, "api_key": api_key},
                lambda p, params: {**params, "apiKey": api_key},
                lambda p, params: {**params, "apikey": api_key},
                lambda p, params: {**params, "key": api_key},
            ]

        while True:
            attempted = False
            for hdr in header_variants:
                for ep in endpoints:
                    for pv in param_variants:
                        base_params = pv(page)
                        for pkv in param_key_variants:
                            params = pkv(page, base_params)
                            url = api_base.rstrip("/") + ep
                            attempted = True
                            try:
                                resp = session.get(url, params=params, headers=hdr, timeout=60)
                                # Save raw response for debugging if status != 200
                                cache_file = _cache_path(f"chpl_raw_page_{page}")
                                try:
                                    cache_file.with_suffix('.json')
                                    cache_file_json = str(cache_file) + '.json'
                                    with open(cache_file_json, 'w') as f:
                                        # avoid writing API keys into the body we save
                                        f.write(resp.text)
                                except Exception:
                                    logger.debug('Could not write CHPL raw page to cache')

                                if not resp.ok:
                                    logger.warning('CHPL probe %s returned status %s for %s (params=%s)', url, resp.status_code, ep, params)
                                    last_exc = Exception(f'Status {resp.status_code}')
                                    continue
                                data = None
                                try:
                                    data = resp.json()
                                except Exception:
                                    logger.warning('CHPL returned non-JSON response for %s', url)
                                    last_exc = Exception('Non-JSON response')
                                    continue

                                # locate item list in known keys
                                items = None
                                if isinstance(data, dict):
                                    for key in ("products", "results", "data", "productListings", "result", "rows"):
                                        if key in data and isinstance(data[key], list):
                                            items = data[key]
                                            break
                                    # also check nested result->results
                                    if items is None and 'result' in data and isinstance(data['result'], dict):
                                        for key in ("products", "results", "data"):
                                            if key in data['result'] and isinstance(data['result'][key], list):
                                                items = data['result'][key]
                                                break
                                elif isinstance(data, list):
                                    items = data

                                if not items:
                                    # no usable content on this endpoint/params, try next
                                    last_exc = Exception('No items in response')
                                    continue

                                # extract product/developer
                                for it in items:
                                    product_name = None
                                    developer_name = None
                                    if isinstance(it, dict):
                                        product_name = it.get("product") or it.get("productName") or it.get("product_name") or it.get("name")
                                        developer_name = it.get("developer") or it.get("developerName") or it.get("vendor") or it.get("developer_name")
                                    products.append({"product": product_name, "developer": developer_name, "raw": it})
                                found_any = True
                                break

                            except Exception as e:
                                last_exc = e
                                logger.debug('CHPL probe failed for %s (params=%s): %s', url, params, e)
                        if found_any:
                            break
                    if found_any:
                        break
                if found_any:
                    break

            if not attempted:
                break
            if not found_any:
                # nothing found for this page across variants
                logger.info('No CHPL items found for page %d (last_exc=%s)', page, last_exc)
                break

            page += 1
            if max_pages is not None and page >= max_pages:
                break
    df = pd.DataFrame(products)
    logger.info("Fetched %d CHPL entries", len(df))
    return df


def get_chpl_cached(ttl_days: int = 7) -> pd.DataFrame:
    key = "chpl_products"
    path = _cache_path(key)
    ttl = int(ttl_days * 24 * 3600)
    if _is_valid(path, ttl):
        logger.info("Loading CHPL from cache: %s", path)
        cached = load_cache(key)
        if cached is not None:
            return cached
    df = fetch_chpl_products()
    save_cache(df, key)
    return df


# --- MITRE ATT&CK fetcher + cache helpers ---

def fetch_attack_techniques(url: Optional[str] = None, session: Optional[requests.Session] = None) -> pd.DataFrame:
    """Fetch MITRE ATT&CK Enterprise techniques (attack-pattern objects) from the public CTI repo.

    This fetcher retrieves the enterprise-attack JSON and extracts objects of
    type `attack-pattern`, returning a DataFrame with `id`, `name`, `description`,
    `aliases`, and `raw` columns for downstream mapping heuristics.
    """
    if not url:
        url = ATTACK_ENTERPRISE_URL

    logger.info("Fetching MITRE ATT&CK enterprise techniques from %s", url)
    if session is None:
        session = _requests_session()
    resp = session.get(url, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    objs = data.get('objects', []) if isinstance(data, dict) else []

    rows = []
    for obj in objs:
        if obj.get('type') == 'attack-pattern':
            rows.append({
                'id': obj.get('id'),
                'name': obj.get('name'),
                'description': obj.get('description', ''),
                'aliases': obj.get('aliases', []) or [],
                'external_references': obj.get('external_references', []) or [],
                'raw': obj,
            })
    df = pd.DataFrame(rows)
    logger.info('Fetched %d ATT&CK techniques', len(df))
    return df


def get_attack_cached(ttl_days: int = 7) -> pd.DataFrame:
    key = "attack_techniques"
    path = _cache_path(key)
    ttl = int(ttl_days * 24 * 3600)
    if _is_valid(path, ttl):
        logger.info("Loading ATT&CK techniques from cache: %s", path)
        cached = load_cache(key)
        if cached is not None:
            return cached
    df = fetch_attack_techniques()
    save_cache(df, key)
    return df


def compute_recency_score(published: str, now: datetime) -> float:
    if not isinstance(published, str):
        return 0.0
    try:
        pub_date = parse_date(published)
    except Exception:
        return 0.0
    if pub_date.tzinfo is None:
        pub_date = pub_date.replace(tzinfo=timezone.utc)
    else:
        pub_date = pub_date.astimezone(timezone.utc)
    days_diff = (now - pub_date).days
    max_days = 180
    score = max(0.0, 1.0 - (days_diff / max_days))
    return float(round(score, 3))


def build_simple_score(df: pd.DataFrame, w_recency: float = 0.4, w_kev: float = 0.4, w_cvss: float = 0.2) -> pd.DataFrame:
    """Return a DataFrame with recency_score, cvss_norm and final_score columns."""
    now = datetime.now(timezone.utc)
    df = df.copy()
    df["recency_score"] = df["published"].apply(lambda x: compute_recency_score(x, now))
    df["cvss"] = pd.to_numeric(df.get("cvss", pd.Series([], dtype=float)), errors="coerce")
    df["cvss_norm"] = df["cvss"].fillna(0) / 10.0
    df["final_score"] = (w_recency * df["recency_score"] + w_kev * df.get("kev_flag", 0) + w_cvss * df["cvss_norm"]) 
    return df


# --- Healthcare-focused features and baseline scorer ---

def load_healthcare_patterns(path: Optional[Path] = None) -> List[str]:
    """Return lowercase patterns to identify healthcare-relevant CVEs.

    Load order:
    1) CSV mapping (explicit `path` or configured `settings.HEALTHCARE_MAPPING_PATH`)
    2) Structured healthcare vocab from `src.analysis.healthcare_mapping`
    3) Small hardcoded fallback list (only if prior sources unavailable)
    """
    patterns: List[str] = []

    # Try CSV mapping first (explicit path, then configured path).
    csv_candidates: List[Path] = []
    if path is not None:
        csv_candidates.append(Path(path))
    else:
        configured = settings.HEALTHCARE_MAPPING_PATH
        if configured.is_absolute():
            csv_candidates.append(configured)
        else:
            csv_candidates.append(settings.PROJECT_ROOT / configured)
            csv_candidates.append(Path(configured))

    for csv_path in csv_candidates:
        try:
            if not csv_path.exists():
                continue
            df = pd.read_csv(csv_path)
            if 'pattern' not in df.columns:
                logger.warning("Healthcare mapping file missing 'pattern' column: %s", csv_path)
                continue

            if 'active' in df.columns:
                active_mask = df['active'].astype(str).str.lower().isin(['true', '1', 'yes', 'y'])
                df = df[active_mask]

            csv_patterns = [str(x).lower().strip() for x in df['pattern'].dropna().tolist() if str(x).strip()]
            patterns.extend(csv_patterns)
            logger.info("Loaded %d healthcare patterns from %s", len(csv_patterns), csv_path)
            break
        except Exception:
            logger.exception('Failed to load healthcare patterns from %s', csv_path)

    # Merge structured vocabulary from healthcare mapping module.
    try:
        from src.analysis.healthcare_mapping import (
            HEALTHCARE_VENDORS,
            HEALTHCARE_PRODUCTS,
            HEALTHCARE_KEYWORDS,
        )

        for vendor_terms in HEALTHCARE_VENDORS.values():
            patterns.extend([str(v).lower().strip() for v in vendor_terms if str(v).strip()])

        for product_terms in HEALTHCARE_PRODUCTS.values():
            patterns.extend([str(p).lower().strip() for p in product_terms if str(p).strip()])

        patterns.extend([str(k).lower().strip() for k in HEALTHCARE_KEYWORDS if str(k).strip()])
    except Exception:
        logger.exception("Failed to load structured healthcare vocab; continuing with available patterns")

    # Last-resort fallback to ensure non-empty behavior.
    if not patterns:
        patterns = [str(p).lower().strip() for p in settings.HEALTHCARE_PATTERN_FALLBACK if str(p).strip()]

    # Deduplicate while preserving order.
    deduped = list(dict.fromkeys(patterns))
    logger.info("Using %d healthcare patterns for matching", len(deduped))
    return deduped


def build_healthcare_features(
    df: pd.DataFrame,
    kev_df: Optional[pd.DataFrame] = None,
    patterns: Optional[List[str]] = None,
    chpl_df: Optional[pd.DataFrame] = None,
    attack_df: Optional[pd.DataFrame] = None,
    add_epss: bool = True,
    include_osint: bool = True,
) -> pd.DataFrame:
    """Add features useful for healthcare-focused scoring.

    Features added:
    - recency_score (0..1)
    - cvss_norm (0..1)
    - kev_flag (0/1)
    - epss_score (0..1) - exploit prediction if add_epss=True
    - is_healthcare (0/1) based on substring matching against descriptions or patterns
    - healthcare_osint_flag (0/1) based on openFDA/CISA-derived healthcare terms
    - chpl_flag (0/1) exact-match signal derived from CHPL product/developer names
    - attack_flag (0/1) based on ATT&CK technique name/alias presence in description
    """
    now = datetime.now(timezone.utc)
    df = df.copy()

    df['recency_score'] = df['published'].apply(lambda x: compute_recency_score(x, now))
    df['cvss'] = pd.to_numeric(df.get('cvss', pd.Series([], dtype=float)), errors='coerce')
    df['cvss_norm'] = df['cvss'].fillna(0) / 10.0

    # KEV flag
    if kev_df is not None:
        kev_small = kev_df[['cve_id']].dropna().drop_duplicates().copy()
        kev_small['kev_flag'] = 1
        merged = pd.merge(df, kev_small, on='cve_id', how='left')
        merged['kev_flag'] = merged['kev_flag'].fillna(0).astype(int)
        df = merged
    else:
        if 'kev_flag' in df.columns:
            df['kev_flag'] = pd.to_numeric(df['kev_flag'], errors='coerce').fillna(0).astype(int)
        else:
            df['kev_flag'] = 0

    # CHPL exact-match flag: check CHPL product and developer names in description
    if chpl_df is not None and not chpl_df.empty:
        chpl_names = set()
        for col in ('product', 'developer'):
            if col in chpl_df.columns:
                chpl_names.update([str(x).lower() for x in chpl_df[col].dropna().unique()])

        def _chpl_flag(desc: Optional[str]) -> int:
            if not isinstance(desc, str):
                return 0
            text = desc.lower()
            for name in chpl_names:
                if name and name in text:
                    return 1
            return 0

        if 'description_en' in df.columns:
            df['chpl_flag'] = df['description_en'].apply(_chpl_flag).astype(int)
        else:
            df['chpl_flag'] = df.get('description', '').fillna('').astype(str).apply(_chpl_flag).astype(int)
    else:
        df['chpl_flag'] = 0

    # Healthcare relevance heuristic (substring matching in description)
    # Allow passing a path to the mapping file
    if isinstance(patterns, (str, Path)):
        patterns = load_healthcare_patterns(Path(patterns))
    if patterns is None:
        patterns = load_healthcare_patterns()
    patterns = [p.lower() for p in patterns if p]

    compiled_patterns = []
    for p in patterns:
        # Use boundary-aware matching for textual patterns to avoid false hits
        # like "his" matching "this" or "lis" matching "list".
        if re.fullmatch(r"[a-z0-9_\-\s]+", p):
            patt = re.escape(p).replace(r"\ ", r"\s+")
            compiled_patterns.append(re.compile(rf"\b{patt}\b", flags=re.IGNORECASE))
        else:
            compiled_patterns.append(None)

    def _is_healthcare(desc: Optional[str]) -> int:
        if not isinstance(desc, str):
            return 0
        text = desc.lower()
        for i, p in enumerate(patterns):
            cp = compiled_patterns[i]
            if cp is not None:
                if cp.search(text):
                    return 1
            elif p in text:
                return 1
        return 0

    osint_terms: List[str] = []
    if include_osint and HAS_HEALTHCARE_OSINT:
        try:
            # Fetch from cache-first adapters. These are best-effort by design.
            _ = get_cisa_ics_cached()
            openfda_enf = get_openfda_enforcement_cached()
            openfda_evt = get_openfda_events_cached()

            stop_words = {str(w).lower() for w in settings.HEALTHCARE_OSINT_STOP_WORDS if str(w).strip()}

            def _expand_osint_terms(text_value: str) -> List[str]:
                text_value = str(text_value).strip().lower()
                if not text_value:
                    return []
                terms = []
                # Keep full phrase only when short enough to be usable as a match key.
                if len(text_value) <= 80:
                    terms.append(text_value)
                tokens = re.findall(r"[a-z][a-z0-9_-]{3,}", text_value)
                tokens = [t for t in tokens if t not in stop_words]

                # Add short phrases for higher precision than single-token matching.
                for i in range(len(tokens) - 1):
                    phrase = f"{tokens[i]} {tokens[i + 1]}"
                    if len(phrase) >= 8:
                        terms.append(phrase)
                return terms

            for col in ("recalling_firm", "product_description"):
                if col in openfda_enf.columns:
                    for v in openfda_enf[col].dropna().astype(str).head(500):
                        osint_terms.extend(_expand_osint_terms(v))

            if "device" in openfda_evt.columns:
                for device_blob in openfda_evt["device"].dropna().astype(str).head(500):
                    # Event payloads are serialized dict/list strings in this dataset.
                    for m in re.findall(r"'(?:brand_name|generic_name|device_name)'\s*:\s*'([^']+)'", device_blob):
                        osint_terms.extend(_expand_osint_terms(m))

            # Deduplicate and avoid extremely long fragments that cause noisy matching.
            osint_terms = sorted({t for t in osint_terms if 5 <= len(t) <= 80})[: settings.HEALTHCARE_OSINT_MAX_TERMS]
            logger.info("Using %d healthcare OSINT terms for matching", len(osint_terms))
        except Exception:
            logger.exception("Failed to load healthcare OSINT terms; continuing without OSINT signal")
            osint_terms = []

    def _osint_healthcare(desc: Optional[str]) -> int:
        if not isinstance(desc, str) or not osint_terms:
            return 0
        text = desc.lower()
        for t in osint_terms:
            if t in text:
                return 1
        return 0

    def _has_health_anchor(desc: Optional[str]) -> int:
        if not isinstance(desc, str):
            return 0
        text = desc.lower()
        anchors = [str(a).lower() for a in settings.HEALTHCARE_OSINT_ANCHOR_TERMS if str(a).strip()]
        return int(any(a in text for a in anchors))

    # Try multiple description fields if present
    if 'description_en' in df.columns:
        desc_series = df['description_en']
    else:
        desc_series = df.get('description', '').fillna('').astype(str)

    df['healthcare_pattern_flag'] = desc_series.apply(_is_healthcare).astype(int)

    # NLP-based fuzzy matching against OSINT terms (char n-grams are robust to punctuation/casing noise).
    if include_osint and osint_terms:
        try:
            desc_text = desc_series.fillna('').astype(str).str.lower()
            vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), min_df=1)
            osint_matrix = vectorizer.fit_transform(osint_terms)
            desc_matrix = vectorizer.transform(desc_text)
            sim = cosine_similarity(desc_matrix, osint_matrix)
            max_sim = sim.max(axis=1)
            df['healthcare_osint_similarity'] = max_sim
            anchor_flag = desc_series.apply(_has_health_anchor).astype(int)
            substring_flag = desc_series.apply(_osint_healthcare).astype(int)
            fuzzy_flag = (
                df['healthcare_osint_similarity'] >= settings.HEALTHCARE_OSINT_SIMILARITY_THRESHOLD
            ).astype(int)
            # Require healthcare anchors for fuzzy matches to reduce false positives.
            df['healthcare_osint_flag'] = (((substring_flag == 1) | (fuzzy_flag == 1)) & (anchor_flag == 1)).astype(int)
        except Exception:
            logger.exception("NLP OSINT matching failed; falling back to substring matching")
            df['healthcare_osint_flag'] = desc_series.apply(_osint_healthcare).astype(int)
            df['healthcare_osint_similarity'] = 0.0
    else:
        df['healthcare_osint_flag'] = 0
        df['healthcare_osint_similarity'] = 0.0

    df['is_healthcare'] = ((df['healthcare_pattern_flag'] == 1) | (df['healthcare_osint_flag'] == 1)).astype(int)

    # ATT&CK mapping: simple heuristic using technique names, aliases, and CAPEC IDs
    if attack_df is not None and not attack_df.empty:
        keywords = set()
        for _, row in attack_df.iterrows():
            name = row.get('name')
            if name:
                keywords.add(str(name).lower())
            for a in (row.get('aliases') or []):
                if a:
                    keywords.add(str(a).lower())
            # Add CAPEC external_ids
            for ref in (row.get('external_references') or []):
                if ref.get('source_name', '').lower() == 'capec':
                    ext_id = ref.get('external_id')
                    if ext_id:
                        keywords.add(str(ext_id).lower())
        # Keep only substantive tokens to avoid noisy short matches
        keywords = {k for k in keywords if len(k) >= 4}

        def _attack_flag(desc: Optional[str]) -> int:
            if not isinstance(desc, str):
                return 0
            txt = desc.lower()
            for kw in keywords:
                if kw in txt:
                    return 1
            return 0

        if 'description_en' in df.columns:
            df['attack_flag'] = df['description_en'].apply(_attack_flag).astype(int)
        else:
            df['attack_flag'] = df.get('description', '').fillna('').astype(str).apply(_attack_flag).astype(int)
    else:
        if 'attack_flag' in df.columns:
            df['attack_flag'] = pd.to_numeric(df['attack_flag'], errors='coerce').fillna(0).astype(int)
        else:
            df['attack_flag'] = 0

    # EPSS (Exploit Prediction Scoring System) scores
    if add_epss and HAS_EPSS:
        try:
            epss_fetcher = EPSSFetcher()
            df = epss_fetcher.enrich_dataframe(df, cve_column='cve_id')
            # Normalize EPSS score (already 0-1, but ensure column exists)
            if 'epss_score' not in df.columns:
                df['epss_score'] = 0.0
        except Exception as e:
            logger.warning(f"Failed to fetch EPSS scores: {e}")
            df['epss_score'] = 0.0
    else:
        df['epss_score'] = 0.0

    return df


def build_weighted_score(df: pd.DataFrame, w_recency: float = 0.20, w_kev: float = 0.25, w_cvss: float = 0.10, w_epss: float = 0.15, w_attack: float = 0.05, w_health: float = 0.10, w_chpl: float = 0.15) -> pd.DataFrame:
    """Compute a weighted final_score using the provided weights. Returns a new DataFrame.

    Phase 2 weights with EPSS integration:
    - Recency: 0.20 (reduced to accommodate EPSS)
    - KEV: 0.25 (proven high-value signal)
    - CVSS: 0.10 (static severity, less predictive than EPSS)
    - EPSS: 0.15 (NEW - exploit probability, fills gaps for missing CVSS)
    - Attack: 0.05 (technique mapping)
    - Healthcare: 0.10 (sector relevance)
    - CHPL: 0.15 (healthcare product database)
    """
    df = df.copy()
    df['recency_score'] = df.get('recency_score', 0.0).fillna(0.0)
    df['cvss_norm'] = df.get('cvss_norm', 0.0).fillna(0.0)
    df['epss_score'] = df.get('epss_score', 0.0).fillna(0.0)
    df['kev_flag'] = df.get('kev_flag', 0).fillna(0).astype(int)
    df['attack_flag'] = df.get('attack_flag', 0).fillna(0).astype(int)
    df['is_healthcare'] = df.get('is_healthcare', 0).fillna(0).astype(int)
    df['chpl_flag'] = df.get('chpl_flag', 0).fillna(0).astype(int)

    df['final_score'] = (
        w_recency * df['recency_score'] +
        w_kev * df['kev_flag'] +
        w_cvss * df['cvss_norm'] +
        w_epss * df['epss_score'] +
        w_attack * df['attack_flag'] +
        w_health * df['is_healthcare'] +
        w_chpl * df['chpl_flag']
    )
    return df


def score_and_save(nvd_df: pd.DataFrame, kev_df: Optional[pd.DataFrame] = None, chpl_df: Optional[pd.DataFrame] = None, attack_df: Optional[pd.DataFrame] = None, out_dir: Path = Path('outputs'), top_k: int = 20, patterns: Optional[List[str]] = None, weights: Optional[Dict[str, float]] = None) -> pd.DataFrame:
    """Combine, compute features, score, and save top results to `out_dir`.

    Supports optional `chpl_df` and `attack_df` to enable CHPL exact-match and ATT&CK presence signals.

    Returns the scored DataFrame sorted by `final_score` descending.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = build_healthcare_features(nvd_df, kev_df=kev_df, patterns=patterns, chpl_df=chpl_df, attack_df=attack_df)

    if weights is None:
        # Phase 2 weights with EPSS integration for exploit prediction
        weights = dict(w_recency=0.20, w_kev=0.25, w_cvss=0.10, w_epss=0.15, w_attack=0.05, w_health=0.10, w_chpl=0.15)

    scored = build_weighted_score(df, **weights)
    scored_sorted = scored.sort_values(by='final_score', ascending=False).reset_index(drop=True)

    # Save outputs
    try:
        scored_sorted.to_csv(out_dir / 'top_scored.csv', index=False)
        scored_sorted.head(top_k).to_csv(out_dir / f'top{top_k}.csv', index=False)
    except Exception:
        logger.exception('Failed to write scored outputs')

    return scored_sorted
