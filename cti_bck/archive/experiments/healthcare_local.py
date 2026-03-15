"""HealthCare local ETL script

This script is a local-friendly version of the original Colab notebook.
Run it with: python healthcare_local.py
It will NOT automatically fetch large date ranges — adjust variables before running.
"""

import os
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Any

import requests
import pandas as pd

# Optional dependencies
try:
    import pyarrow  # type: ignore
    PARQUET_AVAILABLE = True
except Exception:
    PARQUET_AVAILABLE = False

try:
    from tqdm import tqdm  # type: ignore
    TQDM_AVAILABLE = True
except Exception:
    TQDM_AVAILABLE = False

# Project-local paths (relative to repository root).
REPO_ROOT = Path.cwd()
DATA_RAW_DIR = REPO_ROOT / 'data' / 'raw'
DATA_PROCESSED_DIR = REPO_ROOT / 'data' / 'processed'
OUTPUTS_DIR = REPO_ROOT / 'outputs'
for d in [DATA_RAW_DIR, DATA_PROCESSED_DIR, OUTPUTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Configuration (use environment variable for API key)
NVD_API_KEY = os.environ.get('NVD_API_KEY')
NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'

FILE_NVD_RAW_JSON = DATA_RAW_DIR / 'CVE_SourceFeed.json'
FILE_NVD_FLAT_PARQUET = DATA_PROCESSED_DIR / 'CVE_MetadataFlat.parquet'
FILE_NVD_FLAT_CSV = DATA_PROCESSED_DIR / 'CVE_MetadataFlat.csv'
FILE_KEV_RAW_CSV = DATA_RAW_DIR / 'KEV_ExploitedCatalog.csv'
FILE_KEV_PROCESSED_CSV = DATA_PROCESSED_DIR / 'KEV_ExploitedCatalog.csv'
FILE_KEV_PROCESSED_PARQ = DATA_PROCESSED_DIR / 'KEV_ExploitedCatalog.parquet'
FILE_UNIFIED_VULN_INTEL_CSV = DATA_PROCESSED_DIR / 'UnifiedVulnIntel.csv'

print('NVD API key set:', bool(NVD_API_KEY))
print('Parquet available:', PARQUET_AVAILABLE)
print('tqdm available:', TQDM_AVAILABLE)

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def _requests_session(retries: int = 3, backoff_factor: float = 0.3):
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=(500, 502, 504), raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry)
    s.mount('https://', adapter)
    s.mount('http://', adapter)
    s.headers.update({'User-Agent': 'cti-recommender/1.0 (+https://example.com)'})
    return s


def get_json(url: str, params: Optional[dict] = None, headers: Optional[dict] = None, session: Optional[requests.Session] = None) -> Any:
    if headers is None:
        headers = {}
    if NVD_API_KEY:
        headers.setdefault('apiKey', NVD_API_KEY)
    if session is None:
        session = _requests_session()
    resp = session.get(url, params=params, headers=headers, timeout=60)
    if not resp.ok:
        raise RuntimeError(f'Request failed: {resp.status_code} {resp.text[:500]} | url={resp.url}')
    try:
        return resp.json()
    except Exception as e:
        raise RuntimeError(f'Failed to parse JSON: {e} | body={resp.text[:200]}')


def fetch_nvd_cves(pub_start_date: str, pub_end_date: str, results_per_page: int = 2000, max_pages: Optional[int] = None, sleep_seconds: float = 1.2, session: Optional[requests.Session] = None) -> List[dict]:
    all_cves: List[dict] = []
    start_index = 0
    page_count = 0
    if session is None:
        session = _requests_session()
    while True:
        params = {
            'pubStartDate': pub_start_date,
            'pubEndDate': pub_end_date,
            'resultsPerPage': results_per_page,
            'startIndex': start_index,
        }
        data = get_json(NVD_BASE_URL, params=params, session=session)
        cves = data.get('vulnerabilities', [])
        if not cves:
            break
        all_cves.extend(cves)
        page_count += 1
        total_results = data.get('totalResults', None)
        print(f'Fetched page {page_count} — this page: {len(cves)}, total so far: {len(all_cves)}')
        start_index += results_per_page
        if max_pages is not None and page_count >= max_pages:
            print('Reached max_pages limit, stopping early (test mode).')
            break
        if total_results is not None and start_index >= total_results:
            break
        time.sleep(sleep_seconds)
    return all_cves


def normalize_nvd_cves(nvd_items: List[dict]) -> pd.DataFrame:
    records: List[dict] = []
    for item in nvd_items:
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('id')
        published = item.get('published')
        last_modified = item.get('lastModified')
        desc_en = None
        for entry in cve_data.get('descriptions', []):
            if entry.get('lang') == 'en':
                desc_en = entry.get('value')
                break
        metrics = cve_data.get('metrics', {})
        cvss_v31 = None
        if 'cvssMetricV31' in metrics:
            cvss_v31 = metrics['cvssMetricV31'][0].get('cvssData', {})
        elif 'cvssMetricV30' in metrics:
            cvss_v31 = metrics['cvssMetricV30'][0].get('cvssData', {})
        cvss_v3_base_score = None
        cvss_v3_vector = None
        if cvss_v31:
            cvss_v3_base_score = cvss_v31.get('baseScore')
            cvss_v3_vector = cvss_v31.get('vectorString')
        records.append({
            'cve_id': cve_id,
            'published': published,
            'last_modified': last_modified,
            'description_en': desc_en,
            'cvss_v3_base_score': cvss_v3_base_score,
            'cvss_v3_vector': cvss_v3_vector,
        })
    return pd.DataFrame.from_records(records)


def fetch_nvd_range_chunked(start_dt: datetime, end_dt: datetime, chunk_days: int = 120, session: Optional[requests.Session] = None, sleep_seconds: float = 1.2) -> List[dict]:
    current = start_dt
    all_items: List[dict] = []
    while current <= end_dt:
        chunk_end = min(current + timedelta(days=chunk_days - 1), end_dt)
        pub_start = current.isoformat(timespec='milliseconds') + 'Z'
        pub_end = chunk_end.isoformat(timespec='milliseconds') + 'Z'
        print(f'Fetching chunk {pub_start} -> {pub_end}')
        items = fetch_nvd_cves(pub_start, pub_end, session=session, sleep_seconds=sleep_seconds)
        all_items.extend(items)
        current = chunk_end + timedelta(days=1)
    return all_items


def fetch_cisa_kev(url: str = CISA_KEV_URL, session: Optional[requests.Session] = None) -> pd.DataFrame:
    if session is None:
        session = _requests_session()
    resp = session.get(url, timeout=60)
    if not resp.ok:
        raise RuntimeError(f'Failed to download CISA KEV: {resp.status_code} {resp.text[:200]}')
    content = resp.content.decode('utf-8', errors='replace')
    df = pd.read_csv(pd.io.common.StringIO(content))
    df.columns = [c.strip() for c in df.columns]
    possible = ['CVE ID', 'cveID', 'cve_id', 'cveid', 'CVE']
    found = None
    for p in possible:
        if p in df.columns:
            found = p
            break
    if found:
        df = df.rename(columns={found: 'cve_id'})
    return df


def main():
    # Safe default: small test window (last 30 days)
    now = datetime.utcnow()
    start = now - timedelta(days=30)
    pub_start = start.isoformat(timespec='milliseconds') + 'Z'
    pub_end = now.isoformat(timespec='milliseconds') + 'Z'
    print('Fetching test window:', pub_start, '->', pub_end)
    session = _requests_session()
    nvd_test_items = fetch_nvd_cves(pub_start, pub_end, session=session)
    print('Fetched items:', len(nvd_test_items))
    with open(FILE_NVD_RAW_JSON, 'w') as f:
        json.dump(nvd_test_items, f)
    df = normalize_nvd_cves(nvd_test_items)
    if PARQUET_AVAILABLE:
        df.to_parquet(FILE_NVD_FLAT_PARQUET, index=False)
    else:
        df.to_csv(FILE_NVD_FLAT_CSV, index=False)
    print('Saved normalized NVD data (rows):', len(df))

    # Fetch CISA KEV (small and fast)
    df_kev = fetch_cisa_kev()
    print('CISA KEV rows:', len(df_kev))
    if PARQUET_AVAILABLE:
        df_kev.to_parquet(FILE_KEV_PROCESSED_PARQ, index=False)
    else:
        df_kev.to_csv(FILE_KEV_PROCESSED_CSV, index=False)
    print('Saved KEV data')

    # Attempt CHPL fetch if key is present (or API allows anonymous access)
    CHPL_API_KEY = os.environ.get('CHPL_API_KEY')
    if CHPL_API_KEY:
        print('CHPL API key present: fetching CHPL product list')
    else:
        print('CHPL API key not set; skipping CHPL fetch (set CHPL_API_KEY to enable)')

    if CHPL_API_KEY:
        try:
            # Try to import the module normally; if that fails (running as a script),
            # load the module directly from the file path to avoid package issues.
            import importlib
            try:
                cr = importlib.import_module('cti_recommender.cti_recommender')
            except Exception:
                import importlib.util
                mod_path = Path(__file__).resolve().parent / 'cti_recommender.py'
                spec = importlib.util.spec_from_file_location('cr_mod', str(mod_path))
                cr = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(cr)

            chpl_df = cr.get_chpl_cached()
            print('CHPL rows:', len(chpl_df))
            FILE_CHPL_PARQ = DATA_PROCESSED_DIR / 'CHPL_products.parquet'
            FILE_CHPL_CSV = DATA_PROCESSED_DIR / 'CHPL_products.csv'
            if PARQUET_AVAILABLE:
                chpl_df.to_parquet(FILE_CHPL_PARQ, index=False)
            else:
                chpl_df.to_csv(FILE_CHPL_CSV, index=False)
            print('Saved CHPL products')
        except Exception as e:
            print('CHPL fetch failed:', e)

    # Fetch ATT&CK techniques (enterprise) and persist
    try:
        attack_df = cr.get_attack_cached()
        print('ATT&CK rows:', len(attack_df))
        FILE_ATTACK_PARQ = DATA_PROCESSED_DIR / 'ATTACK_techniques.parquet'
        FILE_ATTACK_CSV = DATA_PROCESSED_DIR / 'ATTACK_techniques.csv'
        if PARQUET_AVAILABLE:
            attack_df.to_parquet(FILE_ATTACK_PARQ, index=False)
        else:
            attack_df.to_csv(FILE_ATTACK_CSV, index=False)
        print('Saved ATT&CK techniques')
    except Exception as e:
        print('ATT&CK fetch failed:', e)


if __name__ == '__main__':
    main()
