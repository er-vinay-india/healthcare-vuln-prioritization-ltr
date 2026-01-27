"""
Quick API Test Script
Tests the new FastAPI endpoints
"""

import requests
import json

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health check endpoint"""
    print("\n1. Testing /health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"   Status: {response.status_code}")
    if response.ok:
        data = response.json()
        print(f"   ✓ Database: {data.get('database_status')}")
        print(f"   ✓ Total CVEs: {data.get('total_cves')}")

def test_predict():
    """Test predict endpoint"""
    print("\n2. Testing /api/v1/predict endpoint...")
    test_cves = ["CVE-2024-1234", "CVE-2023-5678"]
    response = requests.post(
        f"{BASE_URL}/api/v1/predict",
        json=test_cves
    )
    print(f"   Status: {response.status_code}")
    if response.ok:
        data = response.json()
        print(f"   ✓ Scored {data.get('count')} CVEs")
        print(f"   Sample predictions: {list(data.get('predictions', {}).items())[:2]}")

def test_top_cves():
    """Test top CVEs endpoint"""
    print("\n3. Testing /api/v1/top_cves endpoint...")
    response = requests.get(
        f"{BASE_URL}/api/v1/top_cves",
        params={
            'limit': 10,
            'healthcare_only': True,
            'min_cvss': 7.0
        }
    )
    print(f"   Status: {response.status_code}")
    if response.ok:
        data = response.json()
        print(f"   ✓ Returned {data.get('count')} CVEs")
        print(f"   Total candidates: {data.get('total_candidates')}")
        if data.get('top_cves'):
            top = data['top_cves'][0]
            print(f"   Top CVE: {top['cve_id']} (score: {top['score']:.4f})")

def test_explain():
    """Test explanation endpoint"""
    print("\n4. Testing /api/v1/explain endpoint...")
    response = requests.post(
        f"{BASE_URL}/api/v1/explain",
        params={'cve_id': 'CVE-2024-0001'}
    )
    print(f"   Status: {response.status_code}")
    if response.ok:
        data = response.json()
        print(f"   ✓ CVE: {data.get('cve_id')}")
        print(f"   Prediction score: {data.get('prediction_score'):.4f}")
        if 'top_3_features' in data:
            print("   Top 3 features:")
            for feat in data['top_3_features']:
                print(f"      - {feat['feature']}: {feat['contribution']:.4f}")

def test_stats():
    """Test statistics endpoint"""
    print("\n5. Testing /api/v1/stats endpoint...")
    response = requests.get(f"{BASE_URL}/api/v1/stats")
    print(f"   Status: {response.status_code}")
    if response.ok:
        data = response.json()
        print(f"   ✓ Total CVEs: {data.get('total_cves')}")
        print(f"   KEV count: {data.get('kev_count')}")
        print(f"   Healthcare count: {data.get('healthcare_count')}")

if __name__ == "__main__":
    print("=" * 60)
    print("API ENDPOINT TESTS")
    print("=" * 60)
    print(f"Base URL: {BASE_URL}")
    print("Note: Make sure the API server is running!")
    print("      Run: uvicorn src.api.main:app --reload")
    print("=" * 60)
    
    try:
        test_health()
        test_stats()
        test_top_cves()
        test_predict()
        test_explain()
        
        print("\n" + "=" * 60)
        print("✓ All tests completed!")
        print("=" * 60)
        
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Could not connect to API server")
        print("   Please start the server with:")
        print("   uvicorn src.api.main:app --reload")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
