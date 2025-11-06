# ml/fetch_dataset.py
import os
import requests
import json
import time

# NVD API base URL
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ensure dataset folder exists
os.makedirs("dataset", exist_ok=True)

def fetch_cves(start_index=0, results_per_page=100):
    """
    Fetch a batch of CVEs from the NVD public API.
    """
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=20)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[!] Error fetching CVEs: {e}")
        return None


def save_cves(data, filename):
    """
    Save CVE data to dataset/ folder in JSON format.
    """
    path = os.path.join("dataset", filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Saved: {path}")


def build_dataset(total_pages=3, per_page=100):
    """
    Downloads several pages of CVE entries and saves them locally.
    Adjust total_pages to collect more data.
    """
    print("🚀 Fetching CVE vulnerability dataset from NVD...")
    all_cves = []

    for i in range(total_pages):
        start = i * per_page
        print(f"   → Fetching records {start}–{start + per_page} ...")
        data = fetch_cves(start, per_page)
        if data:
            cves = data.get("vulnerabilities", [])
            all_cves.extend(cves)
            time.sleep(1)  # avoid API rate limit
        else:
            print("[!] Skipped due to network issue")

    # Save combined dataset
    save_cves(all_cves, "vuln_dataset.json")
    print(f"\n✅ Dataset ready! Total CVEs collected: {len(all_cves)}")


if __name__ == "__main__":
    build_dataset()
