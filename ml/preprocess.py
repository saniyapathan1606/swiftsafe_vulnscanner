# ml/preprocess.py
import os
import json
import pandas as pd

def extract_info(cve_entry):
    """
    Extract useful info from one CVE JSON object
    """
    cve_data = cve_entry.get("cve", {})

    cve_id = cve_data.get("id", "N/A")

    # Extract English description
    desc_list = cve_data.get("descriptions", [])
    description = ""
    for d in desc_list:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # Extract CVSS score and severity
    metrics = cve_data.get("metrics", {})
    severity = "UNKNOWN"
    score = None

    if "cvssMetricV31" in metrics:
        m = metrics["cvssMetricV31"][0]["cvssData"]
        severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        score = m.get("baseScore")
    elif "cvssMetricV2" in metrics:
        m = metrics["cvssMetricV2"][0]["cvssData"]
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
        score = m.get("baseScore")

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "score": score
    }


def preprocess_dataset():
    os.makedirs("dataset", exist_ok=True)
    json_path = os.path.join("dataset", "vuln_dataset.json")

    if not os.path.exists(json_path):
        raise FileNotFoundError("❌ No dataset found! Please run fetch_dataset.py first.")

    print("⚙️ Preprocessing dataset...")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Handle both list and dict formats
    if isinstance(data, dict):
        data = data.get("vulnerabilities", [])

    records = []
    for entry in data:
        try:
            info = extract_info(entry)
            if info["description"]:  # only keep entries with text
                records.append(info)
        except Exception as e:
            print(f"[!] Skipped entry due to parsing error: {e}")

    df = pd.DataFrame(records)
    csv_path = os.path.join("dataset", "cleaned_vuln_data.csv")
    df.to_csv(csv_path, index=False)

    print(f"✅ Preprocessing complete. Clean dataset saved at {csv_path}")
    print(f"📊 Total valid records: {len(df)}")

    return df


if __name__ == "__main__":
    preprocess_dataset()
