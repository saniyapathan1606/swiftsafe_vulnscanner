

# **SwiftSafe – AI-Powered Vulnerability Scanner**

## **About the Project**

**SwiftSafe** is a Machine Learning–driven web vulnerability scanner that detects and predicts the severity of security flaws in web applications. It combines **automated reconnaissance**, **header and cookie analysis**, and **ML-based CVE classification**, helping pentesters and bug bounty researchers identify potential risks quickly and efficiently.

## **Features**

* **Automated Scanning** – Detects misconfigurations, missing security headers, and potential XSS/SQLi vectors
* **Machine Learning Engine** – Trained on CVE/NVD data for severity prediction
* **Intelligent Report Generation** – Generates detailed JSON reports for each target
* **Real-Time Target Analysis** – Scans live websites or locally hosted applications (e.g., OWASP Juice Shop)
* **Modular Design** – ML, scanner, and reporting modules are separate for flexibility and extension

## **Tech Stack**

| Component               | Technology                            |
| ----------------------- | ------------------------------------- |
| **Backend**             | Python (FastAPI / Flask)              |
| **ML Engine**           | scikit-learn, pandas, NumPy           |
| **Dataset Source**      | NVD (National Vulnerability Database) |
| **Frontend (optional)** | React / Next.js                       |
| **Reporting**           | JSON + Terminal Output                |

## **Setup Instructions**

**1. Clone the repository**

```bash
git clone https://github.com/saniyapathan1606/swiftsafe_vulnscanner.git
cd swiftsafe_vulnscanner
```

**2. Create & activate a virtual environment**

```bash
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate   # Linux / macOS
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Fetch the CVE dataset**

```bash
python ml/fetch_nvd_single.py
```

**5. Preprocess & train ML model**

```bash
python ml/preprocess_real.py
python ml/train_model.py
```

**6. Run the scanner**

```bash
python scanner/web_scanner.py
```

**7. Enter your target URL**
Example:

```bash
Enter target URL (e.g., https://example.com): http://127.0.0.1:5000
```

## **Example Output**

```json
{
  "target": "https://juice-shop.local",
  "ip_info": {
    "domain": "juice-shop.local",
    "ip": "127.0.0.1"
  },
  "findings": [
    {
      "issue": "Missing security header: Content-Security-Policy",
      "predicted_severity": "HIGH",
      "confidence": 67.42
    }
  ]
}
```

## **Machine Learning Overview**

The ML model is trained on thousands of CVE entries from NVD. It extracts features such as:

* Attack vector
* Access complexity
* Privileges required
* Impact metrics (CIA triad)

The model predicts **vulnerability severity** (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and assigns a confidence score.

## **Folder Structure**

```
swiftsafe_vulnscanner/
│
├── ml/
│   ├── fetch_nvd_single.py
│   ├── preprocess_real.py
│   ├── train_model.py
│   └── model.pkl
│
├── scanner/
│   ├── web_scanner.py
│   └── report_generator.py
│
├── reports/
│   └── scan_report.json
│
├── requirements.txt
└── README.md
```

## **Future Enhancements**

* Integration with **Burp Suite / OWASP ZAP APIs**
* **Visual dashboard** for real-time report visualization
* **Threat intelligence** integration
* Multi-target concurrent scanning

## **Author**

**👩‍💻 Saniya Pathan**
Cybersecurity & AI Enthusiast

