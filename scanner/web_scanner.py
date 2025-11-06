# scanner/web_scanner.py
"""
Passive web scanner with ML triage integration (scanner/web_scanner.py)

- Passive only: GET requests, harmless reflection marker check (no payloads/exploits)
- Uses models from ml/model_predict.py: predict_vulnerability(description) -> dict with keys:
    - predicted_severity
    - confidence
- Uses config/whitelist.txt to skip noisy sites (one hostname per line)
- Saves output to reports/scan_report.json
"""

import sys
from pathlib import Path
import json
import re
import time
from urllib.parse import urlparse, urljoin

# Ensure project root is importable when running as script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# Import predict function from your ml module
try:
    from ml.model_predict import predict_vulnerability
except Exception as e:
    # Friendly error if model_predict is missing
    print("Error importing ml.model_predict.predict_vulnerability:", e)
    print("Make sure models/vuln_model.pkl and models/vectorizer.pkl exist and ml/ is a package.")
    raise

# ----------------- Config -----------------
COMMON_PATHS = [
    "/", "/index.php", "/login", "/admin", "/robots.txt", "/sitemap.xml",
    "/.git/", "/.env", "/wp-login.php", "/wp-admin/", "/admin.php", "/search"
]

SUSPICIOUS_PATTERNS = [
    r"sql syntax", r"syntax error", r"warning: mysql", r"pdoexception",
    r"stack trace", r"xss", r"cross-site scripting", r"<script>alert\(",
    r"fatal error", r"undefined variable", r"traceback \(most recent call last\)",
    r"ora-", r"sqlstate"
]

HEADER_SECURITY_HEADERS = [
    "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Strict-Transport-Security"
]

USER_AGENT = "SwiftSafe-Passive-Scanner/1.0 (+https://example.com)"

# Confidence threshold: if classifier confidence < this, downgrade severity to INFO/LOW
CONFIDENCE_THRESHOLD = 0.60

# Whitelist file path
WHITELIST_PATH = ROOT / "config" / "whitelist.txt"

# ----------------- Utilities -----------------
def load_whitelist(path=WHITELIST_PATH):
    if not path.exists():
        # built-in default to avoid false positives on big providers
        return {
            "google.com","www.google.com","bing.com","yahoo.com",
            "facebook.com","twitter.com","amazon.com","cloudflare.com",
            "akamai.com","microsoft.com","github.com","gitlab.com","bitbucket.org"
        }
    try:
        text = path.read_text(encoding="utf-8")
        lines = [ln.strip().lower() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        return set(lines)
    except Exception:
        return set()

DOMAIN_WHITELIST = load_whitelist()

def make_session(max_retries=3, backoff_factor=0.5):
    s = requests.Session()
    retries = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=["GET", "HEAD"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": USER_AGENT})
    return s

SESSION = make_session()

def is_html_response(headers):
    ctype = headers.get("Content-Type", "") if headers else ""
    return "text/html" in ctype.lower()

def analyze_response_for_patterns(text):
    found = []
    if not text:
        return found
    snippet = text[:20000].lower()
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, snippet):
            found.append(pat)
    return list(set(found))

def find_forms(html, base_url):
    forms = []
    if not html:
        return forms
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        inputs = []
        for inp in form.find_all(["input","textarea","select"]):
            name = inp.get("name") or inp.get("id") or ""
            itype = inp.get("type") or inp.name
            inputs.append({"name": name, "type": itype})
        forms.append({"action": urljoin(base_url, action), "method": method, "inputs": inputs})
    return forms

def form_is_suspicious(form, target_host):
    # require at least one text-like input
    text_like = {"text","search","textarea","email","url","tel",""}
    has_text_inputs = any((i.get("type","").lower() in text_like) for i in form.get("inputs", []))
    if not has_text_inputs:
        return False
    # if action has external host, require same-origin to flag
    action = form.get("action","")
    try:
        a_host = urlparse(action).netloc.split(":")[0].lower() if action else ""
        if a_host:
            return a_host == target_host
        return True
    except Exception:
        return True

def apply_confidence_downgrade(predicted, confidence):
    """Downgrade severity when classifier confidence is low."""
    # confidence expects 0-100 or 0-1; normalize to 0-1
    try:
        conf = float(confidence)
        if conf > 1:
            conf = conf / 100.0
    except Exception:
        conf = 0.0
    if conf < CONFIDENCE_THRESHOLD:
        # downgrade mapping
        if predicted in ("HIGH", "CRITICAL"):
            return "INFO"
        if predicted == "MEDIUM":
            return "LOW"
    return predicted

# ----------------- Core scanning logic -----------------
def get_url(url, timeout=10):
    try:
        r = SESSION.get(url, timeout=timeout, allow_redirects=True)
        return {"ok": True, "status": r.status_code, "headers": dict(r.headers), "text": r.text, "url": r.url}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def probe_paths(target, probe_list=None, timeout=8):
    results = []
    if probe_list is None:
        probe_list = COMMON_PATHS
    for p in probe_list:
        full = target.rstrip("/") + p
        try:
            r = SESSION.get(full, timeout=timeout, allow_redirects=True)
            results.append({"path": full, "status": r.status_code, "text": r.text or "", "url": r.url})
        except Exception as e:
            results.append({"path": full, "error": str(e)})
    return results

def passive_scan(target_url, timeout=10):
    target = target_url.strip()
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "https://" + target

    parsed = urlparse(target)
    target_host = parsed.netloc.split(":")[0].lower()

    report = {
        "target": target,
        "ip_info": {},
        "findings": [],
        "_diagnostics": {"attempts": []}
    }

    # DNS/IP
    try:
        ip = requests.get("https://api.ipify.org").text  # not used for scanning, just example
    except Exception:
        ip = None
    report["ip_info"] = {"domain": target_host, "local_ip_check": ip}

    # attempt main GET (with retries)
    main = get_url(target, timeout=timeout)
    report["_diagnostics"]["attempts"].append({"url": target, "result": ("error", main.get("error")) if not main.get("ok") else {"status": main.get("status")}})

    # fallback to http if https failed
    if not main.get("ok") and target.startswith("https://"):
        alt = "http://" + target[len("https://"):]
        report["_diagnostics"]["attempts"].append({"url": alt})
        main = get_url(alt, timeout=timeout)

    if not main.get("ok"):
        report["error"] = main.get("error")
        return report

    headers = main.get("headers", {})
    body = main.get("text", "") or ""
    url_used = main.get("url", target)

    # If whitelisted, skip noisy heuristics (but still record a minimal info finding)
    if target_host in DOMAIN_WHITELIST:
        report["_diagnostics"]["whitelisted"] = True
    else:
        # Header analysis: only for HTML responses
        if is_html_response(headers):
            # info-leak headers
            if "Server" in headers:
                desc = f"Server: {headers.get('Server')}"
                pred = predict_vulnerability(f"Server header reveals technology: {desc}")
                predicted = pred.get("predicted_severity") if isinstance(pred, dict) else pred.get("pred")
                conf = pred.get("confidence") if isinstance(pred, dict) else pred.get("probs")
                report["findings"].append({
                    "issue": "Server header reveals technology",
                    "detail": desc,
                    "predicted_severity": apply_confidence_downgrade(predicted, conf),
                    "confidence": conf
                })
            if "X-Powered-By" in headers:
                desc = f"X-Powered-By: {headers.get('X-Powered-By')}"
                pred = predict_vulnerability(f"X-Powered-By reveals tech: {desc}")
                predicted = pred.get("predicted_severity") if isinstance(pred, dict) else pred.get("pred")
                conf = pred.get("confidence") if isinstance(pred, dict) else pred.get("probs")
                report["findings"].append({
                    "issue": "X-Powered-By reveals tech",
                    "detail": desc,
                    "predicted_severity": apply_confidence_downgrade(predicted, conf),
                    "confidence": conf
                })

            # missing security headers (conservative)
            for h in HEADER_SECURITY_HEADERS:
                if h not in headers:
                    pred = predict_vulnerability(f"Missing security header: {h}")
                    predicted = pred.get("predicted_severity") if isinstance(pred, dict) else pred.get("pred")
                    conf = pred.get("confidence") if isinstance(pred, dict) else pred.get("probs")
                    report["findings"].append({
                        "issue": f"Missing security header: {h}",
                        "detail": h,
                        "predicted_severity": apply_confidence_downgrade(predicted, conf),
                        "confidence": conf
                    })

        # pattern analysis on main page
        patterns = analyze_response_for_patterns(body)
        for p in patterns:
            pred = predict_vulnerability(f"Suspicious pattern: {p}")
            predicted = pred.get("predicted_severity") if isinstance(pred, dict) else pred.get("pred")
            conf = pred.get("confidence") if isinstance(pred, dict) else pred.get("probs")
            report["findings"].append({
                "issue": f"Suspicious pattern matched: {p}",
                "detail": f"Pattern found in {url_used}",
                "predicted_severity": apply_confidence_downgrade(predicted, conf),
                "confidence": conf
            })

        # form discovery
        forms = find_forms(body, url_used)
        for f in forms:
            if form_is_suspicious(f, target_host):
                desc = f"Form at {f.get('action')} method={f.get('method')} inputs={[i.get('name') for i in f.get('inputs',[])]}"
                pred = predict_vulnerability(desc)
                predicted = pred.get("predicted_severity") if isinstance(pred, dict) else pred.get("pred")
                conf = pred.get("confidence") if isinstance(pred, dict) else pred.get("probs")
                report["findings"].append({
                    "issue": "Form discovered (possible vector)",
                    "detail": desc,
                    "predicted_severity": apply_confidence_downgrade(predicted, conf),
                    "confidence": conf
                })

        # shallow harmless reflection check: marker must appear exactly to be considered
        marker = f"swiftsafe_reflect_{int(time.time()%100000)}"
        try:
            test_url = url_used + ("&" if "?" in url_used else "?") + f"{marker}=1"
            rr = SESSION.get(test_url, timeout=6)
            if rr.ok and marker in (rr.text or ""):
                pred = predict_vulnerability(f"Reflection of parameter marker detected at {url_used}")
                predicted = pred.get("predicted_severity") if isinstance(pred, dict) else pred.get("pred")
                conf = pred.get("confidence") if isinstance(pred, dict) else pred.get("probs")
                report["findings"].append({
                    "issue": "Reflected input detected (possible XSS reflection point)",
                    "detail": url_used,
                    "predicted_severity": apply_confidence_downgrade(predicted, conf),
                    "confidence": conf
                })
        except Exception:
            pass

        # probe a few common paths (non-destructive)
        path_results = probe_paths(target, COMMON_PATHS, timeout=8)
        for pr in path_results:
            if pr.get("status") == 200:
                # sensitive path heuristics
                pth = pr.get("path")
                if any(x in pth for x in [".git", ".env", "wp-admin", "wp-login", "/sensitive/"]):
                    pred = predict_vulnerability(f"Accessible resource: {pth} returned 200")
                    predicted = pred.get("predicted_severity") if isinstance(pred, dict) else pred.get("pred")
                    conf = pred.get("confidence") if isinstance(pred, dict) else pred.get("probs")
                    report["findings"].append({
                        "issue": "Accessible sensitive path",
                        "detail": pth,
                        "predicted_severity": apply_confidence_downgrade(predicted, conf),
                        "confidence": conf
                    })
                # pattern checks on path content
                matches = analyze_response_for_patterns(pr.get("text",""))
                for m in matches:
                    pred = predict_vulnerability(f"Pattern {m} found at {pth}")
                    predicted = pred.get("predicted_severity") if isinstance(pred, dict) else pred.get("pred")
                    conf = pred.get("confidence") if isinstance(pred, dict) else pred.get("probs")
                    report["findings"].append({
                        "issue": f"Pattern {m} at {pth}",
                        "detail": pth,
                        "predicted_severity": apply_confidence_downgrade(predicted, conf),
                        "confidence": conf
                    })

    # dedupe findings
    seen = set()
    deduped = []
    for f in report["findings"]:
        key = (f.get("issue"), str(f.get("detail")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    report["findings"] = deduped
    return report

def save_report(report, path=ROOT / "reports" / "scan_report.json"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"✅ Report saved to {path}")

# ----------------- CLI entry -----------------
def main():
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    if not target:
        print("No target provided. Exiting.")
        return
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "https://" + target
    parsed = urlparse(target)
    print(f"Scanning {target} (host={parsed.netloc}) ...")
    if parsed.netloc.split(":")[0].lower() in DOMAIN_WHITELIST:
        print(f"[WHITELIST] {parsed.netloc} is in whitelist; noisy heuristics will be reduced.")
    report = passive_scan(target, timeout=10)
    save_report(report)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
