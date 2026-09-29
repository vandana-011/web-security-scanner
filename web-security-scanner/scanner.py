import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
]

DIRECTORIES = ["admin", "backup", "uploads", "config", "login", "test", "db", "data"]

SQL_PAYLOADS = ["'", '"', "' OR '1'='1", "' OR 1=1--", '" OR ""="']

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-",
]

XSS_PAYLOAD = "<script>alert('XSS')</script>"


def check_availability(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        return {"status": response.status_code, "available": response.status_code < 500}
    except requests.exceptions.ConnectionError:
        return {"status": None, "available": False, "error": "Could not connect to the URL."}
    except requests.exceptions.Timeout:
        return {"status": None, "available": False, "error": "Connection timed out."}
    except Exception as e:
        return {"status": None, "available": False, "error": str(e)}


def check_headers(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        present = [h for h in SECURITY_HEADERS if h in headers]
        return {"missing": missing, "present": present}
    except Exception as e:
        return {"missing": [], "present": [], "error": str(e)}


def check_sql_injection(url):
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return {"vulnerable": False, "note": "No URL parameters found to test."}

        vulnerabilities = []
        for payload in SQL_PAYLOADS:
            test_url = url + payload
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                body = response.text.lower()
                for error in SQL_ERRORS:
                    if error in body:
                        vulnerabilities.append({"payload": payload, "error_matched": error})
                        break
            except Exception:
                continue

        return {
            "vulnerable": len(vulnerabilities) > 0,
            "details": vulnerabilities,
        }
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


def check_xss(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return {"vulnerable": False, "note": "No forms found on the page."}

        vulnerabilities = []
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            target = urljoin(url, action)

            inputs = form.find_all("input")
            data = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    data[name] = XSS_PAYLOAD

            try:
                if method == "post":
                    resp = requests.post(target, data=data, timeout=10, verify=False)
                else:
                    resp = requests.get(target, params=data, timeout=10, verify=False)

                if XSS_PAYLOAD in resp.text:
                    vulnerabilities.append({"form_action": action, "method": method})
            except Exception:
                continue

        return {
            "vulnerable": len(vulnerabilities) > 0,
            "details": vulnerabilities,
        }
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


def scan_directories(url):
    found = []
    base = url.rstrip("/")
    for directory in DIRECTORIES:
        target = f"{base}/{directory}"
        try:
            response = requests.get(target, timeout=8, verify=False)
            if response.status_code == 200:
                found.append(target)
        except Exception:
            continue
    return {"found": found}


def run_scan(url):
    results = {}

    results["availability"] = check_availability(url)
    if not results["availability"]["available"]:
        return results

    results["headers"] = check_headers(url)
    results["sql_injection"] = check_sql_injection(url)
    results["xss"] = check_xss(url)
    results["directories"] = scan_directories(url)

    # Compute overall risk level
    high = 0
    medium = 0
    low = 0

    if results["sql_injection"].get("vulnerable"):
        high += 1
    if results["xss"].get("vulnerable"):
        high += 1
    if results["directories"]["found"]:
        medium += len(results["directories"]["found"])
    if results["headers"]["missing"]:
        medium += len(results["headers"]["missing"])

    if high > 0:
        risk = "HIGH"
    elif medium >= 3:
        risk = "MEDIUM"
    elif medium > 0:
        risk = "LOW"
    else:
        risk = "SAFE"

    results["risk_level"] = risk
    results["counts"] = {"high": high, "medium": medium, "low": low}

    save_report(url, results)
    return results


def save_report(url, results):
    lines = [
        "=" * 50,
        "WEB APPLICATION SECURITY SCAN REPORT",
        "=" * 50,
        f"Target: {url}",
        f"Risk Level: {results.get('risk_level', 'N/A')}",
        "",
        "--- Security Headers ---",
    ]

    headers_data = results.get("headers", {})
    if headers_data.get("missing"):
        lines.append("Missing:")
        for h in headers_data["missing"]:
            lines.append(f"  - {h}")
    if headers_data.get("present"):
        lines.append("Present:")
        for h in headers_data["present"]:
            lines.append(f"  + {h}")

    lines += ["", "--- SQL Injection ---"]
    sqli = results.get("sql_injection", {})
    lines.append("Vulnerable: " + ("YES" if sqli.get("vulnerable") else "NO"))

    lines += ["", "--- XSS ---"]
    xss = results.get("xss", {})
    lines.append("Vulnerable: " + ("YES" if xss.get("vulnerable") else "NO"))

    lines += ["", "--- Open Directories ---"]
    dirs = results.get("directories", {}).get("found", [])
    if dirs:
        for d in dirs:
            lines.append(f"  - {d}")
    else:
        lines.append("  None found.")

    lines.append("=" * 50)

    with open("reports/scan_report.txt", "w") as f:
        f.write("\n".join(lines))
