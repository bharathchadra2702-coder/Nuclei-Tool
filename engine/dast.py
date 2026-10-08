import os
import json
import shutil
import subprocess
import requests

def run_dast_scan(target_url, results_dir, timeout=15.0):
    findings = []
    nuclei_bin = shutil.which("nuclei")

    if nuclei_bin:
        nuclei_out = os.path.join(results_dir, "nuclei.jsonl")
        cmd = [
            nuclei_bin, "-u", target_url, "-tags", "exposure,misconfig,cve,vulnerability,tech",
            "-c", "30", "-rate-limit", "100", "-timeout", "2", "-retries", "0",
            "-jsonl", "-o", nuclei_out, "-silent", "-duc", "-ni"
        ]
        try:
            subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                stdin=subprocess.DEVNULL, timeout=timeout, check=False
            )
            if os.path.exists(nuclei_out) and os.path.getsize(nuclei_out) > 0:
                with open(nuclei_out, "r", encoding="utf-8", errors="replace") as result_file:
                    for line in result_file:
                        if not line.strip():
                            continue
                        try:
                            obj = json.loads(line)
                            info = obj.get("info", {})
                            sev = str(info.get("severity", "low")).lower()
                            if sev not in ("critical", "high", "medium", "low", "info"):
                                sev = "low"
                            findings.append({
                                "name": f"Nuclei: {info.get('name', obj.get('template-id', 'Vulnerability'))}",
                                "category": "Live Web Vulnerability (DAST)",
                                "severity": sev,
                                "matched": obj.get("matched-at", target_url),
                                "snippet": info.get("description", "Matched live Nuclei security template.")[:120],
                                "remediation": "Apply vendor security patch or tighten server configuration.",
                                "tool": "Nuclei DAST"
                            })
                        except Exception:
                            continue
                if findings:
                    return findings
        except Exception:
            pass

    # Fast built-in HTTP Security Analyzer fallback
    try:
        url = target_url if target_url.startswith("http://") or target_url.startswith("https://") else f"https://{target_url}"
        resp = requests.get(url, timeout=5.0, verify=False, allow_redirects=True, headers={"User-Agent": "BuildSecure-Evaluator/2.0"})
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Missing Security Headers
        if "strict-transport-security" not in headers and url.startswith("https://"):
            findings.append({
                "name": "Missing Strict-Transport-Security (HSTS) Header",
                "category": "Security Header Misconfiguration",
                "severity": "medium",
                "matched": url,
                "snippet": "Server did not send HSTS header on HTTPS.",
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                "tool": "DAST Inspector"
            })

        if "content-security-policy" not in headers:
            findings.append({
                "name": "Missing Content-Security-Policy (CSP) Header",
                "category": "Security Header Misconfiguration",
                "severity": "medium",
                "matched": url,
                "snippet": "No Content-Security-Policy header defined to mitigate XSS.",
                "remediation": "Define a robust Content-Security-Policy to restrict script sources.",
                "tool": "DAST Inspector"
            })

        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append({
                "name": "Missing X-Frame-Options (Clickjacking Risk)",
                "category": "Clickjacking",
                "severity": "low",
                "matched": url,
                "snippet": "Page may be embedded in malicious iframes.",
                "remediation": "Set 'X-Frame-Options: SAMEORIGIN' or 'DENY'.",
                "tool": "DAST Inspector"
            })

        if "x-content-type-options" not in headers:
            findings.append({
                "name": "Missing X-Content-Type-Options Header",
                "category": "MIME Sniffing Risk",
                "severity": "low",
                "matched": url,
                "snippet": "Browser MIME-sniffing protection not enforced.",
                "remediation": "Set 'X-Content-Type-Options: nosniff'.",
                "tool": "DAST Inspector"
            })

        # 2. Check for exposed .git or .env
        base_url = url.rstrip("/")
        for sensitive_path in ["/.env", "/.git/HEAD", "/config.json"]:
            try:
                probe = requests.get(f"{base_url}{sensitive_path}", timeout=3.0, verify=False, allow_redirects=False)
                if probe.status_code == 200 and len(probe.text) > 0 and "<html" not in probe.text.lower():
                    findings.append({
                        "name": f"Sensitive File Exposure: {sensitive_path}",
                        "category": "Information Disclosure",
                        "severity": "critical",
                        "matched": f"{base_url}{sensitive_path}",
                        "snippet": probe.text[:60] + "...",
                        "remediation": f"Block public access to {sensitive_path} in your web server config.",
                        "tool": "DAST Inspector"
                    })
            except Exception:
                pass

    except Exception:
        pass

    return findings
