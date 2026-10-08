import os
import json
import shutil
import subprocess

KNOWN_VULNERABLE_PACKAGES = {
    "lodash": {"max_safe": "4.17.21", "cve": "CVE-2021-23337", "summary": "Prototype Pollution in lodash"},
    "jsonwebtoken": {"max_safe": "9.0.0", "cve": "CVE-2022-23529", "summary": "Insecure key verification in jsonwebtoken"},
    "axios": {"max_safe": "0.21.2", "cve": "CVE-2021-3749", "summary": "Regular Expression Denial of Service in axios"},
    "minimist": {"max_safe": "1.2.6", "cve": "CVE-2021-44906", "summary": "Prototype Pollution in minimist"},
    "express": {"max_safe": "4.17.3", "cve": "CVE-2022-24999", "summary": "qs vulnerability in Express"},
    "qs": {"max_safe": "6.9.7", "cve": "CVE-2022-24999", "summary": "Prototype Pollution in qs"},
    "node-serialize": {"max_safe": "0.0.0", "cve": "CVE-2017-5941", "summary": "Arbitrary Code Execution via untrusted deserialization"},
    "marked": {"max_safe": "4.0.10", "cve": "CVE-2022-21680", "summary": "ReDoS in marked markdown parser"},
    "socket.io": {"max_safe": "4.6.1", "cve": "CVE-2022-2421", "summary": "Uncaught Exception in socket.io-parser"},
    "mongoose": {"max_safe": "5.13.15", "cve": "CVE-2022-2564", "summary": "Prototype Pollution in mongoose"},
    "urllib3": {"max_safe": "1.26.18", "cve": "CVE-2023-45803", "summary": "Request body strip on redirect in urllib3"},
    "requests": {"max_safe": "2.31.0", "cve": "CVE-2023-32681", "summary": "Unintended Proxy-Authorization header leak in requests"}
}

def run_dependencies_scan(target_dir, results_dir, timeout=15.0):
    findings = []
    osv_bin = shutil.which("osv-scanner")

    if osv_bin:
        osv_out = os.path.join(results_dir, "osv.json")
        try:
            subprocess.run(
                [osv_bin, "scan", "--format", "json", "--output", osv_out, "-r", target_dir],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                stdin=subprocess.DEVNULL, timeout=timeout, check=False
            )
            if os.path.exists(osv_out) and os.path.getsize(osv_out) > 0:
                with open(osv_out, "r", encoding="utf-8", errors="replace") as of:
                    osv_data = json.load(of)
                    for res in osv_data.get("results", []):
                        pkg_path = res.get("source", {}).get("path", "")
                        rel_pkg = os.path.relpath(pkg_path, target_dir).replace("\\", "/") if os.path.isabs(pkg_path) else pkg_path
                        for pkg in res.get("packages", []):
                            pname = pkg.get("package", {}).get("name", "pkg")
                            pver = pkg.get("package", {}).get("version", "")
                            vulns = pkg.get("vulnerabilities", [])
                            for vuln in vulns[:2]:
                                vid = vuln.get("id", "Advisory")
                                summary = vuln.get("summary") or f"Vulnerable dependency {pname}@{pver}"
                                findings.append({
                                    "name": f"Dependency CVE ({vid}): {summary[:90]}",
                                    "category": "Known Vulnerable Dependency",
                                    "severity": "high",
                                    "matched": f"{rel_pkg} ({pname}@{pver})",
                                    "snippet": f"Package {pname} version {pver} has known security advisory {vid}",
                                    "remediation": f"Upgrade {pname} to the latest stable patched release.",
                                    "tool": "OSV-Scanner"
                                })
                if findings:
                    return findings
        except Exception:
            pass

    # Fallback manifest inspector for package.json and requirements.txt
    for root, _, files in os.walk(target_dir):
        if "package.json" in files and "node_modules" not in root:
            pkg_json_path = os.path.join(root, "package.json")
            rel_path = os.path.relpath(pkg_json_path, target_dir).replace("\\", "/")
            try:
                with open(pkg_json_path, "r", encoding="utf-8", errors="replace") as pf:
                    data = json.load(pf)
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    for dep_name, dep_ver in deps.items():
                        clean_name = dep_name.lower().strip()
                        if clean_name in KNOWN_VULNERABLE_PACKAGES:
                            vuln_info = KNOWN_VULNERABLE_PACKAGES[clean_name]
                            findings.append({
                                "name": f"Dependency Advisory: {vuln_info['summary']}",
                                "category": "Known Vulnerable Dependency",
                                "severity": "high",
                                "matched": f"{rel_path} ({dep_name}: {dep_ver})",
                                "snippet": f"Found {dep_name}@{dep_ver} (Known CVE: {vuln_info['cve']})",
                                "remediation": f"Upgrade {dep_name} to >= {vuln_info['max_safe']}.",
                                "tool": "Dependency Auditor"
                            })
            except Exception:
                pass

        if "requirements.txt" in files and ".venv" not in root:
            req_path = os.path.join(root, "requirements.txt")
            rel_path = os.path.relpath(req_path, target_dir).replace("\\", "/")
            try:
                with open(req_path, "r", encoding="utf-8", errors="replace") as rf:
                    for line in rf:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            pkg_part = line.split("==")[0].split(">=")[0].split("<=")[0].strip().lower()
                            if pkg_part in KNOWN_VULNERABLE_PACKAGES:
                                vuln_info = KNOWN_VULNERABLE_PACKAGES[pkg_part]
                                findings.append({
                                    "name": f"Python Dependency Advisory: {vuln_info['summary']}",
                                    "category": "Known Vulnerable Dependency",
                                    "severity": "high",
                                    "matched": f"{rel_path} ({line})",
                                    "snippet": f"Found {line} (Advisory {vuln_info['cve']})",
                                    "remediation": f"Upgrade {pkg_part} to >= {vuln_info['max_safe']}.",
                                    "tool": "Dependency Auditor"
                                })
            except Exception:
                pass

    return findings
