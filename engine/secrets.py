import os
import re
import json
import shutil
import subprocess

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "severity": "critical"
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?:aws_secret_access_key|aws_key|secret_key)\s*[:=]\s*[\'\"]([0-9a-zA-Z/+]{40})[\'\"]', re.IGNORECASE),
        "severity": "critical"
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b'),
        "severity": "critical"
    },
    {
        "name": "RSA / OpenSSH Private Key Block",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
        "severity": "critical"
    },
    {
        "name": "Generic Hardcoded API Secret / Password",
        "pattern": re.compile(r'(?:api_key|apikey|secret_token|db_password|access_token)\s*[:=]\s*[\'\"]([a-zA-Z0-9_\-\.]{12,64})[\'\"]', re.IGNORECASE),
        "severity": "high"
    },
    {
        "name": "Stripe Live API Key",
        "pattern": re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,34})\b'),
        "severity": "critical"
    },
    {
        "name": "Slack Webhook URL",
        "pattern": re.compile(r'https://hooks\.slack\.com/services/T[0-9a-zA-Z_]{8}/B[0-9a-zA-Z_]{8}/[0-9a-zA-Z_]{24}'),
        "severity": "high"
    }
]

IGNORED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}

def run_secrets_scan(target_dir, results_dir, timeout=12.0):
    findings = []
    gitleaks_bin = shutil.which("gitleaks")

    if gitleaks_bin:
        gitleaks_out = os.path.join(results_dir, "gitleaks.json")
        try:
            subprocess.run(
                [gitleaks_bin, "detect", "--source", target_dir, "--report-format", "json", "--report-path", gitleaks_out, "--no-banner"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                stdin=subprocess.DEVNULL, timeout=timeout, check=False
            )
            if os.path.exists(gitleaks_out) and os.path.getsize(gitleaks_out) > 0:
                with open(gitleaks_out, "r", encoding="utf-8", errors="replace") as gf:
                    items = json.load(gf)
                    for item in items:
                        rule_id = item.get("RuleID", "Secret Exposure")
                        file_path = (item.get("File") or "").replace("\\", "/")
                        line = item.get("StartLine", 1)
                        is_priv = "key" in rule_id.lower() or "private" in rule_id.lower() or "aws" in rule_id.lower()
                        findings.append({
                            "name": f"Secret Exposure: {item.get('Description', rule_id)}",
                            "category": "Hardcoded Credentials",
                            "severity": "critical" if is_priv else "high",
                            "matched": f"{file_path}:{line}",
                            "snippet": item.get("Secret", "")[:40] + ("..." if len(item.get("Secret", "")) > 40 else ""),
                            "remediation": "Revoke this leaked credential immediately and store it in environment variables or a secrets manager.",
                            "tool": "Gitleaks"
                        })
                return findings
        except Exception:
            pass

    # Fallback Python regex scanner if gitleaks binary is unavailable
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for f in files:
            file_path = os.path.join(root, f)
            rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                    for idx, line in enumerate(fh, 1):
                        for sp in SECRET_PATTERNS:
                            m = sp["pattern"].search(line)
                            if m:
                                snippet = line.strip()
                                if len(snippet) > 80:
                                    snippet = snippet[:77] + "..."
                                findings.append({
                                    "name": f"Secret Exposure: {sp['name']}",
                                    "category": "Hardcoded Credentials",
                                    "severity": sp["severity"],
                                    "matched": f"{rel_path}:{idx}",
                                    "snippet": snippet,
                                    "remediation": "Remove secret from repository history and store in environment variables.",
                                    "tool": "Secret Hunter (Built-in)"
                                })
                                if len(findings) >= 30:
                                    return findings
            except Exception:
                pass

    return findings
