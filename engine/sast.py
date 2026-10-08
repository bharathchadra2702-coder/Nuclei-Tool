import os
import re

SAST_RULES = [
    {
        "id": "eval-rce",
        "category": "Code Injection / RCE",
        "name": "Dangerous Code Execution via eval/Function/exec",
        "severity": "critical",
        "pattern": re.compile(r'\b(eval|Function|exec)\s*\([^)]*(?:req\.|params|query|body|input|argv|data)', re.IGNORECASE),
        "exts": (".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".rb"),
        "remediation": "Avoid dynamic code evaluation. Use structured parsers or safe evaluation libraries."
    },
    {
        "id": "cmd-injection",
        "category": "Command Injection",
        "name": "Unsanitized OS Command Execution",
        "severity": "critical",
        "pattern": re.compile(r'(?:child_process\.(?:exec|execSync|spawn|spawnSync)|os\.system|subprocess\.(?:Popen|run|call|check_output)|system\(|passthru\()\s*\([^)]*(?:\+|%|\.format|`|\$\{)', re.IGNORECASE),
        "exts": (".js", ".ts", ".py", ".php", ".rb", ".go"),
        "remediation": "Never concatenate user input into shell commands. Use argument lists with shell=False or parameterized execution."
    },
    {
        "id": "sql-injection-concat",
        "category": "SQL Injection",
        "name": "SQL Query Formed via String Concatenation",
        "severity": "critical",
        "pattern": re.compile(r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+.*[\'\"]\s*\+\s*(?:req\.|params|query|body|user|input|id)|db\.query\s*\([^)]*\+\s*(?:req\.|params|query)', re.IGNORECASE),
        "exts": (".js", ".ts", ".py", ".php", ".java", ".go"),
        "remediation": "Use parameterized queries, prepared statements, or an ORM (e.g. Prisma, SQLAlchemy, Sequelize)."
    },
    {
        "id": "nosql-injection",
        "category": "NoSQL Injection",
        "name": "NoSQL $where / Unsanitized Mongo Operator",
        "severity": "high",
        "pattern": re.compile(r'\$where\s*:\s*|\.(?:find|findOne|update)\s*\(\s*(?:req\.body|req\.query|params)', re.IGNORECASE),
        "exts": (".js", ".ts", ".py"),
        "remediation": "Sanitize query objects using mongo-sanitize or validate schemas with Zod/Joi."
    },
    {
        "id": "hardcoded-jwt-secret",
        "category": "Broken Authentication",
        "name": "Hardcoded JWT Secret Key",
        "severity": "high",
        "pattern": re.compile(r'(?:jwt\.sign|jwt\.verify|jwt\.decode)\s*\([^)]*[\'\"][a-zA-Z0-9_\-\@\#\$]{4,}[\'\"]', re.IGNORECASE),
        "exts": (".js", ".ts", ".py", ".go", ".php"),
        "remediation": "Load cryptographic keys and JWT secrets from environment variables (process.env.JWT_SECRET)."
    },
    {
        "id": "insecure-cookie",
        "category": "Session Security",
        "name": "Insecure Cookie Configuration (Missing httpOnly/secure)",
        "severity": "medium",
        "pattern": re.compile(r'httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*[\'\"]none[\'\"]', re.IGNORECASE),
        "exts": (".js", ".ts", ".json", ".py"),
        "remediation": "Set httpOnly: true, secure: true, and sameSite: 'lax' or 'strict' on session cookies."
    },
    {
        "id": "disabled-tls",
        "category": "Cryptographic Flaws",
        "name": "Disabled SSL / TLS Certificate Validation",
        "severity": "high",
        "pattern": re.compile(r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'\"]?0[\'\"]?|rejectUnauthorized\s*:\s*false|verify\s*=\s*False', re.IGNORECASE),
        "exts": (".js", ".ts", ".env", ".json", ".py"),
        "remediation": "Never disable certificate validation in production. Ensure trusted CA certificates are installed."
    },
    {
        "id": "path-traversal",
        "category": "Path Traversal",
        "name": "Unsanitized File System Access",
        "severity": "high",
        "pattern": re.compile(r'(?:fs\.readFile|fs\.readFileSync|res\.sendFile|open\()\s*\([^)]*(?:req\.params|req\.query|req\.body|request\.)', re.IGNORECASE),
        "exts": (".js", ".ts", ".py"),
        "remediation": "Use path.basename() or safe path resolution (e.g. path.resolve with a root boundary check)."
    },
    {
        "id": "dom-xss",
        "category": "Cross-Site Scripting (XSS)",
        "name": "Dangerous DOM Manipulation (innerHTML / dangerouslySetInnerHTML)",
        "severity": "high",
        "pattern": re.compile(r'dangerouslySetInnerHTML\s*=|innerHTML\s*=\s*(?:req\.|params|user|input|props\.)|\bv-html\s*=', re.IGNORECASE),
        "exts": (".js", ".jsx", ".ts", ".tsx", ".vue", ".html"),
        "remediation": "Sanitize HTML using DOMPurify before injection or use safe textContent / JSX bindings."
    },
    {
        "id": "cors-wildcard",
        "category": "CORS Misconfiguration",
        "name": "Permissive Wildcard CORS with Credentials",
        "severity": "medium",
        "pattern": re.compile(r'origin\s*:\s*[\'\"]\*[\'\"]|Access-Control-Allow-Origin\s*[\'\"]\s*,\s*[\'\"]\*[\'\"]', re.IGNORECASE),
        "exts": (".js", ".ts", ".py", ".go"),
        "remediation": "Specify explicit allowed origins instead of wildcard '*'."
    },
    {
        "id": "weak-hash",
        "category": "Cryptographic Flaws",
        "name": "Use of Weak Hashing Algorithm (MD5 / SHA-1)",
        "severity": "medium",
        "pattern": re.compile(r'crypto\.createHash\([\'\"](?:md5|sha1)[\'\"]\)|hashlib\.(?:md5|sha1)\(', re.IGNORECASE),
        "exts": (".js", ".ts", ".py", ".java"),
        "remediation": "Use SHA-256 or bcrypt/argon2 for passwords and secure signatures."
    }
]

IGNORED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".idea", ".vscode"}

def run_sast_scan(target_dir, max_findings=60):
    findings = []
    if not os.path.isdir(target_dir):
        return findings

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            file_path = os.path.join(root, f)
            rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")

            for rule in SAST_RULES:
                if not rule["exts"] or ext in rule["exts"]:
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                            for idx, line in enumerate(fh, 1):
                                if rule["pattern"].search(line):
                                    snippet = line.strip()
                                    if len(snippet) > 120:
                                        snippet = snippet[:117] + "..."
                                    findings.append({
                                        "name": f"SAST: {rule['name']}",
                                        "category": rule["category"],
                                        "severity": rule["severity"],
                                        "matched": f"{rel_path}:{idx}",
                                        "snippet": snippet,
                                        "remediation": rule["remediation"],
                                        "tool": "SAST Engine"
                                    })
                                    if len(findings) >= max_findings:
                                        return findings
                    except Exception:
                        pass
    return findings
