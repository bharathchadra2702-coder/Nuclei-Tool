import os
import sys
import time
import base64
import stat
import shutil
import subprocess
from engine.sast import run_sast_scan
from engine.secrets import run_secrets_scan
from engine.dependencies import run_dependencies_scan
from engine.dast import run_dast_scan
from engine.scorer import calculate_score
from engine.database import save_evaluation

def safe_rmtree(path):
    if not path or not os.path.exists(path):
        return
    def _onerror(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    try:
        shutil.rmtree(path, onerror=_onerror, ignore_errors=True)
    except Exception:
        pass

def perform_evaluation(team_name, target, max_score=3.0):
    """
    Executes complete security pipeline on a repo or live target.
    """
    clean_team = "".join(c for c in team_name if c.isalnum() or c in ("-", "_")) or "Team"
    scan_id = f"{clean_team}_{int(time.time() * 1000)}"
    temp_dir = os.path.abspath(f"./temp_eval_{scan_id}")
    results_dir = os.path.abspath(f"./results_eval_{scan_id}")
    os.makedirs(results_dir, exist_ok=True)

    is_git = "github.com" in target.lower() or target.lower().endswith(".git") or (not target.startswith("http://") and not target.startswith("https://") and "/" in target)
    target_type = "Repository" if is_git else "Live Web App"
    start_time = time.monotonic()
    findings = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    try:
        if is_git:
            # 1. Git Clone
            git_target = target if target.startswith("http://") or target.startswith("https://") else f"https://github.com/{target}"
            clone_cmd = ["git", "clone", "--depth", "1", "--single-branch", git_target, temp_dir]
            clone_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
            github_token = os.environ.get("GITHUB_TOKEN", "").strip()
            if github_token:
                basic_auth = base64.b64encode(f"x-access-token:{github_token}".encode("utf-8")).decode("ascii")
                clone_env["GIT_CONFIG_COUNT"] = "1"
                clone_env["GIT_CONFIG_KEY_0"] = "http.https://github.com/.extraheader"
                clone_env["GIT_CONFIG_VALUE_0"] = f"AUTHORIZATION: basic {basic_auth}"

            try:
                clone_res = subprocess.run(
                    clone_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                    stdin=subprocess.DEVNULL, env=clone_env, timeout=30.0, check=False
                )
            except subprocess.TimeoutExpired:
                return {
                    "id": scan_id,
                    "team_name": team_name,
                    "target_url": target,
                    "target_type": target_type,
                    "status": "FAILED",
                    "error": "Git clone timed out after 30 seconds. Verify repository URL.",
                    "score": 0.0,
                    "max_score": max_score,
                    "grade": "F",
                    "duration": round(time.monotonic() - start_time, 1),
                    "severity": severity_counts,
                    "findings": []
                }

            if clone_res.returncode != 0:
                err_msg = (clone_res.stderr or "Git clone failed").strip()[:200]
                return {
                    "id": scan_id,
                    "team_name": team_name,
                    "target_url": target,
                    "target_type": target_type,
                    "status": "FAILED",
                    "error": f"Failed to access repository: {err_msg}",
                    "score": 0.0,
                    "max_score": max_score,
                    "grade": "F",
                    "duration": round(time.monotonic() - start_time, 1),
                    "severity": severity_counts,
                    "findings": []
                }

            # 2. Secret Scan
            sec_findings = run_secrets_scan(temp_dir, results_dir, timeout=12.0)
            findings.extend(sec_findings)

            # 3. Dependency CVE Scan
            dep_findings = run_dependencies_scan(temp_dir, results_dir, timeout=15.0)
            findings.extend(dep_findings)

            # 4. SAST Code Scan
            sast_findings = run_sast_scan(temp_dir)
            findings.extend(sast_findings)

        else:
            # Live DAST Web URL Scan
            dast_findings = run_dast_scan(target, results_dir, timeout=15.0)
            findings.extend(dast_findings)

        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["low"] += 1

        final_score, grade = calculate_score(severity_counts, max_score=max_score)
        duration = round(time.monotonic() - start_time, 1)

        result_payload = {
            "id": scan_id,
            "team_name": team_name,
            "target_url": target,
            "target_type": target_type,
            "score": final_score,
            "max_score": max_score,
            "grade": grade,
            "status": "SUCCESS",
            "duration": duration,
            "severity": severity_counts,
            "findings": findings,
            "message": "Evaluation completed successfully."
        }

        # Save to SQLite Database
        save_evaluation(result_payload)
        return result_payload

    except Exception as exc:
        duration = round(time.monotonic() - start_time, 1)
        return {
            "id": scan_id,
            "team_name": team_name,
            "target_url": target,
            "target_type": target_type,
            "status": "FAILED",
            "error": str(exc),
            "score": 0.0,
            "max_score": max_score,
            "grade": "F",
            "duration": duration,
            "severity": severity_counts,
            "findings": []
        }
    finally:
        if is_git:
            safe_rmtree(temp_dir)
        safe_rmtree(results_dir)
