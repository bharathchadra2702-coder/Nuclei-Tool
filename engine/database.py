import os
import sqlite3
import json
import time

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evaluations.db"))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Ensure table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evaluations (
            id TEXT PRIMARY KEY,
            team_name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            target_type TEXT NOT NULL,
            score REAL NOT NULL,
            max_score REAL NOT NULL,
            grade TEXT NOT NULL,
            status TEXT NOT NULL,
            duration REAL NOT NULL,
            severity_critical INTEGER DEFAULT 0,
            severity_high INTEGER DEFAULT 0,
            severity_medium INTEGER DEFAULT 0,
            severity_low INTEGER DEFAULT 0,
            severity_info INTEGER DEFAULT 0,
            findings_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn

def init_db():
    conn = get_db()
    conn.close()

def save_evaluation(eval_data):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO evaluations (
            id, team_name, target_url, target_type, score, max_score,
            grade, status, duration, severity_critical, severity_high,
            severity_medium, severity_low, severity_info, findings_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        eval_data["id"],
        eval_data["team_name"],
        eval_data["target_url"],
        eval_data["target_type"],
        eval_data["score"],
        eval_data["max_score"],
        eval_data["grade"],
        eval_data["status"],
        eval_data["duration"],
        eval_data["severity"].get("critical", 0),
        eval_data["severity"].get("high", 0),
        eval_data["severity"].get("medium", 0),
        eval_data["severity"].get("low", 0),
        eval_data["severity"].get("info", 0),
        json.dumps(eval_data.get("findings", []))
    ))
    conn.commit()
    conn.close()

def get_all_evaluations(limit=100):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, team_name, target_url, target_type, score, max_score,
               grade, status, duration, severity_critical, severity_high,
               severity_medium, severity_low, severity_info, findings_json, created_at
        FROM evaluations
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "team_name": r["team_name"],
            "target_url": r["target_url"],
            "target_type": r["target_type"],
            "score": r["score"],
            "max_score": r["max_score"],
            "grade": r["grade"],
            "status": r["status"],
            "duration": r["duration"],
            "severity": {
                "critical": r["severity_critical"],
                "high": r["severity_high"],
                "medium": r["severity_medium"],
                "low": r["severity_low"],
                "info": r["severity_info"]
            },
            "findings_count": len(json.loads(r["findings_json"] or "[]")),
            "created_at": r["created_at"]
        })
    conn.close()
    return results

def get_evaluation_by_id(eval_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM evaluations WHERE id = ?
    """, (eval_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    res = {
        "id": row["id"],
        "team_name": row["team_name"],
        "target_url": row["target_url"],
        "target_type": row["target_type"],
        "score": row["score"],
        "max_score": row["max_score"],
        "grade": row["grade"],
        "status": row["status"],
        "duration": row["duration"],
        "severity": {
            "critical": row["severity_critical"],
            "high": row["severity_high"],
            "medium": row["severity_medium"],
            "low": row["severity_low"],
            "info": row["severity_info"]
        },
        "findings": json.loads(row["findings_json"] or "[]"),
        "created_at": row["created_at"]
    }
    conn.close()
    return res

def delete_evaluation(eval_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM evaluations WHERE id = ?", (eval_id,))
    conn.commit()
    conn.close()
    return True

def clear_all_evaluations():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM evaluations")
    conn.commit()
    conn.close()
