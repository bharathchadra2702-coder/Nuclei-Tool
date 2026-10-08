import os
import sys
import io
import csv
import json
import argparse
from flask import Flask, request, jsonify, render_template, send_file, Response
from engine.database import init_db, get_all_evaluations, get_evaluation_by_id, delete_evaluation, clear_all_evaluations
from engine.scanner import perform_evaluation
from engine.tunnel import tunnel_manager

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["JSON_SORT_KEYS"] = False

# Initialize database
init_db()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/health", methods=["GET"])
def health():
    import shutil
    return jsonify({
        "status": "healthy",
        "tools": {
            "git": bool(shutil.which("git")),
            "gitleaks": bool(shutil.which("gitleaks")),
            "osv_scanner": bool(shutil.which("osv-scanner")),
            "nuclei": bool(shutil.which("nuclei")),
            "python_sast": True,
            "fallback_secrets": True,
            "fallback_deps": True
        }
    })

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    team_name = str(data.get("team", "Team_Unknown")).strip() or "Team_Unknown"
    target = str(data.get("target", "")).strip()
    try:
        max_score = float(data.get("max_score", 3.0))
    except (ValueError, TypeError):
        max_score = 3.0

    if not target:
        return jsonify({"error": "Target repository link or web application URL is required.", "status": "FAILED"}), 400

    result = perform_evaluation(team_name=team_name, target=target, max_score=max_score)
    if result.get("status") == "FAILED":
        return jsonify(result), 400

    return jsonify(result)

@app.route("/api/batch-scan", methods=["POST"])
def batch_scan():
    data = request.get_json(silent=True) or {}
    targets = data.get("targets", [])
    try:
        max_score = float(data.get("max_score", 3.0))
    except (ValueError, TypeError):
        max_score = 3.0

    if not targets or not isinstance(targets, list):
        return jsonify({"error": "List of targets is required."}), 400

    results = []
    for item in targets:
        team_name = str(item.get("team", "Team_Unknown")).strip() or "Team_Unknown"
        target = str(item.get("target", "")).strip()
        if not target:
            continue
        res = perform_evaluation(team_name=team_name, target=target, max_score=max_score)
        results.append(res)

    return jsonify({
        "total_scanned": len(results),
        "results": results
    })

@app.route("/api/history", methods=["GET"])
def history():
    limit = request.args.get("limit", 100, type=int)
    evals = get_all_evaluations(limit=limit)
    return jsonify(evals)

@app.route("/api/scan/<eval_id>", methods=["GET"])
def get_scan(eval_id):
    scan_record = get_evaluation_by_id(eval_id)
    if not scan_record:
        return jsonify({"error": "Evaluation not found"}), 404
    return jsonify(scan_record)

@app.route("/api/scan/<eval_id>", methods=["DELETE"])
def delete_scan(eval_id):
    delete_evaluation(eval_id)
    return jsonify({"success": True, "message": "Evaluation deleted"})

@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    evals = get_all_evaluations(limit=1000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Evaluation ID", "Team Name", "Target URL / Repo", "Type",
        "Score", "Max Marks", "Grade", "Status", "Duration (s)",
        "Critical Flaws", "High Flaws", "Medium Flaws", "Low Flaws",
        "Total Findings", "Evaluated At"
    ])

    for e in evals:
        writer.writerow([
            e["id"],
            e["team_name"],
            e["target_url"],
            e["target_type"],
            e["score"],
            e["max_score"],
            e["grade"],
            e["status"],
            e["duration"],
            e["severity"]["critical"],
            e["severity"]["high"],
            e["severity"]["medium"],
            e["severity"]["low"],
            e["findings_count"],
            e["created_at"]
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=BuildSecure_Evaluation_Marksheet.csv"}
    )

@app.route("/api/network-info", methods=["GET"])
def network_info():
    local_ip = tunnel_manager.get_local_ip()
    return jsonify({
        "local_ip": local_ip,
        "local_port": 5000,
        "local_url": f"http://{local_ip}:5000",
        "tunnel_active": tunnel_manager.is_running,
        "public_url": tunnel_manager.public_url
    })

@app.route("/api/tunnel/toggle", methods=["POST"])
def toggle_tunnel():
    data = request.get_json(silent=True) or {}
    enable = data.get("enable", True)
    if enable:
        pub_url = tunnel_manager.start_tunnel()
        return jsonify({"tunnel_active": True, "public_url": pub_url})
    else:
        tunnel_manager.stop_tunnel()
        return jsonify({"tunnel_active": False, "public_url": None})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BuildSecure Security Evaluator Server")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--tunnel", action="store_true", default=True, help="Automatically launch public internet Tunnel (default: True)")
    parser.add_argument("--local-only", action="store_true", help="Disable public internet tunnel")
    args = parser.parse_args()

    tunnel_manager.port = args.port

    public_link = None
    if not args.local_only and args.tunnel:
        public_link = tunnel_manager.start_tunnel()

    local_ip = tunnel_manager.get_local_ip()
    print("\n" + "=" * 75)
    print("   BUILDSECURE / ABHEDHYA SECURITY EVALUATOR PLATFORM")
    print("=" * 75)
    print(f"  [+] Local Access     : http://localhost:{args.port}")
    print(f"  [+] LAN / Wi-Fi      : http://{local_ip}:{args.port}")
    if public_link:
        print("=" * 75)
        print(f"  [>>>] PUBLIC INTERNET URL (ANY NETWORK / ANY DEVICE):")
        print(f"        {public_link}")
        print("=" * 75)
    else:
        print("  [i] Multi-Network    : Connect to internet or click 'Enable Public Link' in UI")
    print("=" * 75 + "\n")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)
