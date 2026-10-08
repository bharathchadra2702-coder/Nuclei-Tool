"""
BuildSecure / Abhedhya CLI Repository Evaluator (Section 2B)
"""
import sys
import argparse
from engine.scanner import perform_evaluation

def main():
    parser = argparse.ArgumentParser(description="Abhedhya Security Evaluator CLI")
    parser.add_argument("--repo", required=True, help="Target GitHub Repo URL or Live Web App URL")
    parser.add_argument("--team", default="Team_Evaluation", help="Team Identifier or Name")
    parser.add_argument("--max", type=float, default=3.0, help="Max Score (default: 3.0)")
    args = parser.parse_args()

    print("=" * 70)
    print(f"  [+] ABHEDHYA SECURITY EVALUATION: {args.team}")
    print(f"  Target: {args.repo}")
    print(f"  Max Marks: {args.max}")
    print("=" * 70)

    print("\n[*] Running Security Scanning Pipeline (Git -> Secrets -> CVEs -> SAST)...")
    res = perform_evaluation(team_name=args.team, target=args.repo, max_score=args.max)

    if res.get("status") == "FAILED":
        print(f"\n[!] Evaluation Failed: {res.get('error')}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("  EVALUATION SCORECARD")
    print("=" * 70)
    print(f"  Team Name   : {res['team_name']}")
    print(f"  Final Score : {res['score']} / {res['max_score']}")
    print(f"  Grade       : {res['grade']}")
    print(f"  Duration    : {res['duration']}s")
    print(f"  Critical    : {res['severity']['critical']} (penalty: -1.5 each)")
    print(f"  High        : {res['severity']['high']} (penalty: -1.0 each)")
    print(f"  Medium      : {res['severity']['medium']} (penalty: -0.5 each)")
    print(f"  Low         : {res['severity']['low']} (penalty: -0.2 each)")
    print("=" * 70)

    findings = res.get("findings", [])
    if findings:
        print(f"\n[!] Identified {len(findings)} Security Findings:")
        for idx, f in enumerate(findings[:15], 1):
            print(f"  [{idx}] [{f['severity'].upper()}] {f['name']}")
            print(f"      Location: {f['matched']}")
            if f.get("snippet"):
                print(f"      Snippet : {f['snippet']}")
            if f.get("remediation"):
                print(f"      Fix     : {f['remediation']}")
            print()
        if len(findings) > 15:
            print(f"  ... and {len(findings) - 15} more findings recorded in database.")
    else:
        print("\n[+] Clean scan: 0 security findings identified. Full marks awarded!")

if __name__ == "__main__":
    main()
