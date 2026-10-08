"""
Abhedhya / BuildSecure - Section 2B Repository & Live Vulnerability Evaluator
Main Entrypoint
"""
import os
import sys
import argparse
from evaluator_server import app, tunnel_manager

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Abhedhya Security Evaluator")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--tunnel", action="store_true", default=True, help="Launch public tunnel for multi-device/internet access (default: True)")
    parser.add_argument("--local-only", action="store_true", help="Disable public internet tunnel and bind to local network only")
    args = parser.parse_args()

    tunnel_manager.port = args.port

    public_link = None
    if not args.local_only and args.tunnel:
        public_link = tunnel_manager.start_tunnel()

    local_ip = tunnel_manager.get_local_ip()
    print("\n" + "=" * 75)
    print("   ABHEDHYA / BUILDSECURE REPOSITORY & WEB SECURITY EVALUATOR")
    print("=" * 75)
    print(f"  [+] Local Dashboard  : http://localhost:{args.port}")
    print(f"  [+] LAN / Wi-Fi      : http://{local_ip}:{args.port}")
    if public_link:
        print("=" * 75)
        print(f"  [>>>] PUBLIC INTERNET URL (ANY NETWORK / ANY DEVICE):")
        print(f"        {public_link}")
        print("=" * 75)
    else:
        print("  [!] Public Tunnel: Not initialized. (Run with internet connection)")
    print("=" * 75 + "\n")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)
