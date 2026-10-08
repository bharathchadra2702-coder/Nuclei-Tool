import os
import sys
import socket
import threading
import subprocess
import time
import re
import shutil

class TunnelManager:
    def __init__(self, port=5000):
        self.port = port
        self.public_url = None
        self.process = None
        self.is_running = False
        self.tunnel_type = None

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start_tunnel(self):
        """
        Launches public internet tunnel using pyngrok or cloudflared.
        Returns the public HTTPS URL.
        """
        if self.is_running and self.public_url:
            return self.public_url

        print("\n[*] Initializing public internet tunnel (Multi-Network Access)...")

        # 1. Try PyNgrok (Fastest & natively installed)
        try:
            from pyngrok import ngrok, conf
            ngrok_token = os.environ.get("NGROK_AUTHTOKEN", "").strip()
            if ngrok_token:
                ngrok.set_auth_token(ngrok_token)

            http_tunnel = ngrok.connect(self.port, "http")
            self.public_url = http_tunnel.public_url
            self.is_running = True
            self.tunnel_type = "ngrok"
            return self.public_url
        except Exception as ngrok_err:
            # If ngrok errored, proceed to Cloudflare
            pass

        # 2. Try Cloudflare Quick Tunnel (cloudflared)
        cf_bin = shutil.which("cloudflared")
        if cf_bin:
            try:
                self.process = subprocess.Popen(
                    [cf_bin, "tunnel", "--url", f"http://localhost:{self.port}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                self.is_running = True
                self.tunnel_type = "cloudflare"
                for line in self.process.stdout:
                    match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                    if match:
                        self.public_url = match.group(0)
                        return self.public_url
            except Exception:
                pass

        return self.public_url

    def stop_tunnel(self):
        if self.tunnel_type == "ngrok":
            try:
                from pyngrok import ngrok
                ngrok.kill()
            except Exception:
                pass
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass
        self.is_running = False
        self.public_url = None
        self.tunnel_type = None

tunnel_manager = TunnelManager(port=5000)
