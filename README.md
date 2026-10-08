# 🛡️ Abhedhya Security & Repository Evaluator (Section 2B)

An enterprise-grade, automated vulnerability assessment and marksheet grading platform designed for hackathons, code reviews, and live security audits.

![Abhedhya Security Banner](static/abedhya-logo.jpeg)

---

## 🌟 Key Features

- **⚡ Fast Multi-Tier Pipeline:**
  1. **Git Engine:** Shallow clone with private repo token support and depth-1 optimization.
  2. **Secret Scanner:** Gitleaks integration + built-in regex pattern hunter (AWS keys, GitHub PATs, JWT tokens, Stripe, SSH keys).
  3. **Dependency CVE Auditor:** OSV-Scanner integration + fallback manifest auditor for `package.json` and `requirements.txt`.
  4. **SAST Engine:** Deep static code analysis detecting Command Injection, SQLi, NoSQLi, RCE (`eval`), Insecure Cookies, and Broken Access Control.
  5. **Live DAST Scanner:** Nuclei integration + HTTP security headers and sensitive file exposure inspector (`.git`, `.env`).
- **🌐 Internet & Multi-Device Access:**
  - Accessible on any network (4G, 5G, Wi-Fi, remote locations) without port forwarding.
  - Built-in one-click **Cloudflare Tunnel** / public URL generation.
- **📊 Marksheet & Persistence:**
  - SQLite persistent storage for all evaluated teams.
  - Automatic letter grade calculation (`A+`, `A`, `B`, `C`, `F`) and configurable max marks (`3.0`, `5.0`, `10.0`, `100%`).
  - 1-Click **Download Marksheet CSV** and printable reports.
- **🚀 Cloud & Docker Ready:**
  - Includes `Dockerfile`, `docker-compose.yml`, `render.yaml`, and `Procfile`.

---

## 🚀 Quick Start (Local)

### 1. Prerequisites
- Python 3.9+
- Git

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Evaluator Server
```bash
python evaluator_server.py
```
Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 🌐 Running Across Other Devices & Networks

To allow other judges, students, or devices to access the evaluator without being connected to the same Wi-Fi network:

### Method A: Start with `--tunnel` Flag
```bash
python evaluator_server.py --tunnel
```
The server will automatically generate a secure public HTTPS URL (e.g. `https://xxxx.trycloudflare.com`) that works on any phone or laptop anywhere in the world!

### Method B: Activate via Web Dashboard
1. Open the dashboard.
2. Go to the **🌐 Multi-Device Access** tab.
3. Click **"Enable Public Link"**.

---

## 🐳 Docker Deployment

Run anywhere with a single command:
```bash
docker-compose up --build
```
The evaluator will be available on `http://localhost:5000`.

---

## ☁️ 1-Click Free Cloud Deployment (Render / Railway)

1. Push this repository to GitHub (see steps below).
2. Go to [Render.com](https://render.com) or [Railway.app](https://railway.app).
3. Connect your GitHub repository.
4. Render will automatically detect `render.yaml` and deploy your live public evaluator!

---

## 📤 How to Push to GitHub

To push this project to your GitHub account:

```bash
# 1. Initialize Git (if not already done)
git init

# 2. Stage all files
git add .

# 3. Commit
git commit -m "feat: Initial commit of Abhedhya Security Evaluator platform"

# 4. Create a new repository on GitHub (e.g. github.com/username/security-evaluator)
# 5. Link and push:
git branch -M main
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>.git
git push -u origin main
```

---

## 📁 Project Structure

```
├── evaluator_server.py    # Main Flask server and REST API
├── engine/
│   ├── database.py        # SQLite persistence & history queries
│   ├── scanner.py         # Multi-threaded pipeline orchestrator
│   ├── sast.py            # Static application security testing
│   ├── secrets.py         # Secret detection engine
│   ├── dependencies.py    # Dependency vulnerability analyzer
│   ├── dast.py            # Live web vulnerability inspector
│   ├── scorer.py          # Scoring and grading logic
│   └── tunnel.py          # Internet tunnel manager
├── templates/
│   └── index.html         # Cyberpunk dark mode dashboard
├── static/
│   └── abedhya-logo.jpeg  # Official club branding logo
├── Dockerfile             # Container definition
├── docker-compose.yml     # Multi-container orchestrator
├── requirements.txt       # Python dependencies
├── render.yaml            # Render cloud deployment config
├── Procfile               # WSGI process runner
└── README.md              # Documentation
```

---

## ⚖️ License
Built for the **Abhedhya / BuildSecure** Section 2B Hackathon Evaluation.
