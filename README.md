# 🛡️ Custom SAST Engine & DevSecOps Code Auditor

An enterprise-grade, lightweight Static Application Security Testing (SAST) engine built in Python. Designed to enforce **Shift-Left security** in modern CI/CD pipelines, this tool parses Abstract Syntax Trees (AST) and dynamic YAML-based regex rules to detect hardcoded secrets, unsafe code execution sinks, and SQL injection vulnerabilities before deployment.

Includes an interactive **Flask Web Dashboard** and native support for the **OASIS SARIF standard** for seamless integration with GitHub Code Scanning.

---

## 🚀 Key Features

- **AST Code Analysis:** Parses Python Abstract Syntax Trees (AST) to uncover complex vulnerabilities like unsafe dynamic execution (`eval`, `exec`) and string formatting SQL injection hazards.
- **Customizable YAML Rules Engine:** Decouples security logic into an easily extensible `rules.yaml` schema.
- **Interactive Web Dashboard:** Upload source files via a responsive, dark-themed Flask Web UI to inspect real-time security posture scores and line-by-line findings.
- **OASIS SARIF Export:** Generates industry-standard `.sarif` report files compatible with GitHub Security & Code Scanning tabs.
- **Automated CI/CD Quality Gates:** Returns non-zero exit codes (`sys.exit(1)`) on critical vulnerabilities to fail unsafe builds automatically.
- **Git Pre-Commit Hook:** Comes with an automated installer (`install_hook.sh`) to block vulnerable code directly on developers' local machines.

---

## 🏗️ Architecture & Project Structure

```text
project02_sast_engine/
├── core/
│   ├── __init__.py
│   ├── cli.py             # CLI Entrypoint for automated scans
│   └── sast_analyzer.py   # Core AST & Regex Scanning Engine
├── templates/
│   └── index.html         # Bootstrap Dark Theme Dashboard
├── test_targets/
│   └── vulnerable_sample.py # Sample targets for rule testing
├── app.py                 # Flask Web App Server
├── rules.yaml             # Configurable Detection Rules
├── install_hook.sh        # Pre-commit Security Gate Installer
├── requirements.txt       # Dependencies
└── Procfile               # Cloud Deployment Config (Render/Heroku)