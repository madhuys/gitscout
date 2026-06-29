# 🛡️ GitScout

> **Real-Time GitHub Secret Reconnaissance & Security Intelligence Platform**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![Storage Engine](https://img.shields.io/badge/engine-DuckDB-yellow.svg)](https://duckdb.org)
[![UI Framework](https://img.shields.io/badge/frontend-React%20%2B%20AG%20Grid-61dafb.svg)](https://react.dev)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**GitScout** is a high-throughput, autonomous security reconnaissance platform that passively intercepts real-time GitHub event feeds (`PushEvent` and `PullRequestEvent`). Designed for security engineers, threat intelligence teams, and researchers, GitScout automatically identifies accidentally committed credentials, API keys, private certificates, and database connection strings before they can be exploited.

---

## 🚀 Architectural Overview

GitScout v1.0.0 is a comprehensive security reconnaissance suite featuring high-speed stream processing, embedded database analysis, concurrent analytics, and an interactive React dashboard.

```
                  ┌───────────────────────────────┐
                  │   GitHub Events REST API      │
                  └──────────────┬────────────────┘
                                 │ ETag Conditional Polling
                                 ▼
                  ┌───────────────────────────────┐
                  │      GitScout Engine          │
                  │       (gitscout.py)           │
                  └──────┬─────────────────┬──────┘
                         │                 │
     SQLite DB Binaries  │                 │ Text Content (code/env)
                         ▼                 ▼
                  ┌──────────────┐  ┌──────────────┐
                  │ SQLite Parser│  │ Regex Engine │ 250+ Patterns
                  └──────┬───────┘  └──────┬───────┘
                         │                 │
                         └────────┬────────┘
                                  │ High-Signal Findings
                                  ▼
                  ┌───────────────────────────────┐
                  │     DuckDB Analytics Engine   │
                  │   (WAL Isolated Snapshots)    │
                  └──────┬─────────────────┬──────┘
                         │                 │
                         ▼                 ▼
             ┌─────────────────────┐   ┌─────────────────────┐
             │  React Web UI (8765)│   │   CLI Query & Reports│
             └─────────────────────┘   └─────────────────────┘
```

---

## 🌟 Key Features

* 📡 **Passive Telemetry Interception**: Polls global GitHub public event streams with strict rate-limit management and ETag header caching to maximize efficiency.
* 🔍 **250+ High-Signal Regex Signatures**: Context-aware signature matching across Cloud Providers (AWS, GCP, Azure), LLMs & AI platforms (OpenAI, Anthropic, Groq, Cohere), Financial & Crypto APIs, SMTP, JWT, and SSH keys.
* 🗄️ **Deep SQLite DB Inspection**: Automatically detects committed `.db` SQLite binaries, creates isolated temporary environments, and inspects internal table schemas and rows for unencrypted credentials.
* ⚡ **High-Performance Analytics Store**: Built on top of **DuckDB** with thread-safe Write-Ahead Logging (WAL) snapshot mirrors, allowing concurrent real-time background ingestion alongside frontend analytics queries.
* 💻 **Modern Web Dashboard**: Features a sleek, dark-mode React application (`ui/react-app`) with AG Grid integration, server-side full-text search, live status cards, multi-column sorting, and instant CSV exporting.
* 📊 **Vulnerability Reporting**: Built-in CLI query utility (`query_findings.py`) and automated markdown report generator (`generate_report.py`) for threat intelligence pipelines.

---

## 🛠️ Installation & Setup

### Prerequisites

* Python 3.10+
* Node.js 18+ (Optional, only required if rebuilding the frontend)

### 1. Clone & Install Dependencies

```bash
git clone <your-repository-url> && cd GitScout
pip3 install -r requirements.txt
```

### 2. Configure GitHub Access Token

Provide a GitHub Personal Access Token (PAT) to increase API rate limits from 60 req/hr to 5,000 req/hr:

```bash
export GITHUB_ACCESS_TOKEN="your_personal_access_token"
```

*Optionally, create a local `.env` file (which is gitignored):*
```env
GITHUB_ACCESS_TOKEN=ghp_your_token_here
```

---

## 💻 Operating GitScout

### 1. Launch the Secret Scanner

Run the core event listener directly or via the convenience shell wrapper:

```bash
python3 gitscout.py
# OR
./run.sh
```

### 2. Start the Findings Web UI

Launch the built-in HTTP server to access the live analytics dashboard:

```bash
python3 findings_server.py --port 8765
```
Open your browser to **`http://127.0.0.1:8765`**.

### 3. Query Findings via CLI

Use the command-line query utility to quickly inspect findings in your terminal:

```bash
# View summary statistics by secret type
python3 query_findings.py summary

# Inspect high-signal findings (API keys, connection strings, private keys)
python3 query_findings.py interesting --limit 50
```

### 4. Generate Security Reports

Generate an executive markdown summary of high-value exposures:

```bash
python3 generate_report.py
```

---

## 📁 Repository Structure

```
GitScout/
├── bin/                 # Executable runner scripts
│   ├── run.sh           # Main scanner execution script
│   └── build_ui.sh      # React dashboard compilation script
├── docs/                # Documentation & audit report archive
│   ├── FINDINGS_SUMMARY.md
│   ├── FINDINGS_REPORT.md
│   ├── FINDINGS.md
│   └── KEY_COVERAGE.md
├── scout/               # Core Python package engine
│   ├── constants.py     # Scanner thresholds, ANSI formatting, & path resolvers
│   ├── github_api.py    # GitHub REST API client, ETag polling, & stream fetchers
│   ├── detector.py      # Regex pattern engine & SQLite DB inspector
│   ├── db.py            # DuckDB engine & thread-safe WAL snapshot layer
│   ├── patterns.py      # 250+ signature definitions & provider classifications
│   ├── logger.py        # Findings loggers for DuckDB & JSONL exports
│   ├── processor.py     # Event processing workflows & ASCII banner
│   ├── server.py        # Web HTTP API server & static asset host
│   ├── query.py         # CLI query interface for DuckDB findings
│   └── reporter.py      # Executive markdown security report generator
├── ui/                  # Web Dashboards
│   ├── static/          # Single-file HTML dashboard fallback
│   └── react-app/       # Modern React + AG Grid dashboard application
├── gitscout.py          # Main CLI scanner entrypoint
├── findings_server.py   # Web server CLI entrypoint wrapper
├── query_findings.py    # CLI query entrypoint wrapper
├── generate_report.py   # Security report entrypoint wrapper
├── run.sh               # Root runner forwarder script
├── build_ui.sh          # Root UI build forwarder script
└── requirements.txt     # Python dependencies (requests, duckdb)
```

---

## 🔒 Security & Responsible Disclosure

* **Data Sensitivity**: Discovered findings may contain active production credentials. Ensure all generated `.duckdb` files, `.jsonl` exports, and report summaries are stored securely and excluded from version control.
* **Ethical Usage**: GitScout is designed strictly for authorized defensive security monitoring, internal auditing, and threat research. Never use discovered credentials to perform unauthorized access or testing.

---

## 👤 Author & Maintainer

* **Developer**: [@madhuys](https://github.com/madhuys)
* **GitHub**: [github.com/madhuys](https://github.com/madhuys)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
