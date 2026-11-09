# CyberGuard AI 🛡️
> **Autonomous Conversational AI Agent for Authorized VAPT (Vulnerability Assessment & Penetration Testing)**

CyberGuard AI is an intelligent cybersecurity operations agent designed to guide security analysts and penetration testers through end-to-end assessments — from initial reconnaissance and service fingerprinting, through vulnerability scanning and cross-tool correlation, to generating client-ready executive VAPT reports in PDF format.

---

## 🎯 Key Capabilities & Security Reasoning

- **Autonomous Tool Selection**: Selects reconnaissance (Nmap), web application (OWASP ZAP), and server misconfiguration (Nikto) tools dynamically based on discovered assets.
- **Evidence Correlation**: Correlates multi-tool telemetry to eliminate false positives and formulate cross-vector attack chains.
- **Risk Prioritization**: Maps findings against CVSS v3.1 severity metrics and prioritizes remediation roadmaps.
- **Explainable Reasoning**: Explains *why* each scan or probe is recommended before execution.
- **Strict Security Boundaries**:
  - Validates all targets against organizer-provided CIDRs / hostnames.
  - Enforces explicit **Human-in-the-Loop Sign-Off** for any offensive proof-of-concept validation or active exploitation.
- **Client-Ready Deliverables**: Generates professional ReportLab PDF reports complete with executive summaries, vulnerability breakdown tables, and remediation steps.

---

## 🏗️ Technology Stack

| Component | Technology | Description |
|-----------|------------|-------------|
| **Frontend** | React.js (v18) | Single Page Application with real-time WebSocket chat and responsive UI |
| **Styling** | CSS / Bootstrap 5 | Cybersecurity dark theme (cyber-glow, SOC aesthetic) |
| **Backend** | Python + FastAPI | High-performance async API with WebSocket streaming |
| **AI Engine** | LLM API + Agent Engine | Function-calling reasoning engine with autonomous fallback |
| **Database** | SQLite + SQLAlchemy (aiosqlite) | Relational audit log of assessments, scans, findings, and reports |
| **Network Scanning** | Nmap (`python-nmap`) | Host discovery, port enumeration, service versioning, NSE scripts |
| **Web Scanning** | OWASP ZAP | Web crawler, active/passive vulnerability scanner (OWASP Top 10) |
| **Server Auditing** | Nikto | HTTP header auditing, dangerous methods, outdated banners |
| **PDF Reporting** | Python ReportLab | Client-ready VAPT report generator with two-pass canvas numbering |
| **Version Control** | Git + GitHub | Clean commit history and documentation |

---

## 📁 Project Architecture

```
cyberguard-ai/
├── backend/
│   ├── agent/
│   │   ├── engine.py              # Core SecurityAgent reasoning loop & tool dispatcher
│   │   ├── prompts.py             # Security prompts & correlation templates
│   │   └── tools.py               # Tool definitions & human approval rules
│   ├── routers/
│   │   ├── assessments.py         # Assessment CRUD & statistics
│   │   ├── chat.py                # WebSocket & REST conversational streaming
│   │   ├── scans.py               # Scans and findings management
│   │   └── reports.py             # PDF generation and download
│   ├── scanners/
│   │   ├── nmap_scanner.py        # Nmap wrapper with sandbox telemetry fallback
│   │   ├── zap_scanner.py         # OWASP ZAP REST wrapper
│   │   └── nikto_scanner.py       # Nikto CLI wrapper
│   ├── services/
│   │   ├── report_generator.py    # ReportLab PDF generator
│   │   └── vulnerability_db.py    # CVE & CVSS knowledge base
│   ├── config.py                  # Environment & safety boundaries
│   ├── database.py                # Async SQLite engine
│   ├── models.py                  # SQLAlchemy relational models
│   ├── schemas.py                 # Pydantic API schemas
│   ├── requirements.txt           # Python dependencies
│   ├── .env.example               # Environment variables template
│   └── main.py                    # FastAPI entrypoint
│
├── frontend/
│   ├── public/
│   │   └── index.html             # HTML template
│   ├── src/
│   │   ├── components/
│   │   │   ├── Chat/
│   │   │   │   ├── ChatContainer.js    # Interactive chat & findings view
│   │   │   │   ├── ChatMessage.js      # Markdown & syntax highlighted bubbles
│   │   │   │   ├── ToolCallCard.js     # Live tool execution cards
│   │   │   │   ├── ApprovalCard.js     # Human-in-the-loop sign-off prompt
│   │   │   │   └── QuickInfoPanel.js   # Live sidebar stats & scans
│   │   │   ├── Dashboard/
│   │   │   │   ├── Dashboard.js        # Assessment grid & metrics
│   │   │   │   ├── NewAssessmentModal.js # Modal to create target session
│   │   │   │   └── StatsChart.js       # Chart.js severity distribution
│   │   │   ├── Layout/
│   │   │   │   ├── Layout.js           # App shell
│   │   │   │   ├── Navbar.js           # Header with connection badge
│   │   │   │   └── Sidebar.js          # Navigation drawer
│   │   │   ├── Reports/
│   │   │   │   └── ReportView.js       # PDF preview & download manager
│   │   │   └── ScanResults/
│   │   │       ├── FindingsPanel.js    # Filterable findings dossier
│   │   │       └── FindingDetail.js    # Detailed finding triage modal
│   │   ├── services/
│   │   │   └── api.js                  # Axios client & WebSocket factory
│   │   ├── App.css                     # Dark-themed cyber styling
│   │   ├── App.js                      # React Router configuration
│   │   └── index.js                    # React bootstrap
│   └── package.json
│
├── .gitignore
└── README.md
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ & npm
- *(Optional)* Nmap, OWASP ZAP, Nikto for live environment tools

### 2. Backend Setup
```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
python main.py
```
The FastAPI backend will start at `http://localhost:8000` (docs at `http://localhost:8000/docs`).

### 3. Frontend Setup
```bash
cd frontend
npm install
npm start
```
The React frontend will open at `http://localhost:3000`.

---

## 🔒 Security Boundary Enforcement

All live scanning strictly requires target authorization:
- `ALLOWED_TARGETS` configures authorized sandbox targets (e.g., `127.0.0.1, localhost, scanme.nmap.org`).
- Any attempt to scan unauthorized IP/domain blocks is rejected immediately.
- Exploitation attempts require explicit human operator confirmation via `ApprovalCard`.
