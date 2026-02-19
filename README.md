<p align="center">
  <img src="https://img.shields.io/badge/HACK_KRMU_5.0-FINALIST-gold?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Team-BUG_SLAYERS-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Track-Cybersecurity-blue?style=for-the-badge" />
</p>

<h1 align="center">🛡️ CROSURE — Attack-Chain Vulnerability Scanner</h1>

<p align="center">
  <b>AI-Augmented Web Vulnerability Scanner with Multi-Step Attack Chain Discovery</b><br/>
  <i>Goes beyond single-finding scanners — discovers how vulnerabilities chain together into real-world attack paths</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Ollama-LLM-black?logo=ollama" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/ChromaDB-Vector_Store-orange" />
</p>

---

## 📌 Problem Statement

Traditional vulnerability scanners (Nikto, ZAP, Burp) report **individual findings in isolation**. A medium-severity XSS and a low-severity information leak might each seem minor — but **chained together**, they become a critical account takeover.

**Crosure** solves this by:
1. Scanning for vulnerabilities across 12 attack categories
2. Modeling inter-vulnerability relationships as a **directed attack graph**
3. Discovering **multi-step attack chains** that represent realistic exploitation paths
4. Using **AI for remediation guidance** and **vector-based knowledge matching** from a community exploit database

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         CROSURE ARCHITECTURE                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐    WebSocket     ┌──────────────────────────────┐  │
│  │   React UI  │◄────────────────►│     FastAPI Backend          │  │
│  │  Cytoscape  │    REST API      │                              │  │
│  │  Zustand    │◄────────────────►│  ┌────────────────────────┐  │  │
│  │  Tailwind   │                  │  │    Scan Orchestrator    │  │  │
│  └─────────────┘                  │  │                        │  │  │
│                                   │  │  Crawl ──► Detect ───┐ │  │  │
│                                   │  │                      │ │  │  │
│                                   │  │  Chain ◄── Dedup ◄───┘ │  │  │
│                                   │  │    │                   │  │  │
│                                   │  │    ▼                   │  │  │
│                                   │  │  AI Triage & Remediate │  │  │
│                                   │  └────────────────────────┘  │  │
│                                   │                              │  │
│  ┌─────────────┐                  │  ┌────────┐  ┌───────────┐  │  │
│  │  Ollama LLM │◄────────────────►│  │ChromaDB│  │PostgreSQL │  │  │
│  │  (dolphin-  │   AI Prompts     │  │Vectors │  │   ORM     │  │  │
│  │   mistral)  │                  │  └────────┘  └───────────┘  │  │
│  └─────────────┘                  └──────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │              12 Detection Plugins (Async)                    │    │
│  │  SQLi │ XSS │ SSTI │ CSTI │ RCE │ BOLA │ BAC │ Auth/Sess  │    │
│  │  Misconfig │ CORS │ OAST │ Emerging Threats                 │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Scan Pipeline — How It Works

```
Target URL
    │
    ▼
┌─────────────────────────────────────┐
│  PHASE 1: INTELLIGENT CRAWLING      │
│  • Playwright headless browser       │
│  • JavaScript-rendered page discovery│
│  • Form, API endpoint, dynamic       │
│    route extraction                  │
│  • Technology stack fingerprinting   │
│  Output: Endpoint list + tech stack  │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  PHASE 2: VULNERABILITY DETECTION    │
│  • 12 async plugins run concurrently │
│  • Each endpoint tested against all  │
│    applicable attack vectors         │
│  • Pattern matching, timing analysis,│
│    error-based & behavioral detection│
│  • Deduplication by (URL, type, param)│
│  Output: Unique vulnerability list   │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  PHASE 3: ATTACK CHAIN DISCOVERY     │
│  • Map vulns to attack primitives    │
│    (info_disclosure → auth_bypass →  │
│     data_access → code_exec)         │
│  • Build directed graph (NetworkX)   │
│  • Transition rules define valid     │
│    chaining relationships            │
│  • Query KB for known chain patterns │
│  • Score chains with severity ×      │
│    transition boost × KB match       │
│  Output: Ranked attack chains        │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  PHASE 4: AI ANALYSIS                │
│  • LLM-powered remediation for       │
│    high/critical findings            │
│  • Context-aware fix suggestions     │
│  • Severity validation               │
│  Output: Remediation guidance        │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  PHASE 5: RESULTS & VISUALIZATION    │
│  • Real-time WebSocket progress      │
│  • Interactive findings table        │
│  • Cytoscape.js attack chain graph   │
│  • Severity distribution dashboard   │
│  • One-click remediation panel       │
└─────────────────────────────────────┘
```

---

## ⚡ Key Features

### 🕷️ Intelligent Crawling
- **Playwright headless browser** — renders JavaScript SPAs, unlike traditional crawlers
- Extracts forms, API endpoints, query parameters, and dynamic routes
- Technology stack fingerprinting (detects Express, Django, React, Angular, etc.)
- Handles authentication via cookie injection

### 🔍 12 Vulnerability Detection Plugins
| Plugin | Attack Type | Detection Method |
|--------|------------|-----------------|
| **SQLi** | SQL Injection | Error-based + time-based blind |
| **XSS** | Cross-Site Scripting | Reflected payload detection |
| **SSTI** | Server-Side Template Injection | Math expression evaluation |
| **CSTI** | Client-Side Template Injection | Angular/Vue expression injection |
| **RCE** | Remote Code Execution | Command injection + response analysis |
| **BOLA** | Broken Object-Level Auth | ID enumeration + access patterns |
| **BAC** | Broken Access Control | Privilege escalation testing |
| **Auth/Session** | Authentication Flaws | Session handling, token analysis |
| **Misconfig** | Security Misconfiguration | Header analysis, debug endpoint detection |
| **CORS** | CORS Misconfiguration | Origin reflection + credential exposure |
| **OAST** | Out-of-Band Testing | DNS/HTTP callback detection |
| **Emerging** | Emerging Threats | Prototype pollution, WebSocket hijacking, GraphQL introspection |

### 🔗 Attack Chain Graph Engine
- **Attack primitives**: Maps each vulnerability to its exploitation capability (info_disclosure, auth_bypass, session_hijack, data_access, privilege_escalation, code_exec)
- **Transition rules**: Defines valid chaining relationships (e.g., XSS → session_hijack → auth_bypass → data_access)
- **Directed graph construction** using NetworkX with automated path discovery
- **KB-boosted scoring**: Chains matching known exploitation patterns from the knowledge base receive a 1.3x score boost
- **Chain classification**: Automatically categorizes as privilege_escalation, data_breach, full_compromise, or auth_bypass

### 🧠 AI-Augmented Analysis
- **Ollama LLM integration** (dolphin-mistral 7B) for context-aware remediation
- Per-vulnerability fix guidance with code examples
- Fallback remediation library for offline operation (XSS, SQLi, CSRF, SSRF, IDOR, etc.)
- LLM-powered document parsing for uploaded exploit files

### 📚 Community Knowledge Base
- **PostgreSQL** storage for exploits, attack chains, tags, and uploaded files
- **ChromaDB vector store** with `all-MiniLM-L6-v2` sentence embeddings
- Semantic search across exploits and chain patterns
- Upload & parse exploit documents (Markdown, Python, YAML, JSON)
- Chain pattern matching to boost discovery of known exploitation sequences

### 🖥️ Real-Time UI
- **WebSocket** live scan progress with phase indicators
- **Cytoscape.js** interactive chain visualization
- **Glassmorphism** dark theme with metallic accents
- Severity distribution charts and dashboard analytics
- One-click remediation panel with AI-generated fix guidance

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 18 + Vite 6 | Component-based UI with HMR |
| **State** | Zustand | Lightweight reactive store |
| **Styling** | Tailwind CSS | Utility-first dark theme |
| **Graphs** | Cytoscape.js + Dagre | Attack chain visualization |
| **Backend** | FastAPI + Uvicorn | Async Python API server |
| **ORM** | SQLAlchemy 2.0 (async) + asyncpg | PostgreSQL async access |
| **Crawler** | Playwright | JS-rendered headless crawling |
| **Chain Engine** | NetworkX 3.4 | Directed graph algorithms |
| **Vector DB** | ChromaDB 0.5.0 | Semantic similarity search |
| **LLM** | Ollama + dolphin-mistral | AI remediation & parsing |
| **Database** | PostgreSQL 16 | Persistent structured storage |
| **Infra** | Docker Compose (5 services) | One-command deployment |

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 8 GB+ RAM (for Ollama LLM)
- macOS / Linux

### Setup

```bash
# Clone the repository
git clone https://github.com/<your-username>/crosure.git
cd crosure

# Start all services (backend, frontend, db, llm, test target)
docker compose up -d --build

# Pull the LLM model (one-time, ~4 GB)
docker compose exec ollama ollama pull dolphin-mistral

# Open the scanner
open http://localhost:5173
```

### Seed the Knowledge Base (Optional)

```bash
# Upload exploit documents
curl -X POST http://localhost:8000/api/kb/upload \
  -F "file=@exploits/sqli_union.md" \
  -F "title=SQL Injection Union Attack"
```

### Run a Scan

1. Enter target URL (e.g., `http://testphp.vulnweb.com`)
2. Click **Start Scan**
3. Watch real-time progress via WebSocket
4. View findings, chains, and dashboard

---

## 📁 Project Structure

```
crosure/
├── docker-compose.yml          # 5-service orchestration
├── backend/                    # Python 3.11 FastAPI server
│   ├── main.py                 # App entrypoint + CORS + lifespan
│   ├── config.py               # Environment configuration
│   ├── api/
│   │   ├── routes_scan.py      # Sync & async scan endpoints
│   │   ├── routes_findings.py  # Remediation & triage API
│   │   ├── routes_kb.py        # Knowledge base CRUD + upload
│   │   └── ws.py               # WebSocket broadcast hub
│   ├── core/
│   │   ├── models.py           # Pydantic schemas & enums
│   │   └── orchestrator.py     # 5-phase scan pipeline
│   ├── crawler/
│   │   └── playwright_crawler.py  # Headless browser crawling
│   ├── plugins/                # 12 async detection plugins
│   │   ├── base.py             # Abstract plugin interface
│   │   ├── sqli.py             # SQL Injection detection
│   │   ├── xss.py              # Cross-Site Scripting
│   │   ├── ssti.py             # Server-Side Template Injection
│   │   ├── csti.py             # Client-Side Template Injection
│   │   ├── rce.py              # Remote Code Execution
│   │   ├── bola.py             # Broken Object-Level Auth
│   │   ├── bac.py              # Broken Access Control
│   │   ├── auth_session.py     # Auth & Session analysis
│   │   ├── misconfig.py        # Security misconfiguration
│   │   ├── cors.py             # CORS testing
│   │   ├── oast.py             # Out-of-band testing
│   │   └── emerging.py         # Prototype pollution, GraphQL, WS
│   ├── chains/
│   │   ├── graph_engine.py     # NetworkX chain builder
│   │   └── primitives.py       # Attack primitives & transitions
│   ├── kb/
│   │   ├── database.py         # SQLAlchemy ORM models
│   │   ├── embeddings.py       # ChromaDB vector operations
│   │   └── parser.py           # LLM + regex document parser
│   └── llm/
│       └── ollama_client.py    # Ollama API wrapper
├── frontend/                   # React 18 + Vite SPA
│   └── src/
│       ├── App.jsx             # Root + WebSocket connection
│       ├── store.js            # Zustand state management
│       ├── api.js              # Axios + WS client
│       └── components/
│           ├── ScanControl.jsx     # Scan trigger + async polling
│           ├── ScanProgress.jsx    # Real-time progress bar
│           ├── ScanTab.jsx         # Findings view + remediation
│           ├── FindingsTable.jsx   # Sortable vulnerability table
│           ├── RemediationPanel.jsx # AI fix suggestions
│           ├── ChainGraphTab.jsx   # Cytoscape chain visualization
│           ├── KnowledgeBaseTab.jsx # KB explorer + upload
│           ├── DashboardTab.jsx    # Analytics dashboard
│           └── Header.jsx         # Navigation + status
└── seed_data/                  # Sample exploit documents
```

---

## 📊 Performance

Tested against real-world vulnerable applications:

| Target | Endpoints | Findings | Chains | Duration |
|--------|-----------|----------|--------|----------|
| OWASP Juice Shop | 25+ | 323 | 20 | ~78s |
| testphp.vulnweb.com | 58 | 430+ | 20 | ~115s |

---

## 📄 Research References

Crosure's architecture and optimization strategies are informed by the following research:

1. **Cascaded Vulnerability Attacks in Software Supply Chains** (arXiv, Jan 2026)
   — Link prediction for multi-CVE chains in SBOMs. Informed our approach to modeling inter-vulnerability dependencies as directed graphs with transition-rule-based edge construction.

2. **Savant: Semantic-Guided Reachability in Dependencies** (arXiv, Jun 2025)
   — High-precision vulnerable API usage detection via semantic code analysis. Guided our design of the ChromaDB semantic search layer for vulnerability-to-exploit knowledge matching.

3. **APPATCH / Logs-to-Patches** (USENIX Security 2025)
   — Tree-of-thought + iterative refinement for vulnerability repair. Influences our LLM-powered remediation pipeline architecture (prompt design & structured output).

4. **VulnResolver / VRpilot** (arXiv & AIware 2024–2025)
   — Agentic LLM workflows for patch generation + validation feedback loops. Informs our iterative AI triage system with confidence scoring.

5. **OWASP Testing Guide v5** & **NIST SP 800-115** (Technical Guide to Information Security Testing)
   — Standard vulnerability classification and testing methodology. Our 12 plugins align with OWASP Top 10 & NIST penetration testing guidelines.

---

## 🗺️ What's Next

Our focus heading into the finals is **performance optimization & hardening**:

- ⚡ Scan engine parallelism — run plugins concurrently with adaptive concurrency limits
- 🧠 Smarter deduplication — reduce noise by merging similar findings across plugins
- 📉 Memory & CPU profiling — optimize chain graph construction for large attack surfaces
- 🔒 False-positive reduction — tighten detection heuristics with stricter response analysis
- 📊 Scan result persistence — write findings to PostgreSQL for history & diff comparison
- 🚀 Faster cold starts — slim Docker images, pre-warmed browser pools

---

## 🧪 Testing

```bash
# Scan OWASP Juice Shop (included in Docker Compose)
# Target: http://juice-shop:3000 (internal) or http://localhost:3000 (external)

# Scan Acunetix test site
# Target: http://testphp.vulnweb.com

# API test
curl -X POST http://localhost:8000/api/scan/async \
  -H 'Content-Type: application/json' \
  -d '{"target_url": "http://testphp.vulnweb.com"}'
```

---

## 👥 Team — BUG SLAYERS

| Member | Role |
|--------|------|
| **Atul Kumar** | Lead Developer & Architecture |
| **Ashish Singh** | Backend & Security Research |
| **Palak** | Frontend & UI/UX |
| **Akshita Jha** | Testing & Documentation |

---

## 📜 License

Built for **HACK KRMU 5.0** — Cybersecurity Track

---

<p align="center">
  <b>Crosure</b> — <i>Because vulnerabilities don't attack alone.</i>
</p>
