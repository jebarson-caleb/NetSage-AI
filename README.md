# NetSage AI

**Cisco Packet Tracer — Editorial Network Intelligence.** Evidence-first AI troubleshooting for Packet Tracer labs: 30 deterministic rule checks, Groq-powered reasoning (Llama 3.3 70B), and a mandatory human-in-the-loop workflow before any remediation ships.

> Editorial × Cybersecurity × AI · Monochrome, grid, and type — no neon, no matrix.

## Features

- **Deterministic Rule Engine (30 checks)** — `engine/rule_checker.py` catches duplicate IPs, wrong masks, missing `encapsulation dot1Q`, un-encapsulated subinterfaces, missing routes, and destructive commands with literal CLI evidence.
- **Groq Native Reasoning** — `llama-3.3-70b-versatile` / `llama-3.1-8b-instant` via `https://api.groq.com/openai/v1/chat/completions`, strict JSON schema, verbatim `evidence_citations`, and automatic fallback to the local CCIE Expert Reasoner when offline.
- **Interactive Workbench** — Web UI presets for 6 common labs (Router-on-a-Stick, OSPF Multi-Area, DHCP Relay, NAT/PAT Overload, Port Security Err-Disabled, Extended ACL DNS block) + quick-insert for 8 `show` commands and topology context.
- **Human-in-the-Loop Review** — `Accepted` / `Edited` / `Rejected` state machine in `engine/human_review.py`, reviewer audit trail at `logs/review_audit_trail.json`, and guardrails that intercept `reload`, `erase startup-config`, `format`, `delete`.
- **Responsible AI Log** — 7 documented incidents where AI advice was corrected (e.g., preventing unnecessary reloads, inverted wildcard masks, stripping security ACLs) at `logs/responsible_ai_log.{md,json}`.
- **Editorial Dashboard** — Monochrome grid, oversized type (`clamp()`), thin 1px borders, responsive analytics (Chart.js doughnut/bar/pie), filterable case table, and copy-pasteable IOS fixes with rollback.
- **CLI** — `cli.py` offers `--chat`, `--run-all`, `--case NET-001`, and `--stats` with Groq key/model flags.

## Tech Stack

| Layer | Technology | Version / Detail |
|-------|------------|------------------|
| Frontend | Vanilla HTML / CSS / JS (no framework) | SPA with CSS variables, `Space Grotesk` + `Inter` + `JetBrains Mono`, Chart.js 4 via CDN |
| Backend | Python `http.server` + `ThreadingMixIn` | Zero required pip deps, `web/server.py` serves REST + static |
| AI | Groq Cloud API + Local CCIE Expert | `llama-3.3-70b-versatile` default, fallback `ccie-local-expert` |
| Engine | Deterministic + AI Orchestrator | `engine/ai_engine.py`, `engine/rule_checker.py`, `engine/simulator.py` |
| Data | JSON / CSV | `data/cases.json` (35 cases), `data/cases.csv`, `logs/review_audit_trail.json` |
| Package Manager | pip (optional) | `pandas`, `matplotlib`, `requests`, `httpx` are optional |
| Build / Test | No build step | `python -m unittest discover -s tests` (17 tests) |

## Installation

```bash
git clone https://github.com/jebarson-caleb/NetSage-AI.git
cd NetSage-AI

# Optional: create venv (server runs with stdlib only)
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate

# Optional extras for notebooks/analysis only
pip install -r requirements.txt
```

## Environment Variables

Copy the template and set your keys:

```bash
copy .env.example .env   # Windows
# cp .env.example .env   # Linux/macOS
```

`.env.example`:

```
GROQ_API_KEY=gsk_your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
NETSAGE_PROVIDER=groq   # groq | local | gemini | openai
# GEMINI_API_KEY=...
# OPENAI_API_KEY=...
PORT=8000
```

- `GROQ_API_KEY` — free at https://console.groq.com/keys
- `GROQ_MODEL` — any Groq model (default `llama-3.3-70b-versatile`)
- `NETSAGE_PROVIDER` — routing for `DiagnosticEngine` (legacy `NETSAGE_PROVIDER` still honored)
- `PORT` — web server port

The web UI also stores `netsage_provider`, `netsage_groq_model`, `netsage_groq_api_key`, and `netsage_reviewer` in `localStorage` (with fallback to legacy `netsage_*` keys).

## Development

```bash
# Run the web server (zero pip deps required)
python web/server.py
# → http://localhost:8000

# Custom port
python web/server.py 3000
```

API endpoints served by `web/server.py`:
`GET /api/health`, `/api/cases`, `/api/cases/<id>`, `/api/presets`, `/api/stats`, `/api/reviews`, `/api/responsible-ai-log`, `/api/groq-status`, `/api/export/csv` · `POST /api/diagnose`, `/api/chat`, `/api/rule-check`, `/api/review`

## Build

No build step — static assets are served directly from `web/static/`. For verification:

```bash
python -m unittest discover -s tests   # 17 tests
python -m py_compile web/server.py engine/*.py cli.py
```

## Usage

**Web — 5-minute walkthrough**
1. Open `http://localhost:8000` → hero + workbench.
2. Click preset **Router-on-a-Stick: Missing 802.1Q Encapsulation** → watch deterministic flag `VLAN_TRUNK_MISMATCH` + verbatim CLI citation + IOS fix (`encapsulation dot1Q 20` on `G0/0.0.20`).
3. Click **Submit to Human Review** → choose Accept/Edit/Reject, add notes, save to audit trail.
4. Visit **Responsible AI Log** → inspect 7 corrected incidents; **Overview & Analytics** → OSI layer / severity charts.

**CLI**

```bash
python cli.py --chat                         # interactive local-first assistant
python cli.py --run-all --no-llm              # deterministic offline batch run
python cli.py --case NET-001                  # human-readable diagnosis
python cli.py --case NET-001 --json --no-llm  # automation-friendly diagnosis
python cli.py --run-all --json --no-llm       # structured batch report
python cli.py --case NET-001 --provider groq --model llama-3.3-70b-versatile --groq-key gsk_...
python cli.py --stats --json
```

## Project Structure

```
NetSage AI/
├── data/
│   ├── cases.json                 # 35 structured Packet Tracer cases
│   ├── cases.csv                  # CSV export
│   └── build_dataset.py
├── prompts/
│   ├── packet_tracer_assistant_prompt.md
│   ├── diagnose_prompt.md
│   ├── system_prompt.md
│   ├── helper_prompts.md
│   └── few_shot_examples.json
├── engine/
│   ├── ai_engine.py               # Hybrid orchestrator (Groq + Local CCIE)
│   ├── rule_checker.py            # 30-rule deterministic engine
│   ├── human_review.py            # Review manager + guardrails
│   └── simulator.py               # Cisco terminal simulator
├── web/
│   ├── server.py                  # Threaded REST API + static server
│   └── static/
│       ├── index.html             # Editorial SPA (monochrome, grid, clamp)
│       ├── css/style.css          # Design tokens, editorial nav/hero/footer
│       └── js/app.js              # Vanilla JS controller, Chart.js
├── logs/
│   ├── responsible_ai_log.md
│   ├── responsible_ai_log.json
│   └── review_audit_trail.json
├── tests/
│   ├── test_rule_checker.py
│   └── test_diagnostic_flow.py
├── cli.py
├── requirements.txt
└── README.md
```
