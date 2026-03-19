<div align="center">

```
  ╔═══════════════════════════════════════════════════════╗
  ║                                                       ║
  ║    ✦  S W A R M H A W K   A I                        ║
  ║       Autonomous Offensive Security Platform          ║
  ║                                                       ║
  ╚═══════════════════════════════════════════════════════╝
```

**Autonomous external attack surface assessment.**
Recon → Exploit Detection → AI Synthesis → Report. One command.

[![Tests](https://github.com/swarmhawk-ai/swarmhawk/actions/workflows/test.yml/badge.svg)](https://github.com/swarmhawk-ai/swarmhawk/actions)
[![PyPI](https://img.shields.io/pypi/v/swarmhawk?color=blue)](https://pypi.org/project/swarmhawk/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

## What is SwarmHawk?

SwarmHawk is an **open-source CLI** that chains together subdomain enumeration, vulnerability scanning, CVE enrichment, and AI-powered report generation into a single autonomous pipeline — the kind of thing a senior pentester would spend days setting up manually.

```
Target domain
    ↓ Subdomain enumeration (subfinder)
    ↓ Live asset probing (httpx + IP enrichment)
    ↓ Vulnerability scanning (8,000+ Nuclei templates)
    ↓ 3-layer validation (syntactic → template quality → NVD/EPSS)
    ↓ AI synthesis (business impact + remediation via Claude/OpenAI)
    ↓ Professional HTML/PDF report
    ↓ Tamper-evident audit log (SHA-256 hash chain)
```

**No tools installed? No API keys?** Run `--mock` for a full demo with synthetic data in 10 seconds.

---

## Quickstart

```bash
pip install swarmhawk

# Demo — runs on any machine, no tools required
swarmhawk scan --target acme-corp.com --mock
```

Open `./reports/*.html` in your browser. That's it.

---

## Demo Output

```
  ╔═══════════════════════════════════════════════════════╗
  ║    ✦  S W A R M H A W K   A I  —  MVP v1.0.0         ║
  ╚═══════════════════════════════════════════════════════╝

  ──────────────────────────────────────────────────────
  PHASE 1  ▸  RECONNAISSANCE
  ──────────────────────────────────────────────────────
  09:14:01  ⬡  Enumerating subdomains...
  09:14:03  ✓  14 live assets discovered
             →  acme-corp.com          nginx/1.18
             →  api.acme-corp.com      Apache/2.4.51
             →  admin.acme-corp.com    PHP/8.1
             →  dev.acme-corp.com      (no server header)
             →  + 10 more...

  ──────────────────────────────────────────────────────
  PHASE 2  ▸  EXPLOIT DETECTION
  ──────────────────────────────────────────────────────
  09:14:08  ◈  Running vulnerability templates...
  09:14:22  ✓  6 findings validated  (2 critical, 2 high)

             [CRITICAL ] PHP CGI RCE (CVE-2024-4577)          CVSS 9.8
             [CRITICAL ] Apache Path Traversal RCE             CVSS 9.8
             [HIGH     ] Web Server Misconfiguration           CVSS 7.5
             [HIGH     ] Exposed Admin Panel                   CVSS 7.2
             [MEDIUM   ] Missing Security Headers              CVSS 5.3
             [LOW      ] Server Version Disclosure             CVSS 3.1

  ──────────────────────────────────────────────────────
  PHASE 3  ▸  AI SYNTHESIS
  ──────────────────────────────────────────────────────
  09:14:23  ✦  Enriching findings with business context...
  09:14:31  ✓  Executive summary generated

  ──────────────────────────────────────────────────────
  PHASE 4  ▸  REPORT GENERATION
  ──────────────────────────────────────────────────────

  ══════════════════════════════════════════════════════
    ✦  MISSION COMPLETE
  ══════════════════════════════════════════════════════

  Target:          acme-corp.com
  Assets scanned:  14
  Duration:        0m 31s
  Findings:        2 critical  2 high  2 other
  Audit chain:     ✓ VERIFIED

  Reports saved:
    →  HTML     reports/swarmhawk_acme-corp_com_20260319_091401.html
    →  JSON     reports/swarmhawk_acme-corp_com_20260319_091401_findings.json
    →  Audit    reports/swarmhawk_acme-corp_com_20260319_091401_audit.json
```

---

## Installation

### From PyPI (recommended)

```bash
pip install swarmhawk
```

### From source

```bash
git clone https://github.com/swarmhawk-ai/swarmhawk.git
cd swarmhawk
pip install -e .
```

### Optional: Real scanning (live mode)

Install [ProjectDiscovery](https://projectdiscovery.io/) tools for live scans against real targets:

```bash
# macOS
brew install subfinder httpx nuclei

# Linux / any platform with Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Without these tools, SwarmHawk automatically falls back to mock mode — useful for demos and CI pipelines.

### Optional: PDF reports

```bash
pip install "swarmhawk[pdf]"    # weasyprint
# or: sudo apt install wkhtmltopdf
```

### Optional: AI synthesis

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # Claude (recommended)
export OPENAI_API_KEY=sk-...          # OpenAI (fallback)
```

Without an API key, SwarmHawk uses high-quality template-based synthesis.

---

## Usage

### Scan a target

```bash
# Mock mode — demo with synthetic data, no tools required
swarmhawk scan --target acme-corp.com --mock

# Live scan — requires subfinder, httpx, nuclei
swarmhawk scan --target acme-corp.com

# Full production scan — scope file + AI + NVD enrichment
swarmhawk scan \
  --target acme-corp.com \
  --scope scopes/acme.json \
  --nvd-key $NVD_API_KEY \
  --output ./reports/acme-2026-q1
```

### Scope ledger (required for live scans)

The scope ledger is a SHA-256 signed JSON file that proves you have written authorization to scan a target. It's your legal protection.

```bash
# Create scope for a new engagement
swarmhawk scope new \
  --customer "ACME Corp" \
  --domain acme-corp.com \
  --authorized-by "Jane Smith, CISO" \
  --days 30

# Verify a scope ledger's integrity
swarmhawk scope verify --file scopes/acme_corp.json
```

### Audit log

Every action is recorded in a tamper-evident SQLite database with SHA-256 hash chaining. Any modification to the log is detectable.

```bash
swarmhawk audit --file reports/audit_acme_corp_com.db
```

---

## Output Files

| File | Description |
|------|-------------|
| `*.html` | Full security report — browser-ready, print to PDF |
| `*_findings.json` | Machine-readable findings — SIEM/ticketing integration |
| `*_audit.json` | Tamper-evident audit log export |
| `*.pdf` | PDF report (requires weasyprint or wkhtmltopdf) |

### Findings JSON schema

```json
{
  "generated_at": "2026-03-19T09:14:31Z",
  "target": "acme-corp.com",
  "summary": {
    "total": 6,
    "by_severity": { "critical": 2, "high": 2, "medium": 1, "low": 1 }
  },
  "findings": [
    {
      "id": "SWH-0001",
      "title": "PHP CGI RCE",
      "severity": "critical",
      "cvss_score": 9.8,
      "cve_id": "CVE-2024-4577",
      "epss_score": 0.94,
      "asset": "https://api.acme-corp.com",
      "business_impact": "An unauthenticated attacker can execute arbitrary commands...",
      "remediation": "1. Update PHP to 8.1.29+\n2. Disable CGI handler...",
      "raw_evidence": "HTTP/1.1 200 OK\nX-Powered-By: PHP/8.1.0...",
      "validation_notes": ["✓ Syntactic check passed", "✓ NVD confirmed", "✓ EPSS 0.94"]
    }
  ]
}
```

---

## Architecture

```
swarmhawk/
├── scope.py       SHA-256 signed authorization ledger
├── audit.py       Tamper-evident hash-chained audit log (SQLite)
├── recon.py       RECON agent — subfinder + httpx + IP enrichment
├── exploit.py     EXPLOIT agent — Nuclei + 3-layer validation + NVD/EPSS
├── synthesis.py   SYNTHESIS agent — Claude/OpenAI business context
├── report.py      Report generator — HTML + PDF
└── cli.py         CLI entry point
```

### 3-Layer Validation Pipeline

SwarmHawk doesn't just dump raw Nuclei output. Every finding goes through:

| Layer | What it checks |
|-------|---------------|
| **L1 Syntactic** | Evidence field populated, matched URL present, no empty responses |
| **L2 Template quality** | `confirmed` or `high-confidence` templates only, filters noise |
| **L3 NVD/EPSS** | Cross-references with NIST NVD database, adds exploitation probability (EPSS) |

Confidence thresholds: **Critical/High ≥ 0.70**, **Medium+ ≥ 0.50**

### Tamper-Evident Audit Log

Every agent action is written to a SQLite database with SHA-256 hash chaining — each entry's hash depends on all previous entries. Any post-hoc modification breaks the chain, which `swarmhawk audit` detects instantly.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | No | Claude API — recommended for best AI synthesis |
| `OPENAI_API_KEY` | No | OpenAI fallback |
| `NVD_API_KEY` | No | Raises NVD rate limit from 5/30s → 50/30s |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

27 tests across Scope, Audit, Recon, Exploit, Synthesis, and Integration. All pass with zero external dependencies (mock mode used in tests).

```bash
# With coverage
pytest tests/ -v --cov=swarmhawk --cov-report=term-missing
```

---

## Docker

```bash
# Build
docker build -t swarmhawk .

# Run a mock scan
docker run -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd)/reports:/app/reports \
  swarmhawk scan --target acme-corp.com --mock

# Real scan with scope file
docker run \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e NVD_API_KEY=$NVD_API_KEY \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/scopes:/app/scopes \
  swarmhawk scan --target acme-corp.com --scope /app/scopes/acme.json
```

---

## GitHub Action

Run SwarmHawk automatically on every PR — findings posted as PR comments, pipeline fails on critical findings:

```yaml
# .github/workflows/security.yml
name: Security Scan
on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 8 * * 1'  # Every Monday 08:00 UTC

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: swarmhawk-ai/swarmhawk-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          fail_on_critical: 'true'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Roadmap

| Version | Features |
|---------|----------|
| **v1.0** ✓ | RECON + EXPLOIT + AI SYNTHESIS + HTML/PDF reports |
| **v1.1** | Cloud IAM assessment (AWS/Azure/GCP via Stratus Red Team) |
| **v1.2** | Continuous scan mode + diff reports ("new since last week") |
| **v1.3** | REST API + webhook delivery for SIEM/ticketing integration |
| **v2.0** | Multi-agent swarm (LATERAL movement + INSIDER simulation) |

Community contributions accepted at any version. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Contributing

SwarmHawk is community-driven. The most impactful contributions:

- **New vulnerability checks** — extend `exploit.py` with custom detection logic
- **Nuclei template sets** — curated template lists for specific tech stacks (WordPress, Laravel, SAP, etc.)
- **Recon sources** — additional subdomain / asset discovery methods
- **Report templates** — alternative HTML themes or output formats
- **Integrations** — Jira, Slack, PagerDuty, Splunk output targets

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, conventions, and the PR process.

---

## ☁️ SwarmHawk Cloud

The CLI is open-source. The [cloud platform](https://swarmhawk.ai) adds:

| Feature | CLI (OSS) | Cloud |
|---------|-----------|-------|
| Full pipeline | ✓ | ✓ |
| HTML/PDF reports | ✓ | ✓ |
| Continuous monitoring | — | ✓ |
| Weekly diff alerts | — | ✓ |
| Team access + SSO | — | ✓ |
| Automated outreach pipeline | — | ✓ |
| SOC2/ISO27001 evidence packs | — | ✓ |
| Priority support | — | ✓ |

[Start free →](https://swarmhawk.ai)

---

## Legal

SwarmHawk is for **authorized security testing only**.

- Never run against systems without explicit written authorization
- Always create a signed scope ledger before any engagement — it's your legal protection
- The tamper-evident audit log records every action for compliance and accountability
- By using this tool you agree to only scan systems you own or have written permission to test

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**[swarmhawk.ai](https://swarmhawk.ai)** · [Docs](https://swarmhawk.ai/docs) · [Cloud Platform](https://swarmhawk.ai) · [Report a Bug](https://github.com/swarmhawk-ai/swarmhawk/issues)

*Built with ♥ by the SwarmHawk AI team and contributors.*

</div>
