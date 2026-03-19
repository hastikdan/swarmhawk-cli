# Reddit Posts

Post all four on the same day as the HN submission.

---

## r/netsec

**Title:** SwarmHawk – open-source CLI: recon → Nuclei → CVE enrichment → AI report, one command

**Body:**

Built this to stop stitching tools together manually for every engagement. Open-sourced it today (MIT).

What it does in one command:

- Subdomain enumeration via subfinder
- Live probing via httpx + IP/ASN enrichment
- Vulnerability scanning with 8,000+ Nuclei templates
- 3-layer validation: syntactic → template quality → NVD/EPSS cross-reference (confidence thresholds: Critical/High ≥ 0.70)
- AI synthesis — Claude/OpenAI for business impact narrative + remediation steps
- HTML/PDF report + findings JSON for SIEM ingestion
- Tamper-evident audit log — SHA-256 hash-chained SQLite, every action recorded

The piece I think r/netsec will find interesting: the audit log. Each entry's hash includes all previous entries, so any post-hoc modification breaks the chain. Useful when reports need to survive legal scrutiny.

Runs in `--mock` mode with zero dependencies for demo/CI use.

**GitHub:** https://github.com/hastikdan/swarmhawk-cli
**Install:** `pip install swarmhawk`

Feedback welcome, especially on the validation pipeline — we're still tuning false positive rates across template categories.

---

## r/hacking

**Title:** I automated the full pentest recon-to-report pipeline and open-sourced it

**Body:**

Tired of running subfinder → httpx → nuclei → manually writing reports → exporting to PDF. Built SwarmHawk to do all of it in one command.

```bash
pip install swarmhawk
swarmhawk scan --target example.com --mock
```

That gives you:
- Live subdomain + asset discovery
- Nuclei vuln scan (8k+ templates)
- CVE enrichment with CVSS + EPSS scores
- AI-written business impact + remediation (Claude/OpenAI)
- HTML + PDF report
- JSON output for automation

Works in `--mock` mode with zero tools installed — generates synthetic findings for demo purposes.

MIT license. Contributions welcome, especially new vulnerability checks and template sets.

https://github.com/hastikdan/swarmhawk-cli

---

## r/cybersecurity

**Title:** Open-sourced our external attack surface scanner — recon to PDF report, one command

**Body:**

We built SwarmHawk for security teams doing recurring external assessments — and just open-sourced the CLI under MIT.

The problem it solves: external attack surface monitoring is still largely manual. You enumerate subdomains, probe live assets, run Nuclei, look up CVEs, calculate business impact, write the report. That's 2–4 hours per engagement before you've actually fixed anything.

SwarmHawk automates the full pipeline:

```
swarmhawk scan --target yourdomain.com
```

→ Recon (subfinder + httpx + IP enrichment)
→ Vuln scan (8,000+ Nuclei templates, 3-layer validation)
→ CVE enrichment (NVD + EPSS exploitation probability)
→ AI synthesis (business impact + remediation steps)
→ HTML/PDF report + findings JSON

Particularly useful for teams that need to demonstrate NIS2/ISO27001 compliance — the tamper-evident audit log records every action with SHA-256 hash chaining.

MIT license. `pip install swarmhawk`

https://github.com/hastikdan/swarmhawk-cli

---

## r/Python

**Title:** SwarmHawk – a Python CLI that chains security tools into an autonomous assessment pipeline

**Body:**

Just open-sourced a project I've been working on: SwarmHawk, a Python CLI that orchestrates subfinder → httpx → nuclei → NVD/EPSS API → Claude/OpenAI into a single autonomous pipeline.

```bash
pip install swarmhawk
swarmhawk scan --target acme-corp.com --mock  # demo, no tools needed
```

A few design decisions that might interest r/Python:

**Tamper-evident audit log** — every agent action is written to SQLite with SHA-256 hash chaining. Each entry's hash includes a digest of all previous entries. `swarmhawk audit` verifies the chain. Any post-hoc modification is immediately detectable.

**3-layer validation pipeline** — raw Nuclei JSON → syntactic check → template confidence filter → NVD/EPSS cross-reference. Reduces false positives significantly before passing to the AI synthesis step.

**Mock mode** — the full pipeline runs with synthetic data when real tools aren't installed. All 27 tests use mock mode — zero external dependencies in CI.

**Scope ledger** — SHA-256 signed JSON authorization manifest. You can't scan a target without creating one first. Provides legal protection and clear engagement boundaries.

Architecture:
```
scope.py    — signed authorization ledger
audit.py    — hash-chained SQLite log
recon.py    — RECON agent
exploit.py  — EXPLOIT agent (Nuclei + validation)
synthesis.py — AI synthesis (Claude/OpenAI)
report.py   — HTML/PDF generator
cli.py      — CLI entry point
```

MIT license. Python 3.11+. PRs welcome.

https://github.com/hastikdan/swarmhawk-cli
