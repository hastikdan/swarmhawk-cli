# Hacker News — Show HN

**Post at:** Tuesday–Thursday, 9–11am ET
**URL to submit:** https://github.com/hastikdan/swarmhawk

---

## Title

Show HN: SwarmHawk – open-source CLI that chains recon → Nuclei → AI synthesis → PDF report

---

## First comment (post this yourself immediately after submitting — it seeds the thread)

We built SwarmHawk to solve a specific frustration: running a proper external attack surface assessment requires stitching together subfinder, httpx, nuclei, NVD lookups, and then manually writing a report. We automated the whole thing into one command.

**What it does:**

```
swarmhawk scan --target acme-corp.com --mock
```

1. Subdomain enumeration (subfinder)
2. Live asset probing + IP enrichment (httpx)
3. Vulnerability scanning — 8,000+ Nuclei templates
4. 3-layer validation (syntactic → template quality → NVD/EPSS cross-reference)
5. AI synthesis via Claude/OpenAI — business impact + remediation steps
6. HTML/PDF report + machine-readable JSON
7. Tamper-evident audit log (SHA-256 hash-chained SQLite — every action recorded, any modification detectable)

The `--mock` flag runs the full pipeline with synthetic data in ~10 seconds on any machine with no tools installed. Good for demos and CI pipelines.

We're open-sourcing the CLI (MIT) and keeping the cloud platform paid. Classic OSS/SaaS split.

The part I'm most interested in community feedback on: the 3-layer validation pipeline. Raw Nuclei output has a lot of noise. We filter with confidence thresholds (Critical/High ≥ 0.70, Medium+ ≥ 0.50) cross-referenced against NVD/EPSS. Curious if others have better approaches.

Happy to answer questions about the architecture, the AI synthesis prompting, or the audit log design.
