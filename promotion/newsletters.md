# Newsletter Outreach Emails

Send these after the GitHub repo is live and has at least the first batch of stars (post HN first).

---

## tl;dr sec (Clint Gibler)
**Email:** clint@tldrsec.com
**Subject:** OSS tool for your newsletter — autonomous attack surface scanner

Hi Clint,

I've been reading tl;dr sec for years — it's how I stay current on the field.

I just open-sourced SwarmHawk, an MIT-licensed CLI that chains subdomain recon → Nuclei → NVD/EPSS CVE enrichment → Claude AI synthesis → HTML/PDF report. One command, full pipeline.

```
pip install swarmhawk
swarmhawk scan --target yourdomain.com --mock
```

A few things that might make it worth a mention:

- 3-layer validation pipeline (syntactic → template quality → NVD confidence thresholds) to reduce Nuclei noise
- Tamper-evident SHA-256 hash-chained audit log — detects any post-hoc report modification
- Works in mock mode with zero tools for CI/CD integration
- MIT licensed, 27 tests, Python 3.11+

GitHub: https://github.com/hastikdan/swarmhawk

No pressure at all — just thought it fit the tools section. Happy to answer any technical questions.

[Your name]
SwarmHawk AI

---

## Unsupervised Learning (Daniel Miessler)
**Email:** via danielmiessler.com/contact
**Subject:** OSS security tool — might fit Unsupervised Learning

Hi Daniel,

Long-time reader of Unsupervised Learning.

I built and open-sourced SwarmHawk — an autonomous attack surface assessment CLI that combines traditional recon tooling (subfinder, Nuclei) with AI synthesis (Claude) to produce full security reports in one command.

The architecture might interest you given your writing on AI+security intersections:

- Recon agent → Exploit agent → Synthesis agent → Report generator
- The AI step generates business impact narratives and remediation steps from raw technical findings
- Every agent action is recorded in a tamper-evident audit log (SHA-256 hash chain)

MIT license. https://github.com/hastikdan/swarmhawk

Just wanted to put it on your radar. Thanks for everything you put out.

[Your name]

---

## Securibee (Beyers Cronje)
**Subject:** SwarmHawk — open-source attack surface CLI, might be worth a mention

Hi Beyers,

Sharing a tool I just open-sourced that might fit Securibee's audience.

SwarmHawk is a Python CLI that automates external attack surface assessment — recon, Nuclei scanning, CVE enrichment, AI-written reports, all in one pipeline.

The thing that differentiates it from just running Nuclei directly: a 3-layer validation step that cross-references findings against NVD/EPSS before they hit the report, and an AI synthesis step that translates technical findings into business impact language.

MIT license. `pip install swarmhawk`.

https://github.com/hastikdan/swarmhawk

[Your name]

---

## SANS NewsBites / @SANS_ISC
**Submit via:** https://isc.sans.edu/contact.html
**Note:** Submit as a "tool of interest" — keep it very short

Title: SwarmHawk — open-source autonomous external attack surface scanner
URL: https://github.com/hastikdan/swarmhawk
Summary: MIT-licensed Python CLI that chains subfinder, httpx, and Nuclei with NVD/EPSS CVE enrichment and AI synthesis (Claude/OpenAI) into a single attack surface assessment pipeline. Produces HTML/PDF reports and tamper-evident audit logs. Works in mock mode for CI use without external tools.

---

## The Hacker News (thehackernews.com)
**Contact:** via their tip submission form
**Angle:** "open-source tool" angle, not "startup news"

SwarmHawk is an open-source Python CLI that automates external attack surface assessment. It chains subdomain enumeration (subfinder), live asset probing (httpx), vulnerability scanning (8,000+ Nuclei templates), NVD/EPSS CVE enrichment, and AI synthesis (Claude/OpenAI) into a single pipeline producing professional HTML/PDF reports with tamper-evident audit logs. The tool runs in demo mode without any external tools installed and is MIT-licensed.

GitHub: https://github.com/hastikdan/swarmhawk
