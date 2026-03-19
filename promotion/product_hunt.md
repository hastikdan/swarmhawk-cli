# Product Hunt

**Schedule:** Same week as HN launch, ideally Wednesday or Thursday
**Category:** Developer Tools / Security

---

## Name
SwarmHawk

## Tagline (60 chars max)
Open-source attack surface scanner with AI reports

## Description

SwarmHawk is an open-source CLI that turns a domain name into a full security assessment report — automatically.

One command runs the complete pipeline:

🔍 **Recon** — subdomain enumeration, live asset probing, IP/ASN enrichment
🎯 **Exploit detection** — 8,000+ Nuclei vulnerability templates with 3-layer validation
📊 **CVE enrichment** — CVSS scores + EPSS exploitation probability from NVD
🤖 **AI synthesis** — Claude/OpenAI writes business impact narratives and remediation steps
📄 **Report** — professional HTML/PDF output + machine-readable JSON for SIEM integration
🔐 **Audit log** — tamper-evident SHA-256 hash-chained record of every action

**Try it in 30 seconds:**
```
pip install swarmhawk
swarmhawk scan --target yourdomain.com --mock
```

The `--mock` flag runs the full pipeline with synthetic data — no tools, no API keys required.

**Open source** (MIT) · The CLI is free forever · The cloud platform adds continuous monitoring, team access, and automated outreach workflows

## Topics
developer-tools, security, open-source, ai, python, devops

## First comment (post immediately after going live)

Hey PH! Founder here.

We built SwarmHawk after running too many manual external attack surface assessments. The toolchain (subfinder → httpx → nuclei → manual CVE lookup → report writing) took 2–4 hours per client. We automated it.

Today we're open-sourcing the CLI under MIT. The cloud platform stays paid — same model as Grafana, PostHog, etc.

**What makes it different from just running Nuclei directly:**
1. The full recon phase discovers assets you didn't know existed
2. 3-layer validation cuts false positives before they reach the report
3. AI synthesis translates technical findings into business language CISOs understand
4. The tamper-evident audit log means reports survive legal review

We're particularly interested in security community contributions — new vulnerability checks, Nuclei template curation for specific stacks, integrations with Jira/Slack/Splunk.

GitHub: https://github.com/hastikdan/swarmhawk-cli
Cloud: https://swarmhawk.ai

Happy to answer anything!
