# Social Media Copy

---

## Twitter / X

### Main launch tweet (thread — post as replies)

**Tweet 1:**
Just open-sourced SwarmHawk — one command from domain to security report:

```
pip install swarmhawk
swarmhawk scan --target acme-corp.com --mock
```

→ subdomain recon
→ 8,000+ Nuclei templates
→ CVE/EPSS enrichment
→ AI synthesis (Claude)
→ HTML/PDF report

MIT. Zero config. Works with no tools installed.

github.com/hastikdan/swarmhawk 🧵

**Tweet 2:**
The part I'm most proud of: 3-layer validation

Raw Nuclei output is noisy. Every finding goes through:

L1 — syntactic check (evidence populated, matched URL present)
L2 — template quality filter (confirmed/high-confidence only)
L3 — NVD cross-reference + EPSS exploitation probability

Critical/High need ≥0.70 confidence to make it into the report.

**Tweet 3:**
Also built a tamper-evident audit log.

Every agent action → SQLite with SHA-256 hash chaining.

Each entry's hash depends on all previous entries. Any post-hoc modification breaks the chain. `swarmhawk audit` detects it instantly.

Useful when reports need to hold up legally.

**Tweet 4:**
It's the OSS CLI / paid cloud split (Grafana model).

CLI = free forever, MIT
Cloud = continuous monitoring, team access, weekly diff alerts

If you use it in a pentest or CTF, I'd love to hear how it holds up.

github.com/hastikdan/swarmhawk

---

### Tag these accounts in follow-up replies or quote tweets:
@pdiscovery (ProjectDiscovery — they built subfinder/nuclei/httpx)
@hakluke
@tomnomnom
@NahamSec
@_JohnHammond
@nahamsec

---

### Shorter standalone tweet (for later in the week):

Found a critical RCE, a path traversal, and 4 misconfigs on a test domain in 31 seconds:

```
swarmhawk scan --target acme-corp.com --mock
```

Open-source CLI. MIT.
github.com/hastikdan/swarmhawk

---

## LinkedIn

**Post:**

We just open-sourced SwarmHawk — our external attack surface assessment CLI.

Here's why we built it and why we're giving it away.

Every security assessment we ran followed the same manual sequence:
1. Enumerate subdomains
2. Probe live assets
3. Run Nuclei templates
4. Look up CVEs and CVSS scores
5. Calculate business impact
6. Write the report

That's 2–4 hours before you've remediated a single finding. Multiply by a client roster and it becomes the majority of engagement time.

SwarmHawk automates the entire pipeline. One command. One report. 30 seconds.

We're open-sourcing the CLI under MIT — so security teams, pentesters, and bug bounty hunters can use it, extend it, and contribute new vulnerability checks. The cloud platform stays paid (continuous monitoring, team dashboards, automated outreach).

Same model as Grafana or PostHog. Open source drives adoption. The product pays for the servers.

If you run security assessments — internal or for clients — try it:

```
pip install swarmhawk
swarmhawk scan --target yourdomain.com --mock
```

github.com/hastikdan/swarmhawk

Contributions welcome. Especially interested in: new vulnerability checks, Nuclei template sets for specific tech stacks (SAP, WordPress, Laravel), and SIEM integrations.

#cybersecurity #opensource #pentesting #netsec #NIS2 #attacksurface

---

## Discord — ProjectDiscovery server (#tools-showcase)

Hey everyone — built something on top of subfinder/httpx/nuclei and just open-sourced it.

**SwarmHawk** — chains your tools into an autonomous pipeline:

```bash
pip install swarmhawk
swarmhawk scan --target example.com --mock
```

subfinder → httpx → nuclei (8k+ templates) → NVD/EPSS enrichment → Claude synthesis → HTML/PDF report + JSON

A few things that might be interesting to this community:

- 3-layer Nuclei validation (syntactic → template quality → NVD cross-ref) to cut false positives
- EPSS scores surfaced alongside CVSS in the report
- Tamper-evident audit log for the full scan
- Works in `--mock` mode with no tools for demo/CI use

MIT license. Would love feedback from people who run nuclei at scale — especially on the false positive filtering approach.

github.com/hastikdan/swarmhawk
