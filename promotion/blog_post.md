# Blog Post — Technical Deep Dive

**Title:** How we built a tamper-evident audit log for penetration testing reports
**Publish on:** swarmhawk.ai/blog → cross-post to dev.to → Medium (security tag)
**Target keywords:** pentest automation python, nuclei automation, attack surface management open source, penetration testing audit log
**Length:** ~1,800 words

---

# How we built a tamper-evident audit log for penetration testing reports

Penetration testing reports have a chain of custody problem.

A client receives a PDF. The PDF says their webserver has a critical RCE vulnerability. The client's legal team asks: how do we know this finding is real, and not added to the report after the fact? How do we know the scanner actually ran, and the tester didn't just fabricate findings?

These questions come up more often as security assessments become compliance artifacts — SOC2, ISO27001, NIS2 audits all treat pentest reports as evidence. Evidence needs to be verifiable.

We solved this in SwarmHawk with a tamper-evident audit log. Every action the scanner takes is recorded in a SHA-256 hash-chained SQLite database. Any modification to any entry breaks the chain — and `swarmhawk audit` detects it instantly.

Here's how we built it.

## The problem with PDFs as evidence

A PDF report is a static document. There's no way to verify that:

- The scan actually ran against the stated target
- The findings reflect what the scanner found, not what someone typed
- The timestamps are accurate
- Nothing was added or removed after the scan completed

For internal security teams, this is mostly fine. For compliance audits, legal disputes, or regulated industries, it's a real problem.

We wanted SwarmHawk's reports to be auditable — not just readable.

## Designing the audit log

We had three requirements:

1. **Tamper-evident**: any modification to any historical entry must be detectable
2. **Complete**: every agent action must be recorded, not just findings
3. **Portable**: the log must be verifiable offline, without calling home to any service

The solution: a hash chain, the same fundamental primitive used in blockchains (without the distributed consensus overhead).

Each entry in the log includes a hash of itself plus all previous entries. You can't change entry #5 without also changing entries #6 through #N, which would require recalculating the entire chain — and you'd need to know all the previous hashes to do it correctly. Since the chain is opaque to an attacker who receives only the final log, it's effectively tamper-evident.

## Implementation

The core is in `audit.py`:

```python
class AuditLog:
    def append(self, agent, action, target, outcome, metadata=None):
        seq = self._next_seq()
        prev_hash = self._last_hash()

        entry = {
            "seq":      seq,
            "ts":       datetime.now(timezone.utc).isoformat(),
            "agent":    agent,
            "action":   action,
            "target":   target,
            "outcome":  outcome,
            "metadata": json.dumps(metadata or {}),
            "prev_hash": prev_hash,
        }

        # Hash the entry including the previous hash
        entry_str = json.dumps(entry, sort_keys=True)
        entry["hash"] = hashlib.sha256(entry_str.encode()).hexdigest()

        # Write to SQLite
        self._insert(entry)
```

Verification iterates through every entry and checks that each hash is consistent with the entry data and the previous hash:

```python
def verify_chain(self) -> tuple[bool, str]:
    entries = self.get_all()
    for i, entry in enumerate(entries):
        # Recompute the hash for this entry (excluding the hash field itself)
        entry_without_hash = {k: v for k, v in entry.items() if k != "hash"}
        expected = hashlib.sha256(
            json.dumps(entry_without_hash, sort_keys=True).encode()
        ).hexdigest()

        if entry["hash"] != expected:
            return False, f"Hash mismatch at entry #{entry['seq']}"

        # Check prev_hash linkage
        if i > 0 and entry["prev_hash"] != entries[i-1]["hash"]:
            return False, f"Chain break between entry #{i} and #{i+1}"

    return True, None
```

The verification is entirely self-contained — it reads from the SQLite file and needs no external state.

## What gets logged

Every agent action in SwarmHawk writes an audit entry. A complete scan produces 40–60 entries:

```
09:14:01  HAWK-OS       mission_start        acme-corp.com       initiated
09:14:01  ReconAgent    subdomain_enum        acme-corp.com       14 found
09:14:03  ReconAgent    http_probe           api.acme-corp.com    200 OK
09:14:03  ReconAgent    ip_enrichment        api.acme-corp.com    AS13335/Cloudflare
...
09:14:08  ExploitAgent  nuclei_scan          acme-corp.com        started
09:14:22  ExploitAgent  finding_validated    CVE-2024-4577        confidence=0.94
09:14:22  ExploitAgent  finding_rejected     CVE-2021-99999       confidence=0.41
...
09:14:23  SynthAgent    enrich_finding       SWH-0001             complete
09:14:31  SynthAgent    exec_summary         acme-corp.com        complete
09:14:31  HAWK-OS       report_start         acme-corp.com        initiated
09:14:31  HAWK-OS       mission_complete     acme-corp.com        6 findings, chain valid
```

Crucially, rejected findings are also logged. An auditor can verify that the scanner ran and made deliberate decisions — it didn't just fabricate findings.

## The scope ledger

Paired with the audit log is a scope ledger — a SHA-256 signed JSON file that proves written authorization existed before the scan ran:

```json
{
  "manifest": {
    "customer_id": "ACME Corp",
    "target_domains": ["acme-corp.com", "*.acme-corp.com"],
    "authorized_by": "Jane Smith, CISO",
    "window_start": "2026-03-19T00:00:00+00:00",
    "window_end": "2026-04-19T00:00:00+00:00",
    "permitted_techniques": ["passive_recon", "active_recon", "vuln_scan"]
  },
  "signature": "a3f8c2d1e9b4..."
}
```

The scope ledger is loaded before any scan begins. If the target isn't in the ledger, or the window has expired, the scan refuses to start. This isn't just legal hygiene — it's a design constraint that makes unauthorized use of the tool significantly harder.

## The 3-layer validation pipeline

The audit log records not just findings, but the validation decisions. This is important for another reason: Nuclei produces noise.

SwarmHawk runs every raw finding through three layers before it reaches the report:

**Layer 1 — Syntactic**: Is the evidence field populated? Is there a matched URL? Is the response non-empty?

**Layer 2 — Template quality**: Is the template marked `confirmed` or `high-confidence`? Informational templates and low-quality matches are filtered here.

**Layer 3 — NVD/EPSS**: Does the CVE exist in the NVD database? What's the EPSS exploitation probability? We apply confidence thresholds: Critical/High findings need ≥0.70 confidence, Medium+ need ≥0.50.

Each validation decision is logged. An auditor can see exactly why finding X was included and finding Y was rejected.

## Putting it together

After a scan, you get:

- `swarmhawk_acme-corp_com_20260319.html` — the report
- `swarmhawk_acme-corp_com_20260319_findings.json` — machine-readable findings
- `swarmhawk_acme-corp_com_20260319_audit.json` — audit log export
- `audit_acme_corp_com.db` — the SQLite source of truth

To verify integrity:

```bash
swarmhawk audit --file reports/audit_acme_corp_com.db
# Chain valid: True
# 47 entries
# 09:14:01  HAWK-OS  mission_start  acme-corp.com  initiated
# ...
```

If anyone modifies the SQLite file after the fact — adds a finding, changes a timestamp, deletes an entry — the chain breaks and verification fails.

## Open source

We're open-sourcing the full CLI under MIT. The audit log and scope ledger are the pieces we're most interested in getting community feedback on — especially from practitioners who've dealt with compliance auditors or legal review of pentest reports.

```bash
pip install swarmhawk
swarmhawk scan --target yourdomain.com --mock
```

GitHub: https://github.com/hastikdan/swarmhawk

The cloud platform adds continuous monitoring, team access, and weekly diff reports — but the core pipeline is free, open, and auditable.

---

*SwarmHawk AI — swarmhawk.ai*
