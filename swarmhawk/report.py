"""
swarmhawk.report
================
Report generator — produces professional HTML + PDF security reports.

Output:
  - HTML report (always generated, no dependencies)
  - PDF report (via weasyprint if installed, or wkhtmltopdf)

Design: Clean, professional security report aesthetic.
Suitable for board presentation and CISO review.
"""

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("swarmhawk.report")

SEV_COLOR = {
    "critical": "#FF2D55",
    "high":     "#FF6B2B",
    "medium":   "#FFD60A",
    "low":      "#00C67A",
    "info":     "#00AAFF",
}

SEV_BG = {
    "critical": "#FFF0F3",
    "high":     "#FFF4EF",
    "medium":   "#FFFBEC",
    "low":      "#EDFFF7",
    "info":     "#EEF8FF",
}


class ReportGenerator:
    """Generates HTML and PDF security assessment reports."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        target: str,
        assets: list,
        findings: list,
        scope,
        audit,
        exec_summary: str,
        duration: str,
    ) -> dict:
        """
        Generate full report package.
        Returns dict with paths to generated files.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = f"swarmhawk_{target.replace('.', '_')}_{ts}"

        html_path = self.output_dir / f"{base_name}.html"
        json_path = self.output_dir / f"{base_name}_findings.json"
        audit_path = self.output_dir / f"{base_name}_audit.json"

        # Generate HTML report
        html = self._render_html(
            target, assets, findings, exec_summary, duration, scope, audit
        )
        html_path.write_text(html, encoding="utf-8")
        logger.info(f"REPORT: HTML saved → {html_path}")

        # Export findings JSON
        findings_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "summary": {
                "total": len(findings),
                "by_severity": {
                    s: sum(1 for f in findings if f.severity == s)
                    for s in ["critical", "high", "medium", "low"]
                },
            },
            "findings": [f.to_dict() for f in findings],
        }
        json_path.write_text(json.dumps(findings_data, indent=2))
        logger.info(f"REPORT: Findings JSON → {json_path}")

        # Export audit log
        audit.export_json(str(audit_path))
        logger.info(f"REPORT: Audit log → {audit_path}")

        # Try to generate PDF
        pdf_path = self._generate_pdf(html_path, base_name)

        return {
            "html": str(html_path),
            "json": str(json_path),
            "audit": str(audit_path),
            "pdf": str(pdf_path) if pdf_path else None,
        }

    def _generate_pdf(self, html_path: Path, base_name: str) -> Optional[Path]:
        """Try weasyprint → wkhtmltopdf → skip gracefully."""
        pdf_path = self.output_dir / f"{base_name}.pdf"

        # Try weasyprint
        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info(f"REPORT: PDF saved → {pdf_path}")
            return pdf_path
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"REPORT: weasyprint failed: {e}")

        # Try wkhtmltopdf
        if shutil.which("wkhtmltopdf"):
            try:
                subprocess.run(
                    ["wkhtmltopdf", "--quiet",
                     "--page-size", "A4",
                     "--margin-top", "15mm",
                     "--margin-bottom", "15mm",
                     str(html_path), str(pdf_path)],
                    check=True, timeout=60
                )
                logger.info(f"REPORT: PDF saved → {pdf_path}")
                return pdf_path
            except Exception as e:
                logger.warning(f"REPORT: wkhtmltopdf failed: {e}")

        logger.info(
            "REPORT: PDF not generated (install weasyprint or wkhtmltopdf). "
            "HTML report is the primary deliverable."
        )
        return None

    # ── HTML rendering ────────────────────────────────────────────────────────

    def _render_html(
        self, target, assets, findings, exec_summary, duration, scope, audit=None
    ) -> str:
        sev_counts = {
            s: sum(1 for f in findings if f.severity == s)
            for s in ["critical", "high", "medium", "low"]
        }
        risk_score = min(100,
            sev_counts["critical"] * 18 +
            sev_counts["high"] * 8 +
            sev_counts["medium"] * 3 +
            sev_counts["low"]
        )
        risk_label = (
            "CRITICAL" if risk_score >= 75 else
            "HIGH" if risk_score >= 40 else
            "MEDIUM" if risk_score >= 15 else "LOW"
        )
        risk_color = (
            SEV_COLOR["critical"] if risk_score >= 75 else
            SEV_COLOR["high"] if risk_score >= 40 else
            SEV_COLOR["medium"] if risk_score >= 15 else SEV_COLOR["low"]
        )

        findings_html = "\n".join(
            self._render_finding(f) for f in findings
        )
        audit_rows = "\n".join(
            self._render_audit_row(e)
            for e in audit.get_recent(50)
        )

        generated_at = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SwarmHawk Security Report — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

  :root {{
    --brand: #050A14;
    --accent: #0066FF;
    --text: #1A1A2E;
    --subtext: #6B7280;
    --border: #E5E7EB;
    --bg: #FAFBFC;
    --panel: #FFFFFF;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'IBM Plex Sans', sans-serif;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.6;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }}

  /* ── COVER ── */
  .cover {{
    background: var(--brand);
    color: white;
    padding: 60px 64px 48px;
    position: relative;
    overflow: hidden;
    page-break-after: always;
  }}
  .cover::before {{
    content: '';
    position: absolute;
    top: -40%;
    right: -10%;
    width: 500px;
    height: 500px;
    border: 1px solid rgba(0,102,255,0.15);
    border-radius: 50%;
  }}
  .cover::after {{
    content: '';
    position: absolute;
    top: -20%;
    right: 5%;
    width: 300px;
    height: 300px;
    border: 1px solid rgba(0,102,255,0.1);
    border-radius: 50%;
  }}

  .cover-logo {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 4px;
    color: #00AAFF;
    margin-bottom: 60px;
  }}

  .cover-title {{
    font-size: 13px;
    font-weight: 400;
    color: rgba(255,255,255,0.5);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 16px;
  }}

  .cover-target {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 36px;
    font-weight: 700;
    color: white;
    margin-bottom: 8px;
  }}

  .cover-subtitle {{
    font-size: 16px;
    color: rgba(255,255,255,0.6);
    margin-bottom: 56px;
  }}

  .cover-meta {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 32px;
    border-top: 1px solid rgba(255,255,255,0.1);
    padding-top: 32px;
  }}

  .meta-label {{
    font-size: 10px;
    letter-spacing: 2px;
    color: rgba(255,255,255,0.4);
    margin-bottom: 6px;
    text-transform: uppercase;
  }}

  .meta-value {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 14px;
    color: rgba(255,255,255,0.9);
  }}

  .cover-risk {{
    position: absolute;
    top: 60px;
    right: 64px;
    text-align: center;
    z-index: 1;
  }}

  .risk-number {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 64px;
    font-weight: 700;
    color: {risk_color};
    line-height: 1;
  }}

  .risk-label-text {{
    font-size: 11px;
    letter-spacing: 3px;
    color: rgba(255,255,255,0.5);
    margin-top: 4px;
  }}

  /* ── LAYOUT ── */
  .content {{
    max-width: 900px;
    margin: 0 auto;
    padding: 48px 32px;
  }}

  /* ── SECTION HEADERS ── */
  .section-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 48px 0 20px;
    padding-bottom: 12px;
    border-bottom: 2px solid var(--accent);
  }}

  .section-number {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    color: var(--accent);
    font-weight: 700;
    letter-spacing: 2px;
  }}

  .section-title {{
    font-size: 18px;
    font-weight: 700;
    color: var(--brand);
  }}

  /* ── SEVERITY SUMMARY ── */
  .sev-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 32px;
  }}

  .sev-card {{
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    border: 1px solid;
  }}

  .sev-count {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 40px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 4px;
  }}

  .sev-name {{
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
  }}

  /* ── EXEC SUMMARY ── */
  .exec-summary {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 28px 32px;
    margin-bottom: 32px;
    line-height: 1.8;
    color: #374151;
  }}

  .exec-summary p {{ margin-bottom: 14px; }}
  .exec-summary p:last-child {{ margin-bottom: 0; }}

  /* ── FINDING CARDS ── */
  .finding-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 20px;
    overflow: hidden;
    page-break-inside: avoid;
  }}

  .finding-header {{
    display: flex;
    align-items: flex-start;
    gap: 16px;
    padding: 20px 24px;
    border-bottom: 1px solid var(--border);
  }}

  .finding-sev-badge {{
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    border: 1px solid;
    flex-shrink: 0;
    margin-top: 2px;
    font-family: 'IBM Plex Mono', monospace;
  }}

  .finding-title-wrap {{ flex: 1; min-width: 0; }}

  .finding-title {{
    font-size: 16px;
    font-weight: 700;
    color: var(--brand);
    margin-bottom: 4px;
  }}

  .finding-asset {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px;
    color: var(--subtext);
  }}

  .finding-cvss {{
    text-align: right;
    flex-shrink: 0;
  }}

  .cvss-score {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
  }}

  .cvss-label {{
    font-size: 10px;
    color: var(--subtext);
    letter-spacing: 1px;
  }}

  .finding-meta {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0;
    border-bottom: 1px solid var(--border);
  }}

  .meta-cell {{
    padding: 12px 24px;
    border-right: 1px solid var(--border);
  }}
  .meta-cell:last-child {{ border-right: none; }}
  .meta-cell .key {{
    font-size: 10px;
    letter-spacing: 1.5px;
    color: var(--subtext);
    margin-bottom: 3px;
  }}
  .meta-cell .val {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px;
    color: var(--text);
    font-weight: 600;
  }}

  .finding-body {{ padding: 24px; }}

  .field-label {{
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    color: var(--subtext);
    text-transform: uppercase;
    margin-bottom: 8px;
    margin-top: 20px;
  }}
  .field-label:first-child {{ margin-top: 0; }}

  .field-text {{ color: #374151; line-height: 1.7; }}

  .evidence-block {{
    background: #0D1117;
    color: #7DCFB6;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    padding: 16px 20px;
    border-radius: 4px;
    white-space: pre-wrap;
    overflow-x: auto;
    line-height: 1.6;
    max-height: 200px;
    overflow-y: auto;
  }}

  .remediation-text {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px;
    color: #374151;
    line-height: 1.8;
    white-space: pre-wrap;
  }}

  .validation-chain {{
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }}

  .vc-badge {{
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.5px;
  }}
  .vc-pass {{ background: #ECFDF5; color: #065F46; border: 1px solid #6EE7B7; }}
  .vc-warn {{ background: #FFFBEB; color: #92400E; border: 1px solid #FCD34D; }}

  /* ── ASSETS TABLE ── */
  .assets-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}
  .assets-table th {{
    text-align: left;
    padding: 10px 14px;
    background: var(--brand);
    color: white;
    font-size: 10px;
    letter-spacing: 1.5px;
    font-weight: 700;
  }}
  .assets-table td {{
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
  }}
  .assets-table tr:hover td {{ background: #F9FAFB; }}

  /* ── FOOTER ── */
  .report-footer {{
    margin-top: 64px;
    padding-top: 24px;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    color: var(--subtext);
  }}

  .disclaimer {{
    background: #FFFBEB;
    border: 1px solid #FCD34D;
    border-radius: 6px;
    padding: 16px 20px;
    margin-top: 32px;
    font-size: 12px;
    color: #92400E;
  }}

  @media print {{
    .cover {{ page-break-after: always; }}
    .finding-card {{ page-break-inside: avoid; }}
  }}
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
  <div class="cover-logo">✦ SWARMHAWK AI</div>
  <div class="cover-risk">
    <div class="risk-number">{risk_score}</div>
    <div class="risk-label-text">RISK INDEX</div>
    <div style="font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:700;color:{risk_color};margin-top:6px;letter-spacing:2px">{risk_label}</div>
  </div>
  <div class="cover-title">External Attack Surface Assessment</div>
  <div class="cover-target">{target}</div>
  <div class="cover-subtitle">Autonomous AI Security Assessment Report</div>
  <div class="cover-meta">
    <div>
      <div class="meta-label">Generated</div>
      <div class="meta-value">{generated_at}</div>
    </div>
    <div>
      <div class="meta-label">Duration</div>
      <div class="meta-value">{duration}</div>
    </div>
    <div>
      <div class="meta-label">Assets Scanned</div>
      <div class="meta-value">{len(assets)} live endpoints</div>
    </div>
    <div>
      <div class="meta-label">Customer</div>
      <div class="meta-value">{scope.customer_id}</div>
    </div>
    <div>
      <div class="meta-label">Total Findings</div>
      <div class="meta-value">{len(findings)} validated</div>
    </div>
    <div>
      <div class="meta-label">Scope Ledger</div>
      <div class="meta-value">{'✓ VERIFIED' if scope.verify() else '⚠ INVALID'}</div>
    </div>
  </div>
</div>

<div class="content">

  <!-- SEVERITY SUMMARY -->
  <div class="section-header">
    <span class="section-number">01</span>
    <span class="section-title">Severity Summary</span>
  </div>

  <div class="sev-grid">
    {"".join(
      f'<div class="sev-card" style="border-color:{SEV_COLOR[s]};background:{SEV_BG[s]}">'
      f'<div class="sev-count" style="color:{SEV_COLOR[s]}">{sev_counts[s]}</div>'
      f'<div class="sev-name" style="color:{SEV_COLOR[s]}">{s}</div>'
      f'</div>'
      for s in ["critical","high","medium","low"]
    )}
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div class="section-header">
    <span class="section-number">02</span>
    <span class="section-title">Executive Summary</span>
  </div>
  <div class="exec-summary">
    {"".join(f'<p>{self._escape(para.strip())}</p>' for para in exec_summary.split(chr(10)) if para.strip())}
  </div>

  <!-- FINDINGS -->
  <div class="section-header">
    <span class="section-number">03</span>
    <span class="section-title">Validated Findings ({len(findings)})</span>
  </div>

  {findings_html}

  <!-- ASSETS -->
  <div class="section-header">
    <span class="section-number">04</span>
    <span class="section-title">Attack Surface ({len(assets)} assets)</span>
  </div>

  <table class="assets-table">
    <thead>
      <tr>
        <th>ASSET / URL</th>
        <th>IP ADDRESS</th>
        <th>SERVER</th>
        <th>STATUS</th>
      </tr>
    </thead>
    <tbody>
      {"".join(
        f'<tr><td>{a.url}</td><td>{a.ip or "—"}</td>'
        f'<td>{a.server or "—"}</td><td>{a.status_code or "—"}</td></tr>'
        for a in assets
      )}
    </tbody>
  </table>

  <!-- DISCLAIMER -->
  <div class="disclaimer">
    <strong>⚠ AUTHORIZED ASSESSMENT ONLY</strong><br/>
    This assessment was conducted under an authorized engagement agreement
    (Scope Ledger: {scope.signature[:16]}...).
    All testing was performed within defined scope boundaries.
    This report is confidential and intended solely for {scope.customer_id}.
    SwarmHawk AI — swarmhawk.ai
  </div>

  <div class="report-footer">
    <span>✦ SwarmHawk AI — Autonomous Offensive Security Platform</span>
    <span>Confidential — {scope.customer_id} — {generated_at}</span>
  </div>

</div>
</body>
</html>"""

    def _render_finding(self, f) -> str:
        sev_color = SEV_COLOR.get(f.severity, "#999")
        sev_bg = SEV_BG.get(f.severity, "#fff")

        vc_badges = "".join(
            f'<span class="vc-badge {"vc-pass" if "✓" in n else "vc-warn"}">{n}</span>'
            for n in f.validation_notes
        )

        epss_display = f"{f.epss_score:.0%}" if f.epss_score > 0 else "N/A"
        epss_label = "🔴 Actively exploited" if f.epss_score > 0.5 else (
            "🟡 Some exploitation" if f.epss_score > 0.05 else "🟢 Low exploitation"
        ) if f.epss_score > 0 else "N/A"

        return f"""
<div class="finding-card">
  <div class="finding-header">
    <div class="finding-sev-badge"
      style="color:{sev_color};border-color:{sev_color};background:{sev_bg}">
      {self._escape(f.severity)}
    </div>
    <div class="finding-title-wrap">
      <div class="finding-title">{self._escape(f.title)}</div>
      <div class="finding-asset">{self._escape(f.asset)}</div>
    </div>
    <div class="finding-cvss">
      <div class="cvss-score" style="color:{sev_color}">{f.cvss_score}</div>
      <div class="cvss-label">CVSS</div>
    </div>
  </div>
  <div class="finding-meta">
    <div class="meta-cell">
      <div class="key">FINDING ID</div>
      <div class="val">{self._escape(f.id)}</div>
    </div>
    <div class="meta-cell">
      <div class="key">CVE</div>
      <div class="val">{self._escape(f.cve_id or "—")}</div>
    </div>
    <div class="meta-cell">
      <div class="key">EPSS / EXPLOITATION</div>
      <div class="val">{self._escape(epss_display)} — {self._escape(epss_label)}</div>
    </div>
  </div>
  <div class="finding-body">
    <div class="field-label">Description</div>
    <div class="field-text">{self._escape(f.description)}</div>

    <div class="field-label">Business Impact</div>
    <div class="field-text">{self._escape(f.business_impact or "See description above.")}</div>

    <div class="field-label">Raw Evidence</div>
    <div class="evidence-block">{self._escape(f.raw_evidence[:800])}</div>

    <div class="field-label">Remediation</div>
    <div class="remediation-text">{self._escape(f.remediation or "Apply vendor patch.")}</div>

    <div class="field-label">Validation Chain</div>
    <div class="validation-chain">{vc_badges}</div>
  </div>
</div>"""

    @staticmethod
    def _render_audit_row(e) -> str:
        return f"<tr><td>{e.get('seq')}</td><td>{e.get('ts','')[:19]}</td><td>{e.get('agent')}</td><td>{e.get('action')}</td><td>{e.get('target')}</td><td>{e.get('outcome')}</td></tr>"

    @staticmethod
    def _escape(text: str) -> str:
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))
