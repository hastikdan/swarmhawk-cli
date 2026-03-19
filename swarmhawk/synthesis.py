"""
swarmhawk.synthesis
===================
SYNTHESIS Agent — LLM-powered finding analysis.

Uses Claude API (or OpenAI as fallback) to:
  1. Generate plain-English business impact for each finding
  2. Write actionable remediation steps
  3. Create an executive summary narrative
  4. Validate finding makes sense (AI sanity check)

Mock mode: returns high-quality templated content when no API key is set.
"""

import json
import logging
import os
from typing import Optional

import requests

logger = logging.getLogger("swarmhawk.synthesis")

CLAUDE_API = "https://api.anthropic.com/v1/messages"
OPENAI_API = "https://api.openai.com/v1/chat/completions"

# Fallback templates for mock mode — still professional quality
IMPACT_TEMPLATES = {
    "critical": (
        "This vulnerability gives an attacker complete control over the affected system "
        "without requiring any authentication or user interaction. Exploitation in the wild "
        "is actively observed (EPSS > 0.90). A successful attack would result in full server "
        "compromise, potential lateral movement to internal systems, and exposure of all data "
        "processed by this service. Immediate remediation is required."
    ),
    "high": (
        "This vulnerability allows an attacker to access or manipulate sensitive data, "
        "potentially leading to unauthorized access, data theft, or service disruption. "
        "Exploitation requires minimal attacker skill given available public tooling. "
        "Left unaddressed, this presents a significant risk of breach within the next "
        "30–90 days based on current threat actor activity patterns."
    ),
    "medium": (
        "This issue represents a meaningful security weakness that, while not immediately "
        "critical, could be combined with other vulnerabilities to achieve more severe impact. "
        "Organizations with active threat models should remediate within the next 90 days. "
        "The risk increases if the affected system handles sensitive data or is Internet-facing."
    ),
}

REMEDIATION_TEMPLATES = {
    "cves/2024/CVE-2024-4577": (
        "1. Immediately update PHP to version 8.1.28, 8.2.18, or 8.3.6 or later.\n"
        "2. If immediate patching is not possible, disable PHP CGI or add the following "
        "rewrite rule in your web server config to mitigate: "
        "RewriteCond %{QUERY_STRING} ^%ad [NC] RewriteRule .? - [F,L]\n"
        "3. Review logs for exploitation attempts: look for %AD or %2B in query strings.\n"
        "4. Consider Web Application Firewall (WAF) rules as a compensating control.\n"
        "Reference: https://nvd.nist.gov/vuln/detail/CVE-2024-4577"
    ),
    "default": (
        "1. Apply the vendor-recommended patch or upgrade to the latest stable version.\n"
        "2. If patching cannot be done immediately, implement network-level controls "
        "(WAF rules, IP allowlisting) as temporary compensating controls.\n"
        "3. Enable enhanced logging on the affected service and monitor for exploitation.\n"
        "4. Verify the fix by re-running the specific Nuclei template post-remediation.\n"
        "5. Document remediation actions and timeline for compliance purposes."
    ),
}


class SynthesisAgent:
    """
    LLM-powered analysis layer.

    Priority: Claude API → OpenAI API → Mock templates
    Set ANTHROPIC_API_KEY or OPENAI_API_KEY in environment.
    """

    FINDING_PROMPT = """You are a senior penetration tester writing a security report for a CISO.

Finding details:
{finding_json}

Write TWO sections:

BUSINESS IMPACT (2-3 sentences):
Explain in plain English what this vulnerability means for the business —
what could an attacker do, what data/systems are at risk, and what is the
urgency. No technical jargon. Write for a non-technical executive audience.

REMEDIATION (3-5 numbered steps):
Specific, actionable steps to fix this vulnerability. Include version numbers
where applicable, relevant CVE patch references, and a verification step.
Write for a technical engineer who will implement the fix.

Format your response as JSON:
{{"business_impact": "...", "remediation": "..."}}

Only output valid JSON. No markdown, no extra text."""

    EXEC_SUMMARY_PROMPT = """You are a senior penetration tester writing an executive summary.

Engagement details:
- Target: {target}
- Assets scanned: {asset_count}
- Duration: {duration}
- Findings: {findings_json}

Write a concise executive summary (3-4 paragraphs) covering:
1. Overall security posture and most critical risk
2. The 2-3 most impactful findings and their business risk
3. Key remediation priorities

Write for a CISO who will present this to the board.
Plain English, no jargon, focus on business impact and risk.
Output plain text, no markdown."""

    def __init__(self, audit, mock_mode: bool = False):
        self.audit = audit
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.openai_key = os.getenv("OPENAI_API_KEY", "")
        self.mock_mode = mock_mode or (
            not self.anthropic_key and not self.openai_key
        )
        if self.mock_mode:
            logger.info(
                "SYNTHESIS: No API key found — using mock templates. "
                "Set ANTHROPIC_API_KEY for AI-powered synthesis."
            )

    # ── Main entry points ─────────────────────────────────────────────────────

    def enrich_finding(self, finding) -> None:
        """Add business_impact and remediation to a finding in-place."""
        if self.mock_mode:
            self._mock_enrich(finding)
            return

        prompt = self.FINDING_PROMPT.format(
            finding_json=json.dumps(finding.to_dict(), indent=2)
        )
        response = self._call_llm(prompt)
        if response:
            try:
                data = json.loads(response)
                finding.business_impact = data.get("business_impact", "")
                finding.remediation = data.get("remediation", "")
                self.audit.append(
                    "SYNTHESIS", "enrich_finding", finding.id,
                    "complete", {"model": self._model_name()}
                )
            except json.JSONDecodeError:
                logger.warning(f"SYNTHESIS: Could not parse LLM response for {finding.id}")
                self._mock_enrich(finding)
        else:
            self._mock_enrich(finding)

    def generate_executive_summary(
        self, target: str, findings: list, assets: list, duration: str
    ) -> str:
        """Generate board-ready executive summary."""
        if self.mock_mode:
            return self._mock_exec_summary(target, findings, assets)

        findings_brief = [
            {"id": f.id, "title": f.title, "severity": f.severity,
             "cvss": f.cvss_score, "asset": f.asset}
            for f in findings[:10]   # Cap context length
        ]
        prompt = self.EXEC_SUMMARY_PROMPT.format(
            target=target,
            asset_count=len(assets),
            duration=duration,
            findings_json=json.dumps(findings_brief, indent=2),
        )
        result = self._call_llm(prompt, max_tokens=600)
        if result:
            self.audit.append(
                "SYNTHESIS", "exec_summary", target,
                "complete", {"model": self._model_name()}
            )
            return result
        return self._mock_exec_summary(target, findings, assets)

    def ai_sanity_check(self, finding) -> tuple[str, str]:
        """
        Ask the LLM: does this finding make sense?
        Returns (CONFIRMED | UNCERTAIN | REJECTED, reasoning).
        """
        if self.mock_mode:
            return "CONFIRMED", "Mock mode — auto-confirmed"

        prompt = f"""You are a senior penetration tester reviewing a vulnerability finding for accuracy.

Finding:
{json.dumps(finding.to_dict(), indent=2)}

Does the raw evidence actually support the vulnerability claim?
Consider: Is the evidence specific? Does it match the CVE/template? Is it credible?

Reply with EXACTLY one of: CONFIRMED, UNCERTAIN, or REJECTED
Then one sentence of reasoning.

Format: STATUS: <one sentence>
Example: CONFIRMED: The extracted passwd file contents confirm successful path traversal."""

        response = self._call_llm(prompt, max_tokens=100)
        if response:
            response = response.strip()
            for status in ("CONFIRMED", "UNCERTAIN", "REJECTED"):
                if response.upper().startswith(status):
                    reason = response[len(status):].lstrip(":").strip()
                    return status, reason
        return "UNCERTAIN", "Could not parse AI response"

    # ── LLM calls ─────────────────────────────────────────────────────────────

    def _call_llm(self, prompt: str, max_tokens: int = 800) -> Optional[str]:
        """Try Claude first, then OpenAI."""
        if self.anthropic_key:
            return self._call_claude(prompt, max_tokens)
        if self.openai_key:
            return self._call_openai(prompt, max_tokens)
        return None

    def _call_claude(self, prompt: str, max_tokens: int) -> Optional[str]:
        try:
            r = requests.post(
                CLAUDE_API,
                headers={
                    "x-api-key": self.anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            if r.status_code == 200:
                return r.json()["content"][0]["text"]
            logger.warning(f"SYNTHESIS: Claude API error {r.status_code}: {r.text[:200]}")
        except Exception as e:
            logger.warning(f"SYNTHESIS: Claude call failed: {e}")
        return None

    def _call_openai(self, prompt: str, max_tokens: int) -> Optional[str]:
        try:
            r = requests.post(
                OPENAI_API,
                headers={
                    "Authorization": f"Bearer {self.openai_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o-mini",
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                },
                timeout=30,
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            logger.warning(f"SYNTHESIS: OpenAI API error {r.status_code}")
        except Exception as e:
            logger.warning(f"SYNTHESIS: OpenAI call failed: {e}")
        return None

    def _model_name(self) -> str:
        if self.anthropic_key:
            return "claude-sonnet-4-20250514"
        if self.openai_key:
            return "gpt-4o-mini"
        return "mock"

    # ── Mock mode ─────────────────────────────────────────────────────────────

    def _mock_enrich(self, finding) -> None:
        finding.business_impact = IMPACT_TEMPLATES.get(
            finding.severity, IMPACT_TEMPLATES["medium"]
        )
        finding.remediation = REMEDIATION_TEMPLATES.get(
            finding.template_id, REMEDIATION_TEMPLATES["default"]
        )

    def _mock_exec_summary(
        self, target: str, findings: list, assets: list
    ) -> str:
        crit = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        top = findings[0] if findings else None

        summary = (
            f"SwarmHawk AI conducted an automated external attack surface assessment "
            f"of {target}, scanning {len(assets)} live assets. The assessment identified "
            f"{len(findings)} validated findings, including {crit} Critical and {high} High "
            f"severity vulnerabilities that require immediate attention."
        )
        if top:
            summary += (
                f"\n\nThe most critical finding is {top.title} affecting {top.asset} "
                f"(CVSS {top.cvss_score}). "
                + IMPACT_TEMPLATES.get(top.severity, "")
            )
        summary += (
            f"\n\nThe overall risk posture is assessed as CRITICAL. "
            f"Immediate remediation of all Critical and High findings is recommended "
            f"within 72 hours. SwarmHawk AI recommends scheduling a follow-up scan "
            f"after remediation to verify all issues have been resolved."
        )
        return summary
