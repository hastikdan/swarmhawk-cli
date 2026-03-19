"""
SwarmHawk MVP — Test Suite
==========================
Run: pytest tests/ -v
"""

import pytest
import json
from pathlib import Path

from swarmhawk.scope import ScopeLedger, ScopeViolation
from swarmhawk.audit import AuditLog
from swarmhawk.recon import ReconAgent, Asset
from swarmhawk.exploit import ExploitAgent, RawFinding
from swarmhawk.synthesis import SynthesisAgent


# ── Scope Ledger Tests ────────────────────────────────────────────────────────

class TestScopeLedger:

    def test_create_and_verify(self):
        scope = ScopeLedger.create(
            customer_id="TEST-CORP",
            target_domains=["test.com"],
            authorized_by="test-signer",
        )
        assert scope.verify() is True

    def test_in_scope_root_domain(self):
        scope = ScopeLedger.create("TEST", ["acme.com"], "test")
        assert scope.is_in_scope("acme.com") is True
        assert scope.is_in_scope("api.acme.com") is True
        assert scope.is_in_scope("evil.com") is False

    def test_in_scope_wildcard(self):
        scope = ScopeLedger.create("TEST", ["*.acme.com"], "test")
        assert scope.is_in_scope("api.acme.com") is True
        assert scope.is_in_scope("admin.acme.com") is True
        assert scope.is_in_scope("evil.com") is False

    def test_in_scope_strips_protocol(self):
        scope = ScopeLedger.create("TEST", ["acme.com"], "test")
        assert scope.is_in_scope("https://acme.com") is True
        assert scope.is_in_scope("http://api.acme.com/path") is True

    def test_tamper_detection(self):
        scope = ScopeLedger.create("TEST", ["acme.com"], "test")
        assert scope.verify() is True
        # Tamper with the manifest
        scope.manifest["target_domains"].append("evil.com")
        assert scope.verify() is False

    def test_scope_violation_raised(self):
        scope = ScopeLedger.create("TEST", ["acme.com"], "test")
        with pytest.raises(ScopeViolation):
            scope.assert_in_scope("evil.com")

    def test_save_and_load(self, tmp_path):
        scope = ScopeLedger.create("TEST", ["acme.com"], "test-signer")
        path = tmp_path / "scope.json"
        scope.save(str(path))
        loaded = ScopeLedger.from_file(str(path))
        assert loaded.verify() is True
        assert loaded.customer_id == "TEST"

    def test_load_tampered_file_raises(self, tmp_path):
        scope = ScopeLedger.create("TEST", ["acme.com"], "test")
        path = tmp_path / "scope.json"
        scope.save(str(path))
        # Tamper with the file
        data = json.loads(path.read_text())
        data["manifest"]["target_domains"] = ["evil.com"]
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError, match="tampered"):
            ScopeLedger.from_file(str(path))

    def test_technique_permission(self):
        scope = ScopeLedger.create(
            "TEST", ["acme.com"], "test",
            permitted_techniques=["passive_recon", "nuclei_safe"]
        )
        assert scope.is_technique_permitted("passive_recon") is True
        assert scope.is_technique_permitted("destructive_exploit") is False
        assert scope.is_technique_permitted("unknown_technique") is False


# ── Audit Log Tests ───────────────────────────────────────────────────────────

class TestAuditLog:

    def test_append_and_retrieve(self):
        log = AuditLog()
        entry = log.append("RECON", "dns_enum", "acme.com", "complete")
        assert entry["agent"] == "RECON"
        assert entry["action"] == "dns_enum"
        assert "hash" in entry

    def test_chain_integrity(self):
        log = AuditLog()
        for i in range(5):
            log.append("AGENT", f"action_{i}", f"target_{i}", "ok")
        valid, reason = log.verify_chain()
        assert valid is True
        assert reason is None

    def test_tamper_detection(self):
        log = AuditLog()
        log.append("RECON", "scan", "acme.com", "complete")
        log.append("EXPLOIT", "probe", "acme.com", "finding")
        # Directly modify an entry (simulates tamper)
        log._conn.execute(
            "UPDATE audit_log SET outcome='TAMPERED' WHERE seq=1"
        )
        log._conn.commit()
        valid, reason = log.verify_chain()
        assert valid is False
        assert reason is not None

    def test_get_recent(self):
        log = AuditLog()
        for i in range(10):
            log.append("AGENT", "action", f"target_{i}", "ok")
        recent = log.get_recent(5)
        assert len(recent) == 5
        # Most recent first
        assert recent[0]["target"] == "target_9"

    def test_export_json(self, tmp_path):
        log = AuditLog()
        log.append("RECON", "scan", "acme.com", "ok")
        path = tmp_path / "audit.json"
        log.export_json(str(path))
        data = json.loads(path.read_text())
        assert data["chain_valid"] is True
        assert len(data["entries"]) == 1

    def test_metadata_stored(self):
        log = AuditLog()
        log.append("EXPLOIT", "finding", "api.acme.com", "proposed",
                   {"cve": "CVE-2024-4577", "cvss": 9.8})
        entries = log.get_all()
        assert entries[0]["metadata"]["cve"] == "CVE-2024-4577"


# ── Recon Agent Tests ─────────────────────────────────────────────────────────

class TestReconAgent:

    @pytest.fixture
    def scope(self):
        return ScopeLedger.create(
            "TEST", ["acme-corp.com", "*.acme-corp.com"], "test"
        )

    @pytest.fixture
    def audit(self):
        return AuditLog()

    def test_mock_run(self, scope, audit):
        agent = ReconAgent(scope, audit, mock_mode=True)
        assets = agent.run("acme-corp.com")
        assert len(assets) > 0
        for a in assets:
            assert a.url.startswith("https://")
            assert a.domain

    def test_all_assets_in_scope(self, scope, audit):
        agent = ReconAgent(scope, audit, mock_mode=True)
        assets = agent.run("acme-corp.com")
        for a in assets:
            assert scope.is_in_scope(a.domain), \
                f"Out of scope asset returned: {a.domain}"

    def test_out_of_scope_target_raises(self, scope, audit):
        agent = ReconAgent(scope, audit, mock_mode=True)
        with pytest.raises(ScopeViolation):
            agent.run("evil.com")

    def test_detect_tech_nginx(self):
        tech = ReconAgent._detect_tech("nginx/1.24.0")
        assert any("Nginx" in t for t in tech)

    def test_detect_tech_apache_version(self):
        tech = ReconAgent._detect_tech("Apache/2.4.49")
        assert any("Apache" in t for t in tech)

    def test_extract_title(self):
        html = "<html><head><title>My Site</title></head></html>"
        title = ReconAgent._extract_title(html)
        assert title == "My Site"


# ── Exploit Agent Tests ───────────────────────────────────────────────────────

class TestExploitAgent:

    @pytest.fixture
    def scope(self):
        return ScopeLedger.create(
            "TEST", ["acme-corp.com", "*.acme-corp.com"], "test"
        )

    @pytest.fixture
    def audit(self):
        return AuditLog()

    @pytest.fixture
    def assets(self):
        return [
            Asset(url="https://api.acme-corp.com", domain="api.acme-corp.com",
                  status_code=200, server="Apache/2.4.49"),
            Asset(url="https://admin.acme-corp.com", domain="admin.acme-corp.com",
                  status_code=200, server="Apache/2.4.49"),
        ]

    def test_mock_run_returns_findings(self, scope, audit, assets):
        agent = ExploitAgent(scope, audit, mock_mode=True)
        findings = agent.run(assets)
        assert len(findings) > 0

    def test_all_findings_validated(self, scope, audit, assets):
        agent = ExploitAgent(scope, audit, mock_mode=True)
        findings = agent.run(assets)
        for f in findings:
            assert f.validated is True, \
                f"Unvalidated finding returned: {f.title} (conf={f.confidence})"

    def test_findings_have_evidence(self, scope, audit, assets):
        agent = ExploitAgent(scope, audit, mock_mode=True)
        findings = agent.run(assets)
        for f in findings:
            assert f.raw_evidence, f"Finding missing evidence: {f.id}"

    def test_critical_findings_high_confidence(self, scope, audit, assets):
        agent = ExploitAgent(scope, audit, mock_mode=True)
        findings = agent.run(assets)
        for f in findings:
            if f.severity == "critical":
                assert f.confidence >= 0.70, \
                    f"Critical finding below confidence threshold: {f.id} ({f.confidence})"

    def test_empty_assets(self, scope, audit):
        agent = ExploitAgent(scope, audit, mock_mode=True)
        findings = agent.run([])
        assert findings == []

    def test_finding_has_cvss(self, scope, audit, assets):
        agent = ExploitAgent(scope, audit, mock_mode=True)
        findings = agent.run(assets)
        for f in findings:
            assert 0.0 <= f.cvss_score <= 10.0

    def test_default_cvss(self):
        assert ExploitAgent._default_cvss("critical") == 9.0
        assert ExploitAgent._default_cvss("high") == 7.5
        assert ExploitAgent._default_cvss("medium") == 5.0

    def test_out_of_scope_findings_blocked(self, scope, audit):
        # Target whose findings should be blocked by scope
        foreign_assets = [
            Asset(url="https://evil.com", domain="evil.com",
                  status_code=200, server="Apache/2.4.49")
        ]
        agent = ExploitAgent(scope, audit, mock_mode=True)
        # Evil.com not in scope — findings should not include it
        findings = agent.run(foreign_assets)
        for f in findings:
            assert scope.is_in_scope(f.asset) or scope.is_in_scope(f.url), \
                f"Out-of-scope finding leaked: {f.url}"


# ── Synthesis Agent Tests ─────────────────────────────────────────────────────

class TestSynthesisAgent:

    @pytest.fixture
    def audit(self):
        return AuditLog()

    def test_mock_enrich(self, audit):
        scope = ScopeLedger.create("TEST", ["acme.com"], "test")
        agent = SynthesisAgent(audit, mock_mode=True)

        # Create a minimal finding
        from swarmhawk.exploit import EnrichedFinding
        finding = EnrichedFinding(
            id="F-001", template_id="cves/2024/CVE-2024-4577",
            title="Test Finding", severity="critical",
            asset="api.acme.com", url="https://api.acme.com",
            cve_id="CVE-2024-4577", cvss_score=9.8, cvss_vector=None,
            epss_score=0.94, epss_percentile=0.99,
            description="Test description",
            raw_evidence="Test evidence",
            confidence=0.9, validated=True, validation_notes=[]
        )

        agent.enrich_finding(finding)
        assert finding.business_impact is not None
        assert len(finding.business_impact) > 20
        assert finding.remediation is not None
        assert len(finding.remediation) > 20

    def test_mock_exec_summary(self, audit):
        from swarmhawk.exploit import EnrichedFinding
        agent = SynthesisAgent(audit, mock_mode=True)
        scope = ScopeLedger.create("TEST", ["acme.com"], "test")

        finding = EnrichedFinding(
            id="F-001", template_id="test", title="Critical Bug",
            severity="critical", asset="api.acme.com",
            url="https://api.acme.com", cve_id=None,
            cvss_score=9.8, cvss_vector=None,
            epss_score=0.0, epss_percentile=0.0,
            description="Test", raw_evidence="evidence",
            confidence=0.9, validated=True, validation_notes=[],
        )

        assets = [Asset(url="https://api.acme.com", domain="api.acme.com")]
        summary = agent.generate_executive_summary(
            "acme.com", [finding], assets, "5m 30s"
        )
        assert len(summary) > 100
        assert "acme.com" in summary.lower() or "acme" in summary.lower()


# ── Integration Test ──────────────────────────────────────────────────────────

class TestIntegration:
    """End-to-end pipeline test in mock mode."""

    def test_full_pipeline_mock(self, tmp_path):
        """Run the complete RECON → EXPLOIT → SYNTHESIS pipeline in mock mode."""
        scope = ScopeLedger.create(
            customer_id="INTEGRATION-TEST",
            target_domains=["test-corp.com", "*.test-corp.com"],
            authorized_by="pytest-integration",
            window_days=1,
        )
        audit = AuditLog(str(tmp_path / "test_audit.db"))

        # RECON
        recon = ReconAgent(scope, audit, mock_mode=True)
        assets = recon.run("test-corp.com")
        assert len(assets) > 0

        # EXPLOIT
        exploit = ExploitAgent(scope, audit, mock_mode=True)
        findings = exploit.run(assets)
        assert len(findings) > 0
        assert all(f.validated for f in findings)

        # SYNTHESIS
        synthesis = SynthesisAgent(audit, mock_mode=True)
        for f in findings:
            synthesis.enrich_finding(f)
        assert all(f.business_impact for f in findings)

        exec_summary = synthesis.generate_executive_summary(
            "test-corp.com", findings, assets, "1m 0s"
        )
        assert len(exec_summary) > 50

        # REPORT
        from swarmhawk.report import ReportGenerator
        reporter = ReportGenerator(output_dir=str(tmp_path / "reports"))
        paths = reporter.generate(
            target="test-corp.com",
            assets=assets,
            findings=findings,
            scope=scope,
            audit=audit,
            exec_summary=exec_summary,
            duration="1m 0s",
        )
        assert Path(paths["html"]).exists()
        assert Path(paths["json"]).exists()
        html = Path(paths["html"]).read_text()
        assert "test-corp.com" in html
        assert "SWARMHAWK" in html

        # Audit chain should be valid throughout
        valid, reason = audit.verify_chain()
        assert valid is True, f"Audit chain broken: {reason}"
