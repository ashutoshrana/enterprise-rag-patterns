"""
Tests for 50_rag_security_auditor.py

Covers RAGSystemConfig, AuditFinding, RAGAuditReport, and RAGSecurityAuditor
across all six security domains (22 controls total).

~40 test cases using pytest and importlib loading pattern.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load the example module via importlib
# ---------------------------------------------------------------------------

_MOD_NAME = "rag_security_auditor_50"
_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "50_rag_security_auditor.py")

spec = importlib.util.spec_from_file_location(_MOD_NAME, _EXAMPLE_PATH)
mod = types.ModuleType(_MOD_NAME)
sys.modules[_MOD_NAME] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

RAGSystemConfig = mod.RAGSystemConfig
AuditFinding = mod.AuditFinding
RAGAuditReport = mod.RAGAuditReport
RAGSecurityAuditor = mod.RAGSecurityAuditor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_off_config(**overrides) -> RAGSystemConfig:
    """Return a fully-default (all-disabled) RAGSystemConfig with optional overrides."""
    return RAGSystemConfig(**overrides)


def _all_on_config() -> RAGSystemConfig:
    """Return a RAGSystemConfig with every control enabled at maximum settings."""
    return RAGSystemConfig(
        system_id="fully-hardened",
        query_injection_detection_enabled=True,
        query_length_limit=2000,
        input_sanitization_enabled=True,
        namespace_isolation_enforced=True,
        document_integrity_checksums=True,
        embedding_source_validated=True,
        vector_store_access_control=True,
        pre_filter_placement="before_retrieval",
        max_retrieved_chunks=10,
        cross_tenant_isolation=True,
        retrieval_audit_logging=True,
        dlp_scan_on_output=True,
        output_schema_validation=True,
        citation_integrity_enforced=True,
        hallucination_detection_enabled=True,
        action_gating_enabled=True,
        tool_call_allowlist_enforced=True,
        human_approval_for_destructive_actions=True,
        query_logging_enabled=True,
        retrieval_logging_enabled=True,
        output_logging_enabled=True,
        anomaly_detection_enabled=True,
        security_alerting_enabled=True,
        audit_retention_days=365,
    )


def _audit(config: RAGSystemConfig) -> RAGAuditReport:
    return RAGSecurityAuditor().audit(config)


def _find(report: RAGAuditReport, control_id: str) -> AuditFinding:
    for f in report.findings:
        if f.control_id == control_id:
            return f
    raise AssertionError(f"Control {control_id!r} not found in findings")


# ---------------------------------------------------------------------------
# RAGSystemConfig defaults
# ---------------------------------------------------------------------------


class TestRAGSystemConfigDefaults:
    def test_system_id_default(self):
        cfg = RAGSystemConfig()
        assert cfg.system_id == "rag-system"

    def test_all_bool_fields_default_false(self):
        cfg = RAGSystemConfig()
        bool_fields = [
            "query_injection_detection_enabled",
            "input_sanitization_enabled",
            "namespace_isolation_enforced",
            "document_integrity_checksums",
            "embedding_source_validated",
            "vector_store_access_control",
            "cross_tenant_isolation",
            "retrieval_audit_logging",
            "dlp_scan_on_output",
            "output_schema_validation",
            "citation_integrity_enforced",
            "hallucination_detection_enabled",
            "action_gating_enabled",
            "tool_call_allowlist_enforced",
            "human_approval_for_destructive_actions",
            "query_logging_enabled",
            "retrieval_logging_enabled",
            "output_logging_enabled",
            "anomaly_detection_enabled",
            "security_alerting_enabled",
        ]
        for field in bool_fields:
            assert getattr(cfg, field) is False, f"{field} should default to False"

    def test_numeric_fields_default_zero(self):
        cfg = RAGSystemConfig()
        assert cfg.query_length_limit == 0
        assert cfg.max_retrieved_chunks == 0
        assert cfg.audit_retention_days == 0

    def test_pre_filter_placement_default_none(self):
        assert RAGSystemConfig().pre_filter_placement == "none"

    def test_field_assignment(self):
        cfg = RAGSystemConfig(system_id="my-rag", query_length_limit=500)
        assert cfg.system_id == "my-rag"
        assert cfg.query_length_limit == 500


# ---------------------------------------------------------------------------
# AuditFinding fields
# ---------------------------------------------------------------------------


class TestAuditFindingFields:
    def test_finding_fields_accessible(self):
        f = AuditFinding(
            control_id="RAG-IV-001",
            control_name="Query Injection Detection",
            domain="Input Validation",
            status="FAIL",
            severity="CRITICAL",
            framework_refs=["OWASP LLM01"],
            evidence="test evidence",
            remediation_step="fix it",
        )
        assert f.control_id == "RAG-IV-001"
        assert f.control_name == "Query Injection Detection"
        assert f.domain == "Input Validation"
        assert f.status == "FAIL"
        assert f.severity == "CRITICAL"
        assert f.framework_refs == ["OWASP LLM01"]
        assert f.evidence == "test evidence"
        assert f.remediation_step == "fix it"


# ---------------------------------------------------------------------------
# RAGAuditReport
# ---------------------------------------------------------------------------


class TestRAGAuditReport:
    def test_summary_returns_string(self):
        report = _audit(_all_off_config())
        result = report.summary()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_summary_contains_system_id(self):
        report = _audit(RAGSystemConfig(system_id="test-system"))
        assert "test-system" in report.summary()

    def test_score_field_is_float(self):
        report = _audit(_all_off_config())
        assert isinstance(report.score, float)

    def test_maturity_level_field_is_string(self):
        report = _audit(_all_off_config())
        assert isinstance(report.maturity_level, str)

    def test_findings_field_is_list(self):
        report = _audit(_all_off_config())
        assert isinstance(report.findings, list)

    def test_count_fields_are_int(self):
        report = _audit(_all_off_config())
        assert isinstance(report.critical_count, int)
        assert isinstance(report.high_count, int)
        assert isinstance(report.medium_count, int)
        assert isinstance(report.passing_count, int)


# ---------------------------------------------------------------------------
# All-defaults audit: score == 0, maturity == "Sandbox", ≥ 6 critical failures
# ---------------------------------------------------------------------------


class TestAllDefaultsAudit:
    def setup_method(self):
        self.report = _audit(_all_off_config())

    def test_score_is_zero(self):
        assert self.report.score == 0.0

    def test_maturity_is_sandbox(self):
        assert self.report.maturity_level == "Sandbox"

    def test_at_least_six_critical_failures(self):
        assert self.report.critical_count >= 6

    def test_passing_count_is_zero(self):
        assert self.report.passing_count == 0

    def test_system_id_preserved(self):
        report = _audit(RAGSystemConfig(system_id="default-system"))
        assert report.system_id == "default-system"


# ---------------------------------------------------------------------------
# All-enabled audit: score == 100, maturity == "Autonomous", 0 critical failures
# ---------------------------------------------------------------------------


class TestAllEnabledAudit:
    def setup_method(self):
        self.report = _audit(_all_on_config())

    def test_score_is_100(self):
        assert self.report.score == 100.0

    def test_maturity_is_autonomous(self):
        assert self.report.maturity_level == "Autonomous"

    def test_zero_critical_failures(self):
        assert self.report.critical_count == 0

    def test_zero_high_failures(self):
        assert self.report.high_count == 0

    def test_zero_medium_failures(self):
        assert self.report.medium_count == 0


# ---------------------------------------------------------------------------
# Per-control assertions
# ---------------------------------------------------------------------------


class TestInputValidationControls:
    def test_rag_iv_001_pass_when_injection_detection_enabled(self):
        report = _audit(_all_off_config(query_injection_detection_enabled=True))
        finding = _find(report, "RAG-IV-001")
        assert finding.status == "PASS"

    def test_rag_iv_001_fail_when_injection_detection_disabled(self):
        report = _audit(_all_off_config())
        finding = _find(report, "RAG-IV-001")
        assert finding.status == "FAIL"
        assert finding.severity == "CRITICAL"


class TestVectorStoreControls:
    def test_rag_vs_001_fail_critical_when_namespace_isolation_off(self):
        report = _audit(_all_off_config(namespace_isolation_enforced=False))
        finding = _find(report, "RAG-VS-001")
        assert finding.status == "FAIL"
        assert finding.severity == "CRITICAL"

    def test_rag_vs_001_pass_when_namespace_isolation_on(self):
        report = _audit(_all_off_config(namespace_isolation_enforced=True))
        finding = _find(report, "RAG-VS-001")
        assert finding.status == "PASS"


class TestRetrievalControls:
    def test_rag_rc_003_fail_when_cross_tenant_isolation_off(self):
        report = _audit(_all_off_config(cross_tenant_isolation=False))
        finding = _find(report, "RAG-RC-003")
        assert finding.status == "FAIL"

    def test_rag_rc_003_pass_when_cross_tenant_isolation_on(self):
        report = _audit(_all_off_config(cross_tenant_isolation=True))
        finding = _find(report, "RAG-RC-003")
        assert finding.status == "PASS"


class TestOutputSecurityControls:
    def test_rag_os_001_pass_when_dlp_enabled(self):
        report = _audit(_all_off_config(dlp_scan_on_output=True))
        finding = _find(report, "RAG-OS-001")
        assert finding.status == "PASS"

    def test_rag_os_001_fail_when_dlp_disabled(self):
        report = _audit(_all_off_config(dlp_scan_on_output=False))
        finding = _find(report, "RAG-OS-001")
        assert finding.status == "FAIL"
        assert finding.severity == "CRITICAL"


class TestActionGatingControls:
    def test_rag_ag_001_fail_critical_when_action_gating_disabled(self):
        report = _audit(_all_off_config(action_gating_enabled=False))
        finding = _find(report, "RAG-AG-001")
        assert finding.status == "FAIL"
        assert finding.severity == "CRITICAL"

    def test_rag_ag_001_pass_when_action_gating_enabled(self):
        report = _audit(_all_off_config(action_gating_enabled=True))
        finding = _find(report, "RAG-AG-001")
        assert finding.status == "PASS"


class TestObservabilityControls:
    def test_rag_ob_004_fail_when_retention_30_days(self):
        """Retention < 90 days → FAIL."""
        report = _audit(_all_off_config(audit_retention_days=30))
        finding = _find(report, "RAG-OB-004")
        assert finding.status == "FAIL"

    def test_rag_ob_004_warn_when_retention_180_days(self):
        """Retention 90–364 days → WARN."""
        report = _audit(_all_off_config(audit_retention_days=180))
        finding = _find(report, "RAG-OB-004")
        assert finding.status == "WARN"

    def test_rag_ob_004_pass_when_retention_365_days(self):
        """Retention ≥ 365 days → PASS."""
        report = _audit(_all_off_config(audit_retention_days=365))
        finding = _find(report, "RAG-OB-004")
        assert finding.status == "PASS"

    def test_rag_ob_004_warn_threshold_exactly_90(self):
        """Exactly 90 days is within WARN range (90 <= retention < 365)."""
        report = _audit(_all_off_config(audit_retention_days=90))
        finding = _find(report, "RAG-OB-004")
        assert finding.status == "WARN"


# ---------------------------------------------------------------------------
# Count consistency
# ---------------------------------------------------------------------------


class TestCountConsistency:
    def test_critical_high_medium_sum_equals_total_fail_count(self):
        report = _audit(_all_off_config())
        total_fails = sum(1 for f in report.findings if f.status == "FAIL")
        assert report.critical_count + report.high_count + report.medium_count == total_fails

    def test_score_does_not_exceed_100(self):
        report = _audit(_all_on_config())
        assert report.score <= 100.0

    def test_score_not_negative(self):
        report = _audit(_all_off_config())
        assert report.score >= 0.0

    def test_passing_count_matches_findings(self):
        report = _audit(_all_on_config())
        actual_passes = sum(1 for f in report.findings if f.status == "PASS")
        assert report.passing_count == actual_passes

    def test_framework_refs_nonempty_for_all_findings(self):
        report = _audit(_all_off_config())
        for f in report.findings:
            assert isinstance(f.framework_refs, list)
            assert len(f.framework_refs) > 0, f"{f.control_id} has empty framework_refs"
            for ref in f.framework_refs:
                assert isinstance(ref, str) and len(ref) > 0
