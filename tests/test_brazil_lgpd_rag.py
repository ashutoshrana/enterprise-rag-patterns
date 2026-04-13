"""
Tests for 31_brazil_lgpd_rag.py

Covers LGPDDataSubjectFilter, LGPDMinimizationFilter, LGPDDataRetentionFilter,
LGPDCrossBorderFilter, BrazilLGPDRAGPipeline, and BrazilRAGAuditRecord.

36 tests total:
  [1-5]   LGPDDataSubjectFilter
  [6-9]   LGPDMinimizationFilter
  [10-13] LGPDDataRetentionFilter
  [14-17] LGPDCrossBorderFilter
  [18-22] Full pipeline integration
  [23-27] BrazilRAGAuditRecord.to_audit_log() structure
  [28-36] Edge cases and additional coverage
"""

from __future__ import annotations

import os
import sys
import importlib.util
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "brazil_lgpd_rag_31"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "31_brazil_lgpd_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
BrazilRAGContext = mod.BrazilRAGContext
BrazilRAGDocument = mod.BrazilRAGDocument
BrazilRole = mod.BrazilRole
Decision = mod.Decision
FilterResult = mod.FilterResult
LGPDDataSubjectFilter = mod.LGPDDataSubjectFilter
LGPDMinimizationFilter = mod.LGPDMinimizationFilter
LGPDDataRetentionFilter = mod.LGPDDataRetentionFilter
LGPDCrossBorderFilter = mod.LGPDCrossBorderFilter
BrazilLGPDRAGPipeline = mod.BrazilLGPDRAGPipeline
BrazilRAGAuditRecord = mod.BrazilRAGAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def _ctx(
    *,
    user_id: str = "u-001",
    requester_role: object = None,
    requester_jurisdiction: str = "BR",
    lgpd_legal_basis: str = "consent",
    has_explicit_consent: bool = True,
    requester_is_data_subject: bool = False,
    authorized_data_categories: object = None,
    processing_purpose: str = "customer_service",
    is_legal_hold: bool = False,
    is_legal_override: bool = False,
    has_lgpd_transfer_mechanism: bool = False,
    is_dpo: bool = False,
) -> object:
    if requester_role is None:
        requester_role = BrazilRole.DATA_CONTROLLER
    if authorized_data_categories is None:
        authorized_data_categories = frozenset({"contact", "financial"})
    return BrazilRAGContext(
        user_id=user_id,
        requester_role=requester_role,
        requester_jurisdiction=requester_jurisdiction,
        lgpd_legal_basis=lgpd_legal_basis,
        has_explicit_consent=has_explicit_consent,
        requester_is_data_subject=requester_is_data_subject,
        authorized_data_categories=authorized_data_categories,
        processing_purpose=processing_purpose,
        is_legal_hold=is_legal_hold,
        is_legal_override=is_legal_override,
        has_lgpd_transfer_mechanism=has_lgpd_transfer_mechanism,
        is_dpo=is_dpo,
    )


def _doc(
    *,
    document_id: str = "doc-001",
    contains_personal_data: bool = True,
    contains_sensitive_data: bool = False,
    data_categories_present: object = None,
    compatible_purposes: object = None,
    retention_expired: bool = False,
    data_subject_requested_deletion: bool = False,
    classification: str = "PERSONAL_DATA",
    data_subject_id: str = "ds-001",
) -> object:
    if data_categories_present is None:
        data_categories_present = frozenset({"contact", "financial"})
    if compatible_purposes is None:
        compatible_purposes = frozenset()
    return BrazilRAGDocument(
        document_id=document_id,
        contains_personal_data=contains_personal_data,
        contains_sensitive_data=contains_sensitive_data,
        data_categories_present=data_categories_present,
        compatible_purposes=compatible_purposes,
        retention_expired=retention_expired,
        data_subject_requested_deletion=data_subject_requested_deletion,
        classification=classification,
        data_subject_id=data_subject_id,
    )


def _public_doc(document_id: str = "doc-public") -> object:
    return _doc(
        document_id=document_id,
        contains_personal_data=False,
        contains_sensitive_data=False,
        data_categories_present=frozenset(),
        classification="PUBLIC",
        data_subject_id="",
    )


def _sensitive_doc(document_id: str = "doc-sensitive") -> object:
    return _doc(
        document_id=document_id,
        contains_personal_data=True,
        contains_sensitive_data=True,
        data_categories_present=frozenset({"health", "contact"}),
        classification="SENSITIVE_DATA",
    )


# ---------------------------------------------------------------------------
# Tests 1–5: LGPDDataSubjectFilter
# ---------------------------------------------------------------------------

class TestLGPDDataSubjectFilter:
    """Tests 1-5: LGPD Art. 7, Art. 11, Art. 18 data subject and legal basis rules."""

    def test_01_data_subject_always_permitted(self):
        """Test 1: Data subject is always permitted to access their own personal data (Art. 18)."""
        f = LGPDDataSubjectFilter()
        ctx = _ctx(requester_is_data_subject=True, lgpd_legal_basis="none")
        doc = _doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED
        assert "Art. 18" in result.regulation_citation

    def test_02_no_legal_basis_denied(self):
        """Test 2: Denied when legal basis is not a valid LGPD Art. 7 basis."""
        f = LGPDDataSubjectFilter()
        ctx = _ctx(lgpd_legal_basis="none", requester_is_data_subject=False)
        doc = _doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "Art. 7" in result.regulation_citation

    def test_03_sensitive_data_without_consent_denied(self):
        """Test 3: Sensitive data denied when no explicit consent and basis is not legal_obligation."""
        f = LGPDDataSubjectFilter()
        ctx = _ctx(
            lgpd_legal_basis="legitimate_interest",
            has_explicit_consent=False,
            requester_is_data_subject=False,
        )
        doc = _sensitive_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "Art. 11" in result.regulation_citation

    def test_04_legal_obligation_overrides_sensitive_gate(self):
        """Test 4: Legal obligation legal basis permits access to sensitive data (Art. 11)."""
        f = LGPDDataSubjectFilter()
        ctx = _ctx(
            lgpd_legal_basis="legal_obligation",
            has_explicit_consent=False,
            requester_is_data_subject=False,
        )
        doc = _sensitive_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_05_valid_legal_basis_non_sensitive_permitted(self):
        """Test 5: Valid Art. 7 legal basis permits access to non-sensitive personal data."""
        f = LGPDDataSubjectFilter()
        ctx = _ctx(lgpd_legal_basis="contract", has_explicit_consent=False)
        doc = _doc(contains_sensitive_data=False)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 6–9: LGPDMinimizationFilter
# ---------------------------------------------------------------------------

class TestLGPDMinimizationFilter:
    """Tests 6-9: LGPD Art. 6(I) purpose limitation and Art. 6(III) data minimization."""

    def test_06_unauthorized_category_denied(self):
        """Test 6: Denied when document contains data categories outside the authorized scope."""
        f = LGPDMinimizationFilter()
        ctx = _ctx(authorized_data_categories=frozenset({"contact"}))
        doc = _doc(data_categories_present=frozenset({"contact", "health"}))
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "Art. 6(III)" in result.regulation_citation

    def test_07_purpose_mismatch_denied(self):
        """Test 7: Denied when processing purpose is not in the document's compatible purposes."""
        f = LGPDMinimizationFilter()
        ctx = _ctx(
            processing_purpose="marketing",
            authorized_data_categories=frozenset({"contact", "financial"}),
        )
        doc = _doc(
            compatible_purposes=frozenset({"customer_service", "fraud_detection"}),
        )
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "Art. 6(I)" in result.regulation_citation

    def test_08_empty_compatible_purposes_passes(self):
        """Test 8: Empty compatible_purposes means any purpose is permitted."""
        f = LGPDMinimizationFilter()
        ctx = _ctx(processing_purpose="analytics")
        doc = _doc(compatible_purposes=frozenset())
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_09_all_authorized_categories_passes(self):
        """Test 9: Permitted when all document categories are within the authorized set."""
        f = LGPDMinimizationFilter()
        ctx = _ctx(
            authorized_data_categories=frozenset({"contact", "financial", "health"}),
            processing_purpose="customer_service",
        )
        doc = _doc(
            data_categories_present=frozenset({"contact", "financial"}),
            compatible_purposes=frozenset({"customer_service"}),
        )
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 10–13: LGPDDataRetentionFilter
# ---------------------------------------------------------------------------

class TestLGPDDataRetentionFilter:
    """Tests 10-13: LGPD Art. 15 retention expiry and Art. 18(VI) erasure requests."""

    def test_10_expired_retention_denied(self):
        """Test 10: Denied when document retention period has expired and no legal hold exists."""
        f = LGPDDataRetentionFilter()
        ctx = _ctx(is_legal_hold=False)
        doc = _doc(retention_expired=True)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "Art. 15" in result.regulation_citation

    def test_11_deletion_requested_redacted(self):
        """Test 11: REDACTED (not DENIED) when data subject requested deletion and no override."""
        f = LGPDDataRetentionFilter()
        ctx = _ctx(is_legal_override=False)
        doc = _doc(data_subject_requested_deletion=True)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.REDACTED
        assert "Art. 18(VI)" in result.regulation_citation

    def test_12_legal_hold_permits_expired_data(self):
        """Test 12: Legal hold overrides the retention expiry denial (Art. 15)."""
        f = LGPDDataRetentionFilter()
        ctx = _ctx(is_legal_hold=True)
        doc = _doc(retention_expired=True)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_13_legal_override_permits_deletion_requested(self):
        """Test 13: Legal override allows access despite data subject deletion request."""
        f = LGPDDataRetentionFilter()
        ctx = _ctx(is_legal_override=True)
        doc = _doc(data_subject_requested_deletion=True)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 14–17: LGPDCrossBorderFilter
# ---------------------------------------------------------------------------

class TestLGPDCrossBorderFilter:
    """Tests 14-17: LGPD Art. 33 cross-border transfer controls."""

    def test_14_adequate_jurisdiction_br_permitted(self):
        """Test 14: Requests from Brazil (BR) are permitted without a transfer mechanism."""
        f = LGPDCrossBorderFilter()
        ctx = _ctx(requester_jurisdiction="BR")
        doc = _doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_15_adequate_jurisdiction_eu_permitted(self):
        """Test 15: Requests from EU jurisdictions are permitted (adequate protection)."""
        f = LGPDCrossBorderFilter()
        ctx = _ctx(requester_jurisdiction="EU")
        doc = _doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_16_non_adequate_without_mechanism_denied(self):
        """Test 16: Non-adequate jurisdiction without SCC/BCR is denied (Art. 33)."""
        f = LGPDCrossBorderFilter()
        ctx = _ctx(requester_jurisdiction="US", has_lgpd_transfer_mechanism=False)
        doc = _doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "Art. 33" in result.regulation_citation

    def test_17_non_personal_data_always_permitted(self):
        """Test 17: Non-personal data bypasses Art. 33 transfer controls entirely."""
        f = LGPDCrossBorderFilter()
        ctx = _ctx(requester_jurisdiction="US", has_lgpd_transfer_mechanism=False)
        doc = _public_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 18–22: Full pipeline integration
# ---------------------------------------------------------------------------

class TestPipelineIntegration:
    """Tests 18-22: end-to-end BrazilLGPDRAGPipeline behavior."""

    def test_18_approved_path_all_filters_pass(self):
        """Test 18: A fully compliant request permits the document through all four layers."""
        pipeline = BrazilLGPDRAGPipeline()
        ctx = _ctx(
            requester_jurisdiction="BR",
            lgpd_legal_basis="consent",
            has_explicit_consent=True,
            authorized_data_categories=frozenset({"contact", "financial"}),
            processing_purpose="customer_service",
        )
        doc = _doc(
            compatible_purposes=frozenset({"customer_service"}),
        )
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 1
        assert results[0][0].document_id == doc.document_id

    def test_19_denied_path_stops_at_first_denial(self):
        """Test 19: Pipeline stops at the first DENIED result and excludes the document."""
        pipeline = BrazilLGPDRAGPipeline()
        ctx = _ctx(lgpd_legal_basis="none", requester_is_data_subject=False)
        doc = _doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 0

    def test_20_audit_record_structure(self):
        """Test 20: retrieve_with_audit returns a BrazilRAGAuditRecord with correct fields."""
        pipeline = BrazilLGPDRAGPipeline()
        ctx = _ctx()
        doc = _doc()
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        assert isinstance(audit, BrazilRAGAuditRecord)
        assert audit.documents_evaluated == 1

    def test_21_public_doc_passes_all_layers(self):
        """Test 21: A PUBLIC/non-personal document passes all four pipeline layers."""
        pipeline = BrazilLGPDRAGPipeline()
        ctx = _ctx(lgpd_legal_basis="none", requester_is_data_subject=False)
        doc = _public_doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 1

    def test_22_redacted_doc_included_in_results(self):
        """Test 22: A document with a deletion request is returned (REDACTED, not excluded)."""
        pipeline = BrazilLGPDRAGPipeline()
        ctx = _ctx(
            lgpd_legal_basis="consent",
            has_explicit_consent=True,
            is_legal_override=False,
        )
        doc = _doc(data_subject_requested_deletion=True)
        results = pipeline.retrieve(ctx, [doc])
        # REDACTED documents are not denied — they pass through and are included
        assert len(results) == 1
        # The retention layer result should be REDACTED
        retention_result = results[0][1][2]  # Layer 3 (index 2) is LGPDDataRetentionFilter
        assert retention_result.decision == Decision.REDACTED


# ---------------------------------------------------------------------------
# Tests 23–27: BrazilRAGAuditRecord.to_audit_log() format
# ---------------------------------------------------------------------------

class TestBrazilRAGAuditRecord:
    """Tests 23-27: audit log structure and field correctness."""

    def _run_audit(self, docs, ctx=None):
        if ctx is None:
            ctx = _ctx()
        pipeline = BrazilLGPDRAGPipeline()
        return pipeline.retrieve_with_audit(ctx, docs)

    def test_23_audit_log_event_name(self):
        """Test 23: to_audit_log() returns the correct LGPD event name."""
        audit = self._run_audit([_doc()])
        log = audit.to_audit_log()
        assert log["event"] == "BRAZIL_LGPD_RAG_RETRIEVAL"

    def test_24_audit_log_document_counts(self):
        """Test 24: Audit log documents_evaluated/permitted/denied counts are correct."""
        ctx = _ctx(
            lgpd_legal_basis="consent",
            has_explicit_consent=True,
            authorized_data_categories=frozenset({"contact", "financial"}),
        )
        # doc1 passes all layers; doc2 is denied at minimization (unauthorized category)
        doc1 = _doc(document_id="d1", data_categories_present=frozenset({"contact"}))
        doc2 = _doc(document_id="d2", data_categories_present=frozenset({"health"}))
        pipeline = BrazilLGPDRAGPipeline()
        audit = pipeline.retrieve_with_audit(ctx, [doc1, doc2])
        log = audit.to_audit_log()
        assert log["documents_evaluated"] == 2
        assert log["documents_permitted"] == 1
        assert log["documents_denied"] == 1

    def test_25_audit_log_required_fields(self):
        """Test 25: Audit log contains all required top-level fields."""
        audit = self._run_audit([_doc()])
        log = audit.to_audit_log()
        required = {
            "event", "user_id", "requester_role", "requester_jurisdiction",
            "lgpd_legal_basis", "processing_purpose", "documents_evaluated",
            "documents_permitted", "documents_denied", "documents_redacted",
            "filter_results", "timestamp",
        }
        assert required.issubset(set(log.keys()))

    def test_26_audit_log_filter_results_structure(self):
        """Test 26: filter_results entries contain document_id, final_decision, layer_results."""
        audit = self._run_audit([_doc(document_id="doc-x")])
        log = audit.to_audit_log()
        assert len(log["filter_results"]) == 1
        fr = log["filter_results"][0]
        assert fr["document_id"] == "doc-x"
        assert "final_decision" in fr
        assert "layer_results" in fr

    def test_27_redacted_document_counted_in_redacted(self):
        """Test 27: documents_redacted count increments for REDACTED decisions."""
        ctx = _ctx(lgpd_legal_basis="consent", is_legal_override=False)
        doc = _doc(data_subject_requested_deletion=True)
        pipeline = BrazilLGPDRAGPipeline()
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        log = audit.to_audit_log()
        assert log["documents_redacted"] == 1
        assert log["documents_denied"] == 0


# ---------------------------------------------------------------------------
# Tests 28–36: Edge cases and additional coverage
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Tests 28-36: edge cases, citation checks, and boundary conditions."""

    def test_28_non_personal_data_skips_subject_filter(self):
        """Test 28: Non-personal data is permitted by LGPDDataSubjectFilter without checks."""
        f = LGPDDataSubjectFilter()
        ctx = _ctx(lgpd_legal_basis="none", requester_is_data_subject=False)
        doc = _public_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_29_filter_result_is_denied_property(self):
        """Test 29: FilterResult.is_denied is True only for DENIED, not REDACTED."""
        denied = FilterResult(
            layer="TEST", decision=Decision.DENIED, reason="r", regulation_citation="c"
        )
        redacted = FilterResult(
            layer="TEST", decision=Decision.REDACTED, reason="r", regulation_citation="c"
        )
        permitted = FilterResult(
            layer="TEST", decision=Decision.PERMITTED, reason="r", regulation_citation="c"
        )
        assert denied.is_denied is True
        assert redacted.is_denied is False
        assert permitted.is_denied is False

    def test_30_pipeline_stops_on_first_denied(self):
        """Test 30: Pipeline stops after the first DENIED and records only layers up to that point."""
        pipeline = BrazilLGPDRAGPipeline()
        ctx = _ctx(lgpd_legal_basis="none", requester_is_data_subject=False)
        doc = _doc()
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        log = audit.to_audit_log()
        fr = log["filter_results"][0]
        assert fr["final_decision"] == "DENIED"
        # Only layer 1 (data subject filter) should have run
        assert len(fr["layer_results"]) == 1
        assert fr["layer_results"][0]["layer"] == LGPDDataSubjectFilter.LAYER_NAME

    def test_31_uk_adequate_jurisdiction_permitted(self):
        """Test 31: UK jurisdiction is treated as adequate under LGPD Art. 33."""
        f = LGPDCrossBorderFilter()
        ctx = _ctx(requester_jurisdiction="UK")
        doc = _doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_32_non_adequate_with_scc_permitted(self):
        """Test 32: Non-adequate jurisdiction is permitted when SCC/BCR mechanism is in place."""
        f = LGPDCrossBorderFilter()
        ctx = _ctx(requester_jurisdiction="US", has_lgpd_transfer_mechanism=True)
        doc = _doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_33_data_subject_bypasses_no_legal_basis(self):
        """Test 33: Data subject can access own data even when legal basis is 'none'."""
        pipeline = BrazilLGPDRAGPipeline()
        ctx = _ctx(
            lgpd_legal_basis="none",
            requester_is_data_subject=True,
            authorized_data_categories=frozenset({"contact", "financial"}),
        )
        doc = _doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 1

    def test_34_explicit_consent_permits_sensitive_data(self):
        """Test 34: Explicit consent permits access to sensitive personal data (Art. 11)."""
        f = LGPDDataSubjectFilter()
        ctx = _ctx(
            lgpd_legal_basis="consent",
            has_explicit_consent=True,
            requester_is_data_subject=False,
        )
        doc = _sensitive_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_35_mixed_batch_filters_correctly(self):
        """Test 35: Pipeline correctly permits some and denies others in a mixed batch."""
        pipeline = BrazilLGPDRAGPipeline()
        ctx = _ctx(
            lgpd_legal_basis="consent",
            has_explicit_consent=True,
            authorized_data_categories=frozenset({"contact", "financial"}),
        )
        ok_doc = _doc(document_id="ok", data_categories_present=frozenset({"contact"}))
        bad_doc = _doc(document_id="bad", data_categories_present=frozenset({"health"}))
        results = pipeline.retrieve(ctx, [ok_doc, bad_doc])
        permitted_ids = [r[0].document_id for r in results]
        assert "ok" in permitted_ids
        assert "bad" not in permitted_ids

    def test_36_all_valid_legal_bases_accepted(self):
        """Test 36: All seven Art. 7 valid legal bases are accepted by LGPDDataSubjectFilter."""
        f = LGPDDataSubjectFilter()
        doc = _doc(contains_sensitive_data=False)
        valid_bases = [
            "consent", "legitimate_interest", "legal_obligation",
            "contract", "vital_interests", "public_task", "official_authority",
        ]
        for basis in valid_bases:
            ctx = _ctx(lgpd_legal_basis=basis, requester_is_data_subject=False)
            result = f.evaluate(ctx, doc)
            assert result.decision == Decision.PERMITTED, (
                f"Expected PERMITTED for legal basis '{basis}', got {result.decision}"
            )
