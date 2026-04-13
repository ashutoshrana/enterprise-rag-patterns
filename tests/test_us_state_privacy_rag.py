"""
Tests for 39_us_state_privacy_rag.py

Covers ColoradoCPAFilter, VirginiaVCDPAFilter, TexasTDPSAFilter,
USStatePrivacyCrossBorderFilter, USStatePrivacyRAGPipeline, and
USStatePrivacyAuditRecord.

42 tests total:
  [1-10]  ColoradoCPAFilter
  [11-20] VirginiaVCDPAFilter
  [21-29] TexasTDPSAFilter
  [30-38] USStatePrivacyCrossBorderFilter
  [39-42] Pipeline — filter_documents and filter_documents_with_audit
  [43-44] Full-stack integration and edge cases  (indices shift; 42 total)
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "us_state_privacy_rag_39"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "39_us_state_privacy_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
USStatePrivacyContext = mod.USStatePrivacyContext
USStatePrivacyDocument = mod.USStatePrivacyDocument
FilterResult = mod.FilterResult
ColoradoCPAFilter = mod.ColoradoCPAFilter
VirginiaVCDPAFilter = mod.VirginiaVCDPAFilter
TexasTDPSAFilter = mod.TexasTDPSAFilter
USStatePrivacyCrossBorderFilter = mod.USStatePrivacyCrossBorderFilter
USStatePrivacyRAGPipeline = mod.USStatePrivacyRAGPipeline
USStatePrivacyAuditRecord = mod.USStatePrivacyAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    user_id: str = "user-001",
    role: str = "data_controller",
    # Layer 1 — Colorado CPA
    data_type: str = "",
    opt_out_offered: bool = False,
    automated_profiling: bool = False,
    sale_of_data: bool = False,
    # Layer 2 — Virginia CDPA
    automated_decision: bool = False,
    legal_or_significant_effect: bool = False,
    human_review_available: bool = False,
    targeted_advertising: bool = False,
    # Layer 3 — Texas TDPSA
    minor_data: bool = False,
    # Layer 4 — Cross-border
    consumer_state: str = "",
    ccpa_compliant: bool = False,
    state_consent_obtained: bool = False,
) -> object:
    return USStatePrivacyContext(
        user_id=user_id,
        role=role,
        data_type=data_type,
        opt_out_offered=opt_out_offered,
        automated_profiling=automated_profiling,
        sale_of_data=sale_of_data,
        automated_decision=automated_decision,
        legal_or_significant_effect=legal_or_significant_effect,
        human_review_available=human_review_available,
        targeted_advertising=targeted_advertising,
        minor_data=minor_data,
        consumer_state=consumer_state,
        ccpa_compliant=ccpa_compliant,
        state_consent_obtained=state_consent_obtained,
    )


def _doc(
    *,
    content: str = "Consumer data record.",
    document_id: str = "doc-001",
    doc_type: str = "consumer_profile",
) -> object:
    return USStatePrivacyDocument(
        content=content,
        document_id=document_id,
        doc_type=doc_type,
    )


# ---------------------------------------------------------------------------
# [1-10] ColoradoCPAFilter
# ---------------------------------------------------------------------------


class TestColoradoCPAFilter:
    def setup_method(self):
        self.f = ColoradoCPAFilter()

    def test_01_sensitive_data_type_denied(self):
        """CPA: 'sensitive' data_type is DENIED (CRS §6-1-1303(19))."""
        ctx = _ctx(data_type="sensitive")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§6-1-1303(19)" in result.regulation_citation

    def test_02_biometric_data_type_denied(self):
        """CPA: 'biometric' data_type is DENIED (CRS §6-1-1303(19))."""
        ctx = _ctx(data_type="biometric")
        result = self.f.evaluate(ctx, _doc(doc_type="biometric_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§6-1-1303(19)" in result.regulation_citation

    def test_03_health_data_type_denied(self):
        """CPA: 'health' data_type is DENIED (CRS §6-1-1303(19))."""
        ctx = _ctx(data_type="health")
        result = self.f.evaluate(ctx, _doc(doc_type="health_record"))
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_04_precise_geolocation_denied(self):
        """CPA: 'precise_geolocation' data_type is DENIED (CRS §6-1-1303(19))."""
        ctx = _ctx(data_type="precise_geolocation")
        result = self.f.evaluate(ctx, _doc(doc_type="location_record"))
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_05_racial_origin_denied(self):
        """CPA: 'racial_origin' data_type is DENIED (CRS §6-1-1303(19))."""
        ctx = _ctx(data_type="racial_origin")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_06_automated_profiling_without_opt_out_requires_review(self):
        """CPA: automated_profiling without opt_out_offered triggers REQUIRES_HUMAN_REVIEW."""
        ctx = _ctx(data_type="standard", automated_profiling=True, opt_out_offered=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§6-1-1306(1)(a)(IV)" in result.regulation_citation

    def test_07_automated_profiling_with_opt_out_approved(self):
        """CPA: automated_profiling WITH opt_out_offered is APPROVED."""
        ctx = _ctx(data_type="standard", automated_profiling=True, opt_out_offered=True)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_08_sale_of_data_without_opt_out_denied(self):
        """CPA: sale_of_data without opt_out_offered is DENIED (CRS §6-1-1306(1)(a)(III))."""
        ctx = _ctx(data_type="standard", sale_of_data=True, opt_out_offered=False)
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§6-1-1306(1)(a)(III)" in result.regulation_citation

    def test_09_sale_of_data_with_opt_out_approved(self):
        """CPA: sale_of_data WITH opt_out_offered is APPROVED."""
        ctx = _ctx(data_type="standard", sale_of_data=True, opt_out_offered=True)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_10_standard_data_type_no_flags_approved(self):
        """CPA: standard data_type with no restricted flags is APPROVED."""
        ctx = _ctx(data_type="standard")
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "§6-1-1301" in result.regulation_citation


# ---------------------------------------------------------------------------
# [11-20] VirginiaVCDPAFilter
# ---------------------------------------------------------------------------


class TestVirginiaVCDPAFilter:
    def setup_method(self):
        self.f = VirginiaVCDPAFilter()

    def test_11_sensitive_data_type_denied(self):
        """CDPA: 'sensitive' data_type is DENIED (Va. Code §59.1-578(A))."""
        ctx = _ctx(data_type="sensitive")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§59.1-578(A)" in result.regulation_citation

    def test_12_biometric_data_type_denied(self):
        """CDPA: 'biometric' data_type is DENIED (Va. Code §59.1-578(A))."""
        ctx = _ctx(data_type="biometric")
        result = self.f.evaluate(ctx, _doc(doc_type="biometric_record"))
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_13_mental_health_data_type_denied(self):
        """CDPA: 'mental_health' data_type is DENIED (Va. Code §59.1-578(A))."""
        ctx = _ctx(data_type="mental_health")
        result = self.f.evaluate(ctx, _doc(doc_type="health_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§59.1-578(A)" in result.regulation_citation

    def test_14_racial_ethnic_data_type_denied(self):
        """CDPA: 'racial_ethnic' data_type is DENIED (Va. Code §59.1-578(A))."""
        ctx = _ctx(data_type="racial_ethnic")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_15_automated_decision_significant_without_review_requires_review(self):
        """CDPA: automated_decision + legal_or_significant_effect + no human_review -> REQUIRES_HUMAN_REVIEW."""
        ctx = _ctx(
            data_type="standard",
            automated_decision=True,
            legal_or_significant_effect=True,
            human_review_available=False,
        )
        result = self.f.evaluate(ctx, _doc(doc_type="automated_decision_record"))
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§59.1-579" in result.regulation_citation

    def test_16_automated_decision_with_human_review_approved(self):
        """CDPA: automated_decision + legal_or_significant_effect WITH human_review is APPROVED."""
        ctx = _ctx(
            data_type="standard",
            automated_decision=True,
            legal_or_significant_effect=True,
            human_review_available=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_17_automated_decision_no_significant_effect_approved(self):
        """CDPA: automated_decision without legal_or_significant_effect is APPROVED."""
        ctx = _ctx(data_type="standard", automated_decision=True, legal_or_significant_effect=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_18_targeted_advertising_without_opt_out_denied(self):
        """CDPA: targeted_advertising without opt_out_offered is DENIED (§59.1-578(A)(3))."""
        ctx = _ctx(data_type="standard", targeted_advertising=True, opt_out_offered=False)
        result = self.f.evaluate(ctx, _doc(doc_type="ad_targeting_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§59.1-578(A)(3)" in result.regulation_citation

    def test_19_targeted_advertising_with_opt_out_approved(self):
        """CDPA: targeted_advertising WITH opt_out_offered is APPROVED."""
        ctx = _ctx(data_type="standard", targeted_advertising=True, opt_out_offered=True)
        result = self.f.evaluate(ctx, _doc(doc_type="ad_targeting_record"))
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_20_standard_data_no_flags_approved(self):
        """CDPA: standard data_type with no restricted flags is APPROVED."""
        ctx = _ctx(data_type="standard")
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "§59.1-571" in result.regulation_citation


# ---------------------------------------------------------------------------
# [21-29] TexasTDPSAFilter
# ---------------------------------------------------------------------------


class TestTexasTDPSAFilter:
    def setup_method(self):
        self.f = TexasTDPSAFilter()

    def test_21_sensitive_data_type_denied(self):
        """TDPSA: 'sensitive' data_type is DENIED (Tex. §541.101)."""
        ctx = _ctx(data_type="sensitive")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§541.101" in result.regulation_citation

    def test_22_biometric_data_type_denied(self):
        """TDPSA: 'biometric' data_type is DENIED (Tex. §541.101)."""
        ctx = _ctx(data_type="biometric")
        result = self.f.evaluate(ctx, _doc(doc_type="biometric_record"))
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_23_health_data_type_denied(self):
        """TDPSA: 'health' data_type is DENIED (Tex. §541.101)."""
        ctx = _ctx(data_type="health")
        result = self.f.evaluate(ctx, _doc(doc_type="health_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§541.101" in result.regulation_citation

    def test_24_precise_geolocation_denied(self):
        """TDPSA: 'precise_geolocation' data_type is DENIED (Tex. §541.101)."""
        ctx = _ctx(data_type="precise_geolocation")
        result = self.f.evaluate(ctx, _doc(doc_type="location_record"))
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_25_sale_of_data_without_opt_out_denied(self):
        """TDPSA: sale_of_data without opt_out_offered is DENIED (§541.052(a)(2))."""
        ctx = _ctx(data_type="standard", sale_of_data=True, opt_out_offered=False)
        result = self.f.evaluate(ctx, _doc(doc_type="sale_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§541.052(a)(2)" in result.regulation_citation

    def test_26_sale_of_data_with_opt_out_approved(self):
        """TDPSA: sale_of_data WITH opt_out_offered is APPROVED."""
        ctx = _ctx(data_type="standard", sale_of_data=True, opt_out_offered=True)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_27_minor_data_denied(self):
        """TDPSA: minor_data flag is DENIED (§541.101(b))."""
        ctx = _ctx(data_type="standard", minor_data=True)
        result = self.f.evaluate(ctx, _doc(doc_type="minor_data_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§541.101(b)" in result.regulation_citation

    def test_28_minor_data_with_sensitive_type_denied_on_sensitive_first(self):
        """TDPSA: sensitive data_type is checked before minor_data — DENIED on §541.101."""
        ctx = _ctx(data_type="biometric", minor_data=True)
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§541.101" in result.regulation_citation

    def test_29_standard_data_no_flags_approved(self):
        """TDPSA: standard data_type with no restricted flags is APPROVED."""
        ctx = _ctx(data_type="standard")
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "§541" in result.regulation_citation


# ---------------------------------------------------------------------------
# [30-38] USStatePrivacyCrossBorderFilter
# ---------------------------------------------------------------------------


class TestUSStatePrivacyCrossBorderFilter:
    def setup_method(self):
        self.f = USStatePrivacyCrossBorderFilter()

    def test_30_california_consumer_without_ccpa_compliance_denied(self):
        """Cross-border: California consumer without CCPA compliance is DENIED (§1798.100)."""
        ctx = _ctx(consumer_state="California", ccpa_compliant=False)
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§1798.100" in result.regulation_citation

    def test_31_california_consumer_with_ccpa_compliance_approved(self):
        """Cross-border: California consumer WITH CCPA compliance is APPROVED."""
        ctx = _ctx(consumer_state="California", ccpa_compliant=True)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_32_colorado_consumer_sensitive_without_consent_denied(self):
        """Cross-border: Colorado consumer with sensitive data and no consent is DENIED."""
        ctx = _ctx(
            consumer_state="Colorado",
            data_type="sensitive",
            state_consent_obtained=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_33_virginia_consumer_biometric_without_consent_denied(self):
        """Cross-border: Virginia consumer with biometric data and no consent is DENIED."""
        ctx = _ctx(
            consumer_state="Virginia",
            data_type="biometric",
            state_consent_obtained=False,
        )
        result = self.f.evaluate(ctx, _doc(doc_type="biometric_record"))
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_34_texas_consumer_sensitive_without_consent_denied(self):
        """Cross-border: Texas consumer with sensitive data and no consent is DENIED."""
        ctx = _ctx(
            consumer_state="Texas",
            data_type="sensitive",
            state_consent_obtained=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_35_connecticut_consumer_sensitive_without_consent_denied(self):
        """Cross-border: Connecticut consumer with sensitive data and no state consent is DENIED."""
        ctx = _ctx(
            consumer_state="Connecticut",
            data_type="biometric",
            state_consent_obtained=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_36_connecticut_consumer_automated_decision_without_opt_out_requires_review(self):
        """Cross-border: Connecticut consumer automated_decision without opt_out -> REQUIRES_HUMAN_REVIEW."""
        ctx = _ctx(
            consumer_state="Connecticut",
            data_type="standard",
            automated_decision=True,
            opt_out_offered=False,
            state_consent_obtained=True,
        )
        result = self.f.evaluate(ctx, _doc(doc_type="automated_decision_record"))
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "Conn. PA 22-15 §14" in result.regulation_citation

    def test_37_connecticut_consumer_automated_decision_with_opt_out_approved(self):
        """Cross-border: Connecticut consumer automated_decision WITH opt_out is APPROVED."""
        ctx = _ctx(
            consumer_state="Connecticut",
            data_type="standard",
            automated_decision=True,
            opt_out_offered=True,
            state_consent_obtained=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_38_no_consumer_state_standard_data_approved(self):
        """Cross-border: empty consumer_state with standard data is APPROVED."""
        ctx = _ctx(consumer_state="", data_type="standard")
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "CPA/VCDPA/TDPSA/CTDPA" in result.reason or "Multi-state" in result.reason


# ---------------------------------------------------------------------------
# [39-42] Pipeline — filter_documents and filter_documents_with_audit
# ---------------------------------------------------------------------------


class TestUSStatePrivacyRAGPipeline:
    def setup_method(self):
        self.pipeline = USStatePrivacyRAGPipeline()

    def test_39_clean_standard_data_all_documents_pass(self):
        """Pipeline: clean standard data context with opt-out passes all documents."""
        ctx = _ctx(
            data_type="standard",
            opt_out_offered=True,
            sale_of_data=False,
            automated_profiling=False,
            targeted_advertising=False,
            minor_data=False,
            consumer_state="",
        )
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 3

    def test_40_sensitive_data_type_excluded_in_pipeline(self):
        """Pipeline: sensitive data_type document is excluded from result."""
        ctx = _ctx(data_type="sensitive")
        docs = [_doc(document_id="doc-deny-sensitive")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_41_empty_document_list_returns_empty(self):
        """Pipeline: empty document list returns empty result."""
        ctx = _ctx()
        result = self.pipeline.filter_documents(ctx, [])
        assert result == []

    def test_42_audit_record_type_and_structure(self):
        """Pipeline: filter_documents_with_audit returns USStatePrivacyAuditRecord with correct keys."""
        ctx = _ctx(data_type="standard", consumer_state="")
        docs = [_doc()]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert isinstance(record, USStatePrivacyAuditRecord)
        log = record.to_audit_log()
        assert isinstance(log, dict)
        required_keys = {
            "event",
            "user_id",
            "role",
            "data_type",
            "consumer_state",
            "documents_in",
            "documents_out",
            "decisions",
            "timestamp",
        }
        assert required_keys.issubset(set(log.keys()))
        assert log["event"] == "US_STATE_PRIVACY_RAG_RETRIEVAL"
        assert log["documents_in"] == 1


# ---------------------------------------------------------------------------
# Full-stack integration and edge cases
# ---------------------------------------------------------------------------


class TestFullStackAndEdgeCases:
    def setup_method(self):
        self.pipeline = USStatePrivacyRAGPipeline()

    def test_43_cross_filter_integration_all_four_pass(self):
        """A fully compliant document passes all four filter layers end-to-end."""
        ctx = _ctx(
            data_type="standard",
            opt_out_offered=True,
            automated_profiling=False,
            sale_of_data=False,
            automated_decision=False,
            legal_or_significant_effect=False,
            human_review_available=False,
            targeted_advertising=False,
            minor_data=False,
            consumer_state="",
            ccpa_compliant=True,
            state_consent_obtained=True,
        )
        docs = [_doc(document_id="doc-all-pass")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_44_context_and_document_are_frozen_dataclasses(self):
        """USStatePrivacyContext and USStatePrivacyDocument are frozen=True."""
        import dataclasses

        ctx = _ctx()
        assert dataclasses.is_dataclass(ctx)
        ctx_raised = False
        try:
            ctx.role = "hacker"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            ctx_raised = True
        assert ctx_raised, "USStatePrivacyContext must be frozen"

        doc = _doc()
        assert dataclasses.is_dataclass(doc)
        doc_raised = False
        try:
            doc.content = "tampered"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            doc_raised = True
        assert doc_raised, "USStatePrivacyDocument must be frozen"

    def test_45_filter_result_is_denied_semantics(self):
        """FilterResult.is_denied is True only for DENIED; False for APPROVED and REQUIRES_HUMAN_REVIEW."""
        denied = FilterResult(layer="L", decision="DENIED", reason="r", regulation_citation="c")
        approved = FilterResult(layer="L", decision="APPROVED", reason="r", regulation_citation="c")
        review = FilterResult(layer="L", decision="REQUIRES_HUMAN_REVIEW", reason="r", regulation_citation="c")
        assert denied.is_denied is True
        assert approved.is_denied is False
        assert review.is_denied is False

    def test_46_missing_keys_default_to_approved(self):
        """Context with all defaults (no restricted flags) produces APPROVED pipeline result."""
        ctx = USStatePrivacyContext(
            user_id="default-user",
        )
        docs = [_doc(document_id="doc-default")]
        result = self.pipeline.filter_documents(ctx, docs)
        # With default values (data_type="", no sale, no profiling, no ad targeting,
        # no minor_data, empty consumer_state), all layers should approve.
        assert len(result) == 1

    def test_47_california_minor_data_denied_by_layer_3(self):
        """California minor_data is DENIED at layer 3 (TDPSA) regardless of CCPA compliance."""
        ctx = _ctx(
            consumer_state="California",
            ccpa_compliant=True,  # CCPA compliant — would pass layer 4
            minor_data=True,  # TDPSA layer 3 should catch this
            data_type="standard",
        )
        docs = [_doc(document_id="doc-ca-minor")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_48_virginia_sensitive_denied_by_layer_2(self):
        """Virginia sensitive data is DENIED at layer 2 (VCDPA) before reaching layer 4."""
        ctx = _ctx(
            consumer_state="Virginia",
            data_type="mental_health",
            state_consent_obtained=True,  # layer 4 would have passed this
        )
        docs = [_doc(document_id="doc-va-sensitive")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_49_audit_denied_document_not_counted_in_documents_out(self):
        """Audit record: DENIED document is excluded from documents_out count."""
        ctx = _ctx(data_type="biometric")
        docs = [_doc(document_id="doc-denied")]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_out == 0
        assert record.documents_in == 1
        log = record.to_audit_log()
        assert log["documents_out"] == 0
        assert log["decisions"][0]["final_decision"] == "DENIED"

    def test_50_connecticut_automated_decision_requires_review_document_included(self):
        """CTDPA REQUIRES_HUMAN_REVIEW (CT automated decision) does not exclude document from pipeline."""
        ctx = _ctx(
            consumer_state="Connecticut",
            data_type="standard",
            automated_decision=True,
            opt_out_offered=False,
            state_consent_obtained=True,
        )
        docs = [_doc(document_id="doc-ct-review")]
        result = self.pipeline.filter_documents(ctx, docs)
        # REQUIRES_HUMAN_REVIEW does NOT deny; document should be included
        assert len(result) == 1
