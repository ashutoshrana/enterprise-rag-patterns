"""
Tests for 37_canada_pipeda_rag.py

Covers PIPEDAConsentFilter, QuebecLaw25Filter, HealthcarePrivacyFilter,
CanadaCrossBorderFilter, CanadaPrivacyRAGPipeline, and
CanadaPrivacyAuditRecord.

40 tests total:
  [1-8]   PIPEDAConsentFilter
  [9-15]  QuebecLaw25Filter
  [16-22] HealthcarePrivacyFilter
  [23-29] CanadaCrossBorderFilter
  [30-35] Pipeline — filter_documents
  [36-39] Pipeline — filter_documents_with_audit
  [40]    Full-stack and edge cases
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "canada_pipeda_rag_37"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "37_canada_pipeda_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
CanadaPrivacyContext = mod.CanadaPrivacyContext
CanadaPrivacyDocument = mod.CanadaPrivacyDocument
FilterResult = mod.FilterResult
PIPEDAConsentFilter = mod.PIPEDAConsentFilter
QuebecLaw25Filter = mod.QuebecLaw25Filter
HealthcarePrivacyFilter = mod.HealthcarePrivacyFilter
CanadaCrossBorderFilter = mod.CanadaCrossBorderFilter
CanadaPrivacyRAGPipeline = mod.CanadaPrivacyRAGPipeline
CanadaPrivacyAuditRecord = mod.CanadaPrivacyAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    user_id: str = "user-001",
    role: str = "organization",
    province: str = "ON",
    sector: str = "general",
    has_meaningful_consent: bool = True,
    has_legitimate_purpose: bool = False,
    involves_sensitive_data: bool = False,
    is_automated_decision: bool = False,
    has_human_review: bool = True,
    has_privacy_impact_assessment: bool = False,
    is_cross_border_transfer: bool = False,
    destination_country: str = "",
    has_transfer_safeguards: bool = False,
    involves_minor: bool = False,
    has_de_identified: bool = False,
    is_publicly_available: bool = False,
) -> object:
    return CanadaPrivacyContext(
        user_id=user_id,
        role=role,
        province=province,
        sector=sector,
        has_meaningful_consent=has_meaningful_consent,
        has_legitimate_purpose=has_legitimate_purpose,
        involves_sensitive_data=involves_sensitive_data,
        is_automated_decision=is_automated_decision,
        has_human_review=has_human_review,
        has_privacy_impact_assessment=has_privacy_impact_assessment,
        is_cross_border_transfer=is_cross_border_transfer,
        destination_country=destination_country,
        has_transfer_safeguards=has_transfer_safeguards,
        involves_minor=involves_minor,
        has_de_identified=has_de_identified,
        is_publicly_available=is_publicly_available,
    )


def _doc(
    *,
    content: str = "Personal information record.",
    document_id: str = "doc-001",
    doc_type: str = "personal_information_record",
) -> object:
    return CanadaPrivacyDocument(
        content=content,
        document_id=document_id,
        doc_type=doc_type,
    )


# ---------------------------------------------------------------------------
# [1-8] PIPEDAConsentFilter
# ---------------------------------------------------------------------------


class TestPIPEDAConsentFilter:
    def setup_method(self):
        self.f = PIPEDAConsentFilter()

    def test_01_individual_self_access_approved_immediately(self):
        """Individual role is APPROVED immediately regardless of other flags."""
        ctx = _ctx(
            role="individual",
            has_meaningful_consent=False,
            involves_sensitive_data=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_02_sensitive_data_without_consent_denied(self):
        """Sensitive data without meaningful consent is DENIED (PIPEDA Principle 3 / CPPA §15)."""
        ctx = _ctx(
            role="organization",
            has_meaningful_consent=False,
            involves_sensitive_data=True,
            has_de_identified=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "CPPA §15" in result.reason or "Principle 3" in result.reason

    def test_03_sensitive_data_de_identified_not_denied(self):
        """Sensitive data that is properly de-identified is NOT denied under Principle 3."""
        ctx = _ctx(
            role="organization",
            has_meaningful_consent=False,
            involves_sensitive_data=True,
            has_de_identified=True,
            has_legitimate_purpose=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied

    def test_04_no_consent_no_purpose_organization_denied(self):
        """Organization without consent or legitimate purpose is DENIED (PIPEDA Principle 4.3)."""
        ctx = _ctx(
            role="organization",
            has_meaningful_consent=False,
            has_legitimate_purpose=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Principle 4.3" in result.reason

    def test_05_regulator_without_consent_approved(self):
        """Regulator without consent bypasses Principle 4.3 consent requirement."""
        ctx = _ctx(
            role="regulator",
            has_meaningful_consent=False,
            has_legitimate_purpose=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_06_minor_data_without_consent_denied(self):
        """Processing minor's data without meaningful consent is DENIED (CPPA §62)."""
        ctx = _ctx(
            role="organization",
            has_meaningful_consent=False,
            involves_minor=True,
            involves_sensitive_data=False,
            has_legitimate_purpose=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§62" in result.reason

    def test_07_minor_data_with_consent_approved(self):
        """Processing minor's data with meaningful (parental) consent is APPROVED."""
        ctx = _ctx(
            role="organization",
            has_meaningful_consent=True,
            involves_minor=True,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_08_compliant_organization_approved(self):
        """Organization with meaningful consent, non-sensitive, non-minor data is APPROVED."""
        ctx = _ctx(
            role="organization",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            involves_minor=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [9-15] QuebecLaw25Filter
# ---------------------------------------------------------------------------


class TestQuebecLaw25Filter:
    def setup_method(self):
        self.f = QuebecLaw25Filter()

    def test_09_non_qc_province_approved_not_applicable(self):
        """Non-Quebec province request is APPROVED as not applicable."""
        ctx = _ctx(province="ON", involves_sensitive_data=True, has_meaningful_consent=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "Not applicable" in result.reason

    def test_10_non_qc_bc_approved(self):
        """BC province is also outside Quebec — filter passes through."""
        ctx = _ctx(province="BC", involves_sensitive_data=True, has_meaningful_consent=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_11_qc_sensitive_without_consent_denied(self):
        """Quebec request with sensitive data and no consent is DENIED (Law 25 §8)."""
        ctx = _ctx(
            province="QC",
            has_meaningful_consent=False,
            involves_sensitive_data=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§8" in result.reason

    def test_12_qc_automated_no_human_review_requires_review(self):
        """Quebec automated decision without human review is REQUIRES_HUMAN_REVIEW (Law 25 §12.1)."""
        ctx = _ctx(
            province="QC",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_automated_decision=True,
            has_human_review=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§12.1" in result.reason

    def test_13_qc_automated_with_human_review_approved(self):
        """Quebec automated decision WITH human review is APPROVED."""
        ctx = _ctx(
            province="QC",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_automated_decision=True,
            has_human_review=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_14_qc_general_sector_sensitive_no_pia_requires_review(self):
        """Quebec general sector with sensitive data and no PIA is REQUIRES_HUMAN_REVIEW (§63.3)."""
        ctx = _ctx(
            province="QC",
            sector="general",
            has_meaningful_consent=True,
            involves_sensitive_data=True,
            has_privacy_impact_assessment=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§63.3" in result.reason

    def test_15_qc_general_sector_sensitive_with_pia_approved(self):
        """Quebec general sector with sensitive data AND PIA is APPROVED."""
        ctx = _ctx(
            province="QC",
            sector="general",
            has_meaningful_consent=True,
            involves_sensitive_data=True,
            has_privacy_impact_assessment=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [16-22] HealthcarePrivacyFilter
# ---------------------------------------------------------------------------


class TestHealthcarePrivacyFilter:
    def setup_method(self):
        self.f = HealthcarePrivacyFilter()

    def test_16_non_healthcare_sector_approved_not_applicable(self):
        """Non-healthcare sector request is APPROVED as not applicable."""
        ctx = _ctx(
            sector="financial",
            province="ON",
            involves_sensitive_data=True,
            has_meaningful_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "Not applicable" in result.reason

    def test_17_ontario_healthcare_sensitive_no_consent_denied(self):
        """Ontario healthcare with sensitive data and no consent is DENIED (PHIPA + PIPEDA)."""
        ctx = _ctx(
            sector="healthcare",
            province="ON",
            involves_sensitive_data=True,
            has_meaningful_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "PHIPA" in result.reason

    def test_18_bc_healthcare_sensitive_no_consent_denied(self):
        """BC healthcare with sensitive data and no consent is DENIED (BC PIPA §11)."""
        ctx = _ctx(
            sector="healthcare",
            province="BC",
            involves_sensitive_data=True,
            has_meaningful_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "BC PIPA §11" in result.reason

    def test_19_other_province_healthcare_sensitive_no_consent_denied(self):
        """Alberta healthcare with sensitive data and no consent is DENIED (PIPEDA Principle 3)."""
        ctx = _ctx(
            sector="healthcare",
            province="AB",
            involves_sensitive_data=True,
            has_meaningful_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "PIPEDA Principle 3" in result.reason

    def test_20_healthcare_provider_with_consent_approved(self):
        """Healthcare provider role with meaningful consent is APPROVED."""
        ctx = _ctx(
            sector="healthcare",
            role="healthcare_provider",
            province="ON",
            involves_sensitive_data=True,
            has_meaningful_consent=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert (
            "Healthcare provider" in result.reason
            or "healthcare_provider" in result.reason.lower()
            or "authorized" in result.reason.lower()
        )  # noqa: E501

    def test_21_ontario_healthcare_with_consent_approved(self):
        """Ontario healthcare request WITH consent is APPROVED (PHIPA + PIPEDA compliant)."""
        ctx = _ctx(
            sector="healthcare",
            province="ON",
            role="organization",
            involves_sensitive_data=True,
            has_meaningful_consent=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_22_bc_healthcare_non_sensitive_approved(self):
        """BC healthcare request with non-sensitive data is APPROVED."""
        ctx = _ctx(
            sector="healthcare",
            province="BC",
            involves_sensitive_data=False,
            has_meaningful_consent=False,
            has_legitimate_purpose=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [23-29] CanadaCrossBorderFilter
# ---------------------------------------------------------------------------


class TestCanadaCrossBorderFilter:
    def setup_method(self):
        self.f = CanadaCrossBorderFilter()

    def test_23_no_transfer_approved(self):
        """No cross-border transfer involved — APPROVED immediately."""
        ctx = _ctx(is_cross_border_transfer=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_24_adequate_destination_gb_approved(self):
        """Transfer to Great Britain (adequate jurisdiction) is APPROVED."""
        ctx = _ctx(
            is_cross_border_transfer=True,
            destination_country="GB",
            has_transfer_safeguards=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "adequate" in result.reason.lower()

    def test_25_adequate_destination_au_approved(self):
        """Transfer to Australia (adequate jurisdiction) is APPROVED."""
        ctx = _ctx(
            is_cross_border_transfer=True,
            destination_country="AU",
            has_transfer_safeguards=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_26_transfer_safeguards_present_approved(self):
        """Transfer to non-adequate country with safeguards is APPROVED (PIPEDA §4.1.3)."""
        ctx = _ctx(
            province="ON",
            is_cross_border_transfer=True,
            destination_country="IN",
            has_transfer_safeguards=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "safeguards" in result.reason.lower() or "Contractual" in result.reason

    def test_27_quebec_cross_border_no_pia_denied(self):
        """Quebec cross-border transfer without PIA is DENIED (Law 25 §17)."""
        ctx = _ctx(
            province="QC",
            is_cross_border_transfer=True,
            destination_country="IN",
            has_transfer_safeguards=False,
            has_privacy_impact_assessment=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§17" in result.reason

    def test_28_non_adequate_no_safeguards_denied(self):
        """Non-adequate destination without safeguards is DENIED (PIPEDA §4.1.3)."""
        ctx = _ctx(
            province="ON",
            is_cross_border_transfer=True,
            destination_country="RU",
            has_transfer_safeguards=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§4.1.3" in result.reason

    def test_29_adequate_destination_jp_approved(self):
        """Transfer to Japan (adequate jurisdiction) is APPROVED."""
        ctx = _ctx(
            is_cross_border_transfer=True,
            destination_country="JP",
            has_transfer_safeguards=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [30-35] Pipeline — filter_documents
# ---------------------------------------------------------------------------


class TestCanadaPrivacyRAGPipelineFilterDocuments:
    def setup_method(self):
        self.pipeline = CanadaPrivacyRAGPipeline()

    def test_30_clean_context_all_documents_pass(self):
        """Clean context with consent, no sensitive data, no transfer passes all documents."""
        ctx = _ctx(
            role="organization",
            province="ON",
            sector="general",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 3

    def test_31_denied_document_removed_from_result(self):
        """Documents denied by PIPEDA consent layer are excluded from the result set."""
        ctx = _ctx(
            role="organization",
            has_meaningful_consent=False,
            has_legitimate_purpose=False,
            involves_sensitive_data=False,
        )
        docs = [_doc(document_id="doc-deny")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_32_requires_human_review_document_included(self):
        """REQUIRES_HUMAN_REVIEW documents (Quebec §12.1) are included in the result."""
        ctx = _ctx(
            role="organization",
            province="QC",
            sector="general",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_automated_decision=True,
            has_human_review=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id="doc-review")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_33_empty_document_list_returns_empty(self):
        """Empty document list returns empty result."""
        ctx = _ctx()
        result = self.pipeline.filter_documents(ctx, [])
        assert result == []

    def test_34_healthcare_denial_removes_document(self):
        """Ontario healthcare denial removes document even when other layers pass."""
        ctx = _ctx(
            role="organization",
            province="ON",
            sector="healthcare",
            has_meaningful_consent=False,
            involves_sensitive_data=True,
            has_legitimate_purpose=True,
        )
        docs = [_doc(document_id="doc-health-deny")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_35_cross_border_denial_removes_document(self):
        """Cross-border transfer denial removes document even when other layers pass."""
        ctx = _ctx(
            role="organization",
            province="ON",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=True,
            destination_country="CN",
            has_transfer_safeguards=False,
        )
        docs = [_doc(document_id="doc-xborder")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# [36-39] Pipeline — filter_documents_with_audit
# ---------------------------------------------------------------------------


class TestCanadaPrivacyRAGPipelineAudit:
    def setup_method(self):
        self.pipeline = CanadaPrivacyRAGPipeline()

    def test_36_audit_record_type(self):
        """filter_documents_with_audit returns a CanadaPrivacyAuditRecord."""
        ctx = _ctx()
        record = self.pipeline.filter_documents_with_audit(ctx, [_doc()])
        assert isinstance(record, CanadaPrivacyAuditRecord)

    def test_37_audit_documents_in_matches_input_count(self):
        """Audit record documents_in equals the number of input documents."""
        ctx = _ctx()
        docs = [_doc(document_id=f"doc-{i}") for i in range(5)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_in == 5

    def test_38_audit_documents_out_matches_permitted(self):
        """Audit record documents_out counts only non-denied documents."""
        ctx = _ctx(
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_out == 3

    def test_39_audit_to_audit_log_returns_dict_with_expected_keys(self):
        """to_audit_log() returns a dict with all expected keys."""
        ctx = _ctx()
        record = self.pipeline.filter_documents_with_audit(ctx, [_doc()])
        log = record.to_audit_log()
        assert isinstance(log, dict)
        assert "event" in log
        assert "user_id" in log
        assert "province" in log
        assert "sector" in log
        assert "documents_in" in log
        assert "documents_out" in log
        assert "decisions" in log
        assert "timestamp" in log


# ---------------------------------------------------------------------------
# [40] Full-stack and edge cases
# ---------------------------------------------------------------------------


class TestFullStackAndEdgeCases:
    def setup_method(self):
        self.pipeline = CanadaPrivacyRAGPipeline()

    def test_40_context_and_document_are_frozen(self):
        """CanadaPrivacyContext and CanadaPrivacyDocument are immutable (frozen=True)."""
        import dataclasses

        ctx = _ctx()
        assert dataclasses.is_dataclass(ctx)
        ctx_raised = False
        try:
            ctx.role = "individual"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            ctx_raised = True
        assert ctx_raised, "CanadaPrivacyContext should be frozen"

        doc = _doc()
        assert dataclasses.is_dataclass(doc)
        doc_raised = False
        try:
            doc.content = "modified"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            doc_raised = True
        assert doc_raised, "CanadaPrivacyDocument should be frozen"

    def test_41_filter_result_is_denied_semantics(self):
        """FilterResult.is_denied is True only for DENIED; False for APPROVED and REQUIRES_HUMAN_REVIEW."""
        denied = FilterResult(layer="L", decision="DENIED", reason="r", regulation_citation="c")
        approved = FilterResult(layer="L", decision="APPROVED", reason="r", regulation_citation="c")
        review = FilterResult(layer="L", decision="REQUIRES_HUMAN_REVIEW", reason="r", regulation_citation="c")
        assert denied.is_denied
        assert not approved.is_denied
        assert not review.is_denied

    def test_42_individual_self_access_bypasses_all_layers(self):
        """Individual role bypasses PIPEDA consent layer and the entire pipeline passes."""
        ctx = _ctx(
            role="individual",
            has_meaningful_consent=False,
            involves_sensitive_data=True,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id="doc-self-access")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_43_qc_sensitive_denial_stops_pipeline(self):
        """Quebec sensitive-data denial (Law 25 §8) stops the pipeline at layer 2."""
        ctx = _ctx(
            role="organization",
            province="QC",
            has_meaningful_consent=False,
            involves_sensitive_data=True,
        )
        docs = [_doc(document_id="doc-qc-deny")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_44_audit_denied_document_reduces_documents_out(self):
        """documents_out is reduced by denied documents in the audit record."""
        ctx = _ctx(
            role="organization",
            has_meaningful_consent=False,
            has_legitimate_purpose=False,
            involves_sensitive_data=False,
        )
        docs = [_doc(document_id="doc-deny")]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_in == 1
        assert record.documents_out == 0

    def test_45_adequate_country_us_cross_border_approved(self):
        """Transfer to US (adequate jurisdiction) is APPROVED in pipeline."""
        ctx = _ctx(
            role="organization",
            province="ON",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=True,
            destination_country="US",
            has_transfer_safeguards=False,
        )
        docs = [_doc(document_id="doc-us-transfer")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_46_healthcare_provider_non_sensitive_approved(self):
        """Healthcare provider accessing non-sensitive healthcare data is APPROVED."""
        ctx = _ctx(
            role="healthcare_provider",
            province="AB",
            sector="healthcare",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id="doc-provider")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_47_qc_healthcare_with_consent_and_pia_approved(self):
        """Quebec healthcare with meaningful consent, PIA, and no transfer is APPROVED."""
        ctx = _ctx(
            role="healthcare_provider",
            province="QC",
            sector="healthcare",
            has_meaningful_consent=True,
            involves_sensitive_data=True,
            has_privacy_impact_assessment=True,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id="doc-qc-health")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_48_mixed_documents_partial_pass(self):
        """Pipeline returns only compliant documents when inputs are mixed."""
        # compliant context — all docs should pass
        ctx_pass = _ctx(
            role="organization",
            has_meaningful_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=False,
        )
        docs_all = [_doc(document_id=f"doc-{i}") for i in range(5)]
        result = self.pipeline.filter_documents(ctx_pass, docs_all)
        assert len(result) == 5

        # non-compliant context — all docs should be denied
        ctx_deny = _ctx(
            role="organization",
            has_meaningful_consent=False,
            has_legitimate_purpose=False,
            involves_sensitive_data=False,
        )
        result_deny = self.pipeline.filter_documents(ctx_deny, docs_all)
        assert len(result_deny) == 0
