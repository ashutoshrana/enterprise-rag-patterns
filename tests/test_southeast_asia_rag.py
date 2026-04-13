"""
Tests for 35_southeast_asia_rag.py

Covers ThailandPDPAFilter, IndonesiaPDPFilter, VietnamCybersecurityFilter,
SEAsiaCrossBorderFilter, SEAsiaRAGPipeline, and SEAsiaAuditRecord.

38 tests total:
  [1-5]   ThailandPDPAFilter
  [6-10]  IndonesiaPDPFilter
  [11-15] VietnamCybersecurityFilter
  [16-22] SEAsiaCrossBorderFilter
  [23-28] Pipeline — filter_documents
  [29-34] Pipeline — filter_documents_with_audit
  [35-38] Full-stack and edge cases
"""

from __future__ import annotations

import os
import sys
import importlib.util
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "southeast_asia_rag_35"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "35_southeast_asia_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
SEAsiaContext = mod.SEAsiaContext
SEAsiaDocument = mod.SEAsiaDocument
FilterResult = mod.FilterResult
ThailandPDPAFilter = mod.ThailandPDPAFilter
IndonesiaPDPFilter = mod.IndonesiaPDPFilter
VietnamCybersecurityFilter = mod.VietnamCybersecurityFilter
SEAsiaCrossBorderFilter = mod.SEAsiaCrossBorderFilter
SEAsiaRAGPipeline = mod.SEAsiaRAGPipeline
SEAsiaAuditRecord = mod.SEAsiaAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def _ctx(
    *,
    user_id: str = "user-001",
    jurisdiction: str = "TH",
    role: str = "data_controller",
    has_explicit_consent: bool = True,
    has_legitimate_interest: bool = False,
    involves_sensitive_data: bool = False,
    is_automated_decision: bool = False,
    has_human_review: bool = True,
    has_dpia: bool = False,
    is_cross_border_transfer: bool = False,
    destination_country: str = "",
    has_transfer_mechanism: bool = False,
    involves_minor: bool = False,
    has_parental_consent: bool = False,
) -> object:
    return SEAsiaContext(
        user_id=user_id,
        jurisdiction=jurisdiction,
        role=role,
        has_explicit_consent=has_explicit_consent,
        has_legitimate_interest=has_legitimate_interest,
        involves_sensitive_data=involves_sensitive_data,
        is_automated_decision=is_automated_decision,
        has_human_review=has_human_review,
        has_dpia=has_dpia,
        is_cross_border_transfer=is_cross_border_transfer,
        destination_country=destination_country,
        has_transfer_mechanism=has_transfer_mechanism,
        involves_minor=involves_minor,
        has_parental_consent=has_parental_consent,
    )


def _doc(
    *,
    content: str = "Personal data record.",
    document_id: str = "doc-001",
    doc_type: str = "personal_data_record",
) -> object:
    return SEAsiaDocument(
        content=content,
        document_id=document_id,
        doc_type=doc_type,
    )


# ---------------------------------------------------------------------------
# [1-5] ThailandPDPAFilter
# ---------------------------------------------------------------------------

class TestThailandPDPAFilter:
    def setup_method(self):
        self.f = ThailandPDPAFilter()

    def test_01_sensitive_data_without_consent_denied(self):
        """Sensitive personal data without explicit consent is DENIED (PDPA §19)."""
        ctx = _ctx(involves_sensitive_data=True, has_explicit_consent=False)
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§19" in result.reason

    def test_02_minor_without_parental_consent_denied(self):
        """Processing a minor's data without parental consent is DENIED (PDPA §20)."""
        ctx = _ctx(
            involves_minor=True,
            has_parental_consent=False,
            has_explicit_consent=True,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§20" in result.reason

    def test_03_no_consent_no_legitimate_interest_denied(self):
        """Request without consent or legitimate interest is DENIED (PDPA §24)."""
        ctx = _ctx(
            has_explicit_consent=False,
            has_legitimate_interest=False,
            role="data_controller",
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§24" in result.reason

    def test_04_data_subject_self_access_approved(self):
        """Data subject self-access is APPROVED regardless of consent (PDPA §30)."""
        ctx = _ctx(
            role="data_subject",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "§30" in result.reason

    def test_05_compliant_path_approved(self):
        """Data controller with explicit consent and non-sensitive data is APPROVED."""
        ctx = _ctx(
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [6-10] IndonesiaPDPFilter
# ---------------------------------------------------------------------------

class TestIndonesiaPDPFilter:
    def setup_method(self):
        self.f = IndonesiaPDPFilter()

    def test_06_sensitive_data_without_consent_denied(self):
        """Sensitive personal data without explicit consent is DENIED (UU PDP Art. 20)."""
        ctx = _ctx(
            jurisdiction="ID",
            involves_sensitive_data=True,
            has_explicit_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 20" in result.reason

    def test_07_no_legal_basis_denied(self):
        """Processing without consent or legitimate interest is DENIED (UU PDP Art. 16)."""
        ctx = _ctx(
            jurisdiction="ID",
            role="data_controller",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 16" in result.reason

    def test_08_automated_decision_without_human_review_requires_review(self):
        """Automated decision without human review triggers REQUIRES_HUMAN_REVIEW (Art. 34)."""
        ctx = _ctx(
            jurisdiction="ID",
            role="data_controller",
            has_explicit_consent=True,
            is_automated_decision=True,
            has_human_review=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "Art. 34" in result.reason

    def test_09_data_subject_bypass_approved(self):
        """Data subject access is APPROVED immediately under UU PDP rights provisions."""
        ctx = _ctx(
            jurisdiction="ID",
            role="data_subject",
            has_explicit_consent=False,
            has_legitimate_interest=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_10_compliant_path_approved(self):
        """Processor with explicit consent and non-automated path is APPROVED."""
        ctx = _ctx(
            jurisdiction="ID",
            role="data_processor",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_automated_decision=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [11-15] VietnamCybersecurityFilter
# ---------------------------------------------------------------------------

class TestVietnamCybersecurityFilter:
    def setup_method(self):
        self.f = VietnamCybersecurityFilter()

    def test_11_sensitive_data_without_consent_denied(self):
        """Sensitive personal data without explicit consent is DENIED (Decree 13 Art. 8)."""
        ctx = _ctx(
            jurisdiction="VN",
            involves_sensitive_data=True,
            has_explicit_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 8" in result.reason

    def test_12_processing_without_consent_denied_for_controller(self):
        """Processing without consent by data controller is DENIED (Decree 13 Art. 5)."""
        ctx = _ctx(
            jurisdiction="VN",
            role="data_controller",
            has_explicit_consent=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 5" in result.reason

    def test_13_regulator_bypass_approved(self):
        """Regulator access is APPROVED immediately under Cybersecurity Law."""
        ctx = _ctx(
            jurisdiction="VN",
            role="regulator",
            has_explicit_consent=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "Regulatory" in result.reason

    def test_14_data_subject_with_consent_approved(self):
        """Data subject with explicit consent is APPROVED (no denial trigger)."""
        ctx = _ctx(
            jurisdiction="VN",
            role="data_subject",
            has_explicit_consent=True,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_15_compliant_path_approved(self):
        """Data controller with explicit consent and non-sensitive data is APPROVED."""
        ctx = _ctx(
            jurisdiction="VN",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [16-22] SEAsiaCrossBorderFilter
# ---------------------------------------------------------------------------

class TestSEAsiaCrossBorderFilter:
    def setup_method(self):
        self.f = SEAsiaCrossBorderFilter()

    def test_16_no_transfer_approved(self):
        """No cross-border transfer involved — APPROVED immediately."""
        ctx = _ctx(is_cross_border_transfer=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_17_adequate_destination_sg_approved(self):
        """Transfer to Singapore (adequate ASEAN jurisdiction) is APPROVED."""
        ctx = _ctx(
            is_cross_border_transfer=True,
            destination_country="SG",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "adequate" in result.reason

    def test_18_adequate_destination_my_approved(self):
        """Transfer to Malaysia (adequate ASEAN jurisdiction) is APPROVED."""
        ctx = _ctx(
            is_cross_border_transfer=True,
            destination_country="MY",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_19_transfer_mechanism_present_approved(self):
        """Transfer to non-adequate country with mechanism is APPROVED."""
        ctx = _ctx(
            jurisdiction="TH",
            is_cross_border_transfer=True,
            destination_country="US",
            has_transfer_mechanism=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "Contractual" in result.reason

    def test_20_thailand_no_mechanism_denied(self):
        """Thailand source transfer to non-adequate country without mechanism is DENIED (PDPA §28)."""
        ctx = _ctx(
            jurisdiction="TH",
            is_cross_border_transfer=True,
            destination_country="US",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§28" in result.reason

    def test_21_indonesia_no_mechanism_denied(self):
        """Indonesia source transfer without mechanism is DENIED (UU PDP Art. 50)."""
        ctx = _ctx(
            jurisdiction="ID",
            is_cross_border_transfer=True,
            destination_country="JP",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 50" in result.reason

    def test_22_vietnam_no_mechanism_denied(self):
        """Vietnam source transfer without mechanism is DENIED (Decree 13 Art. 25)."""
        ctx = _ctx(
            jurisdiction="VN",
            is_cross_border_transfer=True,
            destination_country="AU",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 25" in result.reason


# ---------------------------------------------------------------------------
# [23-28] Pipeline — filter_documents
# ---------------------------------------------------------------------------

class TestSEAsiaRAGPipelineFilterDocuments:
    def setup_method(self):
        self.pipeline = SEAsiaRAGPipeline()

    def test_23_clean_context_all_documents_pass(self):
        """Clean context with consent and no transfer passes all documents."""
        ctx = _ctx(
            jurisdiction="TH",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 3

    def test_24_denied_document_removed_from_result(self):
        """Documents denied by any layer are excluded from the result set."""
        ctx = _ctx(
            jurisdiction="TH",
            involves_sensitive_data=True,
            has_explicit_consent=False,
        )
        docs = [_doc(document_id="doc-deny")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_25_requires_human_review_document_included(self):
        """REQUIRES_HUMAN_REVIEW documents are included in the result."""
        ctx = _ctx(
            jurisdiction="ID",
            role="data_controller",
            has_explicit_consent=True,
            is_automated_decision=True,
            has_human_review=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id="doc-review")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_26_empty_document_list_returns_empty(self):
        """Empty document list returns empty result."""
        ctx = _ctx()
        result = self.pipeline.filter_documents(ctx, [])
        assert result == []

    def test_27_multiple_denied_all_removed(self):
        """All documents denied when context triggers denial for each."""
        ctx = _ctx(
            jurisdiction="VN",
            role="data_controller",
            has_explicit_consent=False,
            involves_sensitive_data=False,
        )
        docs = [_doc(document_id=f"doc-{i}") for i in range(4)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_28_cross_border_denial_removes_document(self):
        """Cross-border transfer denial removes document even when other layers pass."""
        ctx = _ctx(
            jurisdiction="TH",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=True,
            destination_country="US",
            has_transfer_mechanism=False,
        )
        docs = [_doc(document_id="doc-xborder")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# [29-34] Pipeline — filter_documents_with_audit
# ---------------------------------------------------------------------------

class TestSEAsiaRAGPipelineAudit:
    def setup_method(self):
        self.pipeline = SEAsiaRAGPipeline()

    def test_29_audit_record_type(self):
        """filter_documents_with_audit returns a SEAsiaAuditRecord."""
        ctx = _ctx()
        record = self.pipeline.filter_documents_with_audit(ctx, [_doc()])
        assert isinstance(record, SEAsiaAuditRecord)

    def test_30_audit_documents_in_matches_input_count(self):
        """Audit record documents_in equals the number of input documents."""
        ctx = _ctx()
        docs = [_doc(document_id=f"doc-{i}") for i in range(4)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_in == 4

    def test_31_audit_documents_out_matches_permitted(self):
        """Audit record documents_out counts only non-denied documents."""
        ctx = _ctx(has_explicit_consent=True, involves_sensitive_data=False)
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_out == 3

    def test_32_audit_denied_document_reduces_documents_out(self):
        """documents_out is reduced by denied documents."""
        ctx = _ctx(
            jurisdiction="TH",
            involves_sensitive_data=True,
            has_explicit_consent=False,
        )
        docs = [_doc(document_id="doc-deny")]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_in == 1
        assert record.documents_out == 0

    def test_33_audit_decisions_list_length_matches_input(self):
        """decisions list in audit record has one entry per input document."""
        ctx = _ctx()
        docs = [_doc(document_id=f"doc-{i}") for i in range(5)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert len(record.decisions) == 5

    def test_34_audit_to_audit_log_returns_dict(self):
        """to_audit_log() returns a dict with expected keys."""
        ctx = _ctx()
        record = self.pipeline.filter_documents_with_audit(ctx, [_doc()])
        log = record.to_audit_log()
        assert isinstance(log, dict)
        assert "event" in log
        assert "user_id" in log
        assert "jurisdiction" in log
        assert "documents_in" in log
        assert "documents_out" in log
        assert "decisions" in log


# ---------------------------------------------------------------------------
# [35-38] Full-stack and edge cases
# ---------------------------------------------------------------------------

class TestFullStackAndEdgeCases:
    def setup_method(self):
        self.pipeline = SEAsiaRAGPipeline()

    def test_35_filter_result_is_denied_false_for_requires_human_review(self):
        """FilterResult.is_denied is False for REQUIRES_HUMAN_REVIEW decisions."""
        fr = FilterResult(
            layer="TEST",
            decision="REQUIRES_HUMAN_REVIEW",
            reason="test",
            regulation_citation="test",
        )
        assert not fr.is_denied

    def test_36_filter_result_is_denied_true_only_for_denied(self):
        """FilterResult.is_denied is True only for DENIED decisions."""
        denied = FilterResult(layer="L", decision="DENIED", reason="r", regulation_citation="c")
        approved = FilterResult(layer="L", decision="APPROVED", reason="r", regulation_citation="c")
        assert denied.is_denied
        assert not approved.is_denied

    def test_37_seasia_context_is_frozen(self):
        """SEAsiaContext is immutable (frozen=True)."""
        import dataclasses
        ctx = _ctx()
        assert dataclasses.is_dataclass(ctx)
        try:
            ctx.role = "data_subject"  # type: ignore[misc]
            raised = False
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            raised = True
        assert raised, "SEAsiaContext should be frozen"

    def test_38_regulator_with_consent_passes_all_layers(self):
        """Regulator with explicit consent and no cross-border transfer passes all layers."""
        ctx = _ctx(
            jurisdiction="VN",
            role="regulator",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id="doc-reg")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1
