"""
Tests for 36_latin_america_rag.py

Covers ArgentinaPersonalDataFilter, ChilePersonalDataFilter,
ColombiaHabeasDataFilter, LatAmCrossBorderFilter, LatAmRAGPipeline,
and LatAmAuditRecord.

38 tests total:
  [1-6]   ArgentinaPersonalDataFilter
  [7-12]  ChilePersonalDataFilter
  [13-18] ColombiaHabeasDataFilter
  [19-25] LatAmCrossBorderFilter
  [26-31] Pipeline — filter_documents
  [32-36] Pipeline — filter_documents_with_audit
  [37-38] Full-stack and edge cases
"""

from __future__ import annotations

import os
import sys
import importlib.util
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "latin_america_rag_36"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "36_latin_america_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
LatAmContext = mod.LatAmContext
LatAmDocument = mod.LatAmDocument
FilterResult = mod.FilterResult
ArgentinaPersonalDataFilter = mod.ArgentinaPersonalDataFilter
ChilePersonalDataFilter = mod.ChilePersonalDataFilter
ColombiaHabeasDataFilter = mod.ColombiaHabeasDataFilter
LatAmCrossBorderFilter = mod.LatAmCrossBorderFilter
LatAmRAGPipeline = mod.LatAmRAGPipeline
LatAmAuditRecord = mod.LatAmAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def _ctx(
    *,
    user_id: str = "user-001",
    jurisdiction: str = "AR",
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
    is_financial_data: bool = False,
) -> object:
    return LatAmContext(
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
        is_financial_data=is_financial_data,
    )


def _doc(
    *,
    content: str = "Personal data record.",
    document_id: str = "doc-001",
    doc_type: str = "personal_data_record",
) -> object:
    return LatAmDocument(
        content=content,
        document_id=document_id,
        doc_type=doc_type,
    )


# ---------------------------------------------------------------------------
# [1-6] ArgentinaPersonalDataFilter
# ---------------------------------------------------------------------------

class TestArgentinaPersonalDataFilter:
    def setup_method(self):
        self.f = ArgentinaPersonalDataFilter()

    def test_01_sensitive_data_without_consent_denied(self):
        """Sensitive personal data without explicit consent is DENIED (LPDP Art. 7)."""
        ctx = _ctx(
            jurisdiction="AR",
            involves_sensitive_data=True,
            has_explicit_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 7" in result.reason

    def test_02_no_consent_no_legitimate_interest_denied(self):
        """Request without consent or legitimate interest is DENIED (LPDP Art. 5)."""
        ctx = _ctx(
            jurisdiction="AR",
            role="data_controller",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 5" in result.reason

    def test_03_minor_without_parental_consent_denied(self):
        """Processing a minor's data without parental consent is DENIED (LPDP Art. 12)."""
        ctx = _ctx(
            jurisdiction="AR",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            involves_minor=True,
            has_parental_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 12" in result.reason

    def test_04_data_subject_self_access_approved(self):
        """Data subject self-access is APPROVED regardless of consent."""
        ctx = _ctx(
            jurisdiction="AR",
            role="data_subject",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_05_regulator_without_consent_approved(self):
        """Regulator without consent bypasses Art. 5 consent requirement."""
        ctx = _ctx(
            jurisdiction="AR",
            role="regulator",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_06_compliant_path_approved(self):
        """Data controller with explicit consent and non-sensitive non-minor data is APPROVED."""
        ctx = _ctx(
            jurisdiction="AR",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            involves_minor=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [7-12] ChilePersonalDataFilter
# ---------------------------------------------------------------------------

class TestChilePersonalDataFilter:
    def setup_method(self):
        self.f = ChilePersonalDataFilter()

    def test_07_no_consent_no_legitimate_interest_denied(self):
        """Request without consent or legitimate interest is DENIED (Law 19.628 Art. 4)."""
        ctx = _ctx(
            jurisdiction="CL",
            role="data_controller",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 4" in result.reason

    def test_08_sensitive_data_without_consent_denied(self):
        """Sensitive personal data without explicit consent is DENIED (Law 19.628 Art. 2(g))."""
        ctx = _ctx(
            jurisdiction="CL",
            role="data_controller",
            has_explicit_consent=False,
            has_legitimate_interest=True,
            involves_sensitive_data=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 2(g)" in result.reason

    def test_09_automated_decision_without_human_review_requires_review(self):
        """Automated decision without human review triggers REQUIRES_HUMAN_REVIEW (Law 21.719 Art. 16)."""
        ctx = _ctx(
            jurisdiction="CL",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_automated_decision=True,
            has_human_review=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "Art. 16" in result.reason

    def test_10_data_subject_bypass_approved(self):
        """Data subject access is APPROVED immediately."""
        ctx = _ctx(
            jurisdiction="CL",
            role="data_subject",
            has_explicit_consent=False,
            has_legitimate_interest=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_11_regulator_without_consent_approved(self):
        """Regulator without consent bypasses Art. 4 consent requirement."""
        ctx = _ctx(
            jurisdiction="CL",
            role="regulator",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_12_compliant_path_approved(self):
        """Data controller with explicit consent, non-sensitive, non-automated is APPROVED."""
        ctx = _ctx(
            jurisdiction="CL",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_automated_decision=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [13-18] ColombiaHabeasDataFilter
# ---------------------------------------------------------------------------

class TestColombiaHabeasDataFilter:
    def setup_method(self):
        self.f = ColombiaHabeasDataFilter()

    def test_13_sensitive_data_without_consent_denied(self):
        """Sensitive personal data without explicit consent is DENIED (Law 1581/2012 Art. 7)."""
        ctx = _ctx(
            jurisdiction="CO",
            involves_sensitive_data=True,
            has_explicit_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 7" in result.reason

    def test_14_no_consent_no_legitimate_interest_denied(self):
        """Request without consent or legitimate interest is DENIED (Law 1581/2012 Art. 4(c))."""
        ctx = _ctx(
            jurisdiction="CO",
            role="data_controller",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 4(c)" in result.reason

    def test_15_financial_data_without_consent_denied(self):
        """Financial data processing without explicit consent is DENIED (Decree 1377/2013 Art. 10)."""
        ctx = _ctx(
            jurisdiction="CO",
            role="data_controller",
            has_explicit_consent=False,
            has_legitimate_interest=True,
            involves_sensitive_data=False,
            is_financial_data=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 10" in result.reason

    def test_16_data_subject_bypass_approved(self):
        """Data subject access is APPROVED immediately under habeas data rights."""
        ctx = _ctx(
            jurisdiction="CO",
            role="data_subject",
            has_explicit_consent=False,
            has_legitimate_interest=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_17_regulator_without_consent_approved(self):
        """Regulator without consent bypasses Art. 4(c) consent requirement."""
        ctx = _ctx(
            jurisdiction="CO",
            role="regulator",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_18_compliant_path_approved(self):
        """Data controller with explicit consent, non-sensitive, non-financial data is APPROVED."""
        ctx = _ctx(
            jurisdiction="CO",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_financial_data=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [19-25] LatAmCrossBorderFilter
# ---------------------------------------------------------------------------

class TestLatAmCrossBorderFilter:
    def setup_method(self):
        self.f = LatAmCrossBorderFilter()

    def test_19_no_transfer_approved(self):
        """No cross-border transfer involved — APPROVED immediately."""
        ctx = _ctx(is_cross_border_transfer=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_20_adequate_destination_br_approved(self):
        """Transfer to Brazil (adequate Ibero-American jurisdiction) is APPROVED."""
        ctx = _ctx(
            is_cross_border_transfer=True,
            destination_country="BR",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "adequate" in result.reason

    def test_21_adequate_destination_uy_approved(self):
        """Transfer to Uruguay (adequate Ibero-American jurisdiction) is APPROVED."""
        ctx = _ctx(
            is_cross_border_transfer=True,
            destination_country="UY",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_22_transfer_mechanism_present_approved(self):
        """Transfer to non-adequate country with mechanism is APPROVED."""
        ctx = _ctx(
            jurisdiction="AR",
            is_cross_border_transfer=True,
            destination_country="US",
            has_transfer_mechanism=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "Contractual" in result.reason

    def test_23_argentina_no_mechanism_denied(self):
        """Argentina source transfer to non-adequate country without mechanism is DENIED (LPDP Art. 12)."""
        ctx = _ctx(
            jurisdiction="AR",
            is_cross_border_transfer=True,
            destination_country="US",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 12" in result.reason

    def test_24_chile_no_mechanism_denied(self):
        """Chile source transfer without mechanism is DENIED (Law 19.628 Art. 26)."""
        ctx = _ctx(
            jurisdiction="CL",
            is_cross_border_transfer=True,
            destination_country="JP",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 26" in result.reason

    def test_25_colombia_no_mechanism_denied(self):
        """Colombia source transfer without mechanism is DENIED (Law 1581/2012 Art. 26)."""
        ctx = _ctx(
            jurisdiction="CO",
            is_cross_border_transfer=True,
            destination_country="AU",
            has_transfer_mechanism=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Art. 26" in result.reason


# ---------------------------------------------------------------------------
# [26-31] Pipeline — filter_documents
# ---------------------------------------------------------------------------

class TestLatAmRAGPipelineFilterDocuments:
    def setup_method(self):
        self.pipeline = LatAmRAGPipeline()

    def test_26_clean_context_all_documents_pass(self):
        """Clean context with consent and no transfer passes all documents."""
        ctx = _ctx(
            jurisdiction="AR",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 3

    def test_27_denied_document_removed_from_result(self):
        """Documents denied by any layer are excluded from the result set."""
        ctx = _ctx(
            jurisdiction="AR",
            involves_sensitive_data=True,
            has_explicit_consent=False,
        )
        docs = [_doc(document_id="doc-deny")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_28_requires_human_review_document_included(self):
        """REQUIRES_HUMAN_REVIEW documents are included in the result."""
        ctx = _ctx(
            jurisdiction="CL",
            role="data_controller",
            has_explicit_consent=True,
            involves_sensitive_data=False,
            is_automated_decision=True,
            has_human_review=False,
            is_cross_border_transfer=False,
        )
        docs = [_doc(document_id="doc-review")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_29_empty_document_list_returns_empty(self):
        """Empty document list returns empty result."""
        ctx = _ctx()
        result = self.pipeline.filter_documents(ctx, [])
        assert result == []

    def test_30_multiple_denied_all_removed(self):
        """All documents denied when context triggers denial for each."""
        ctx = _ctx(
            jurisdiction="CO",
            role="data_controller",
            has_explicit_consent=False,
            has_legitimate_interest=False,
            involves_sensitive_data=False,
        )
        docs = [_doc(document_id=f"doc-{i}") for i in range(4)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_31_cross_border_denial_removes_document(self):
        """Cross-border transfer denial removes document even when other layers pass."""
        ctx = _ctx(
            jurisdiction="CL",
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
# [32-36] Pipeline — filter_documents_with_audit
# ---------------------------------------------------------------------------

class TestLatAmRAGPipelineAudit:
    def setup_method(self):
        self.pipeline = LatAmRAGPipeline()

    def test_32_audit_record_type(self):
        """filter_documents_with_audit returns a LatAmAuditRecord."""
        ctx = _ctx()
        record = self.pipeline.filter_documents_with_audit(ctx, [_doc()])
        assert isinstance(record, LatAmAuditRecord)

    def test_33_audit_documents_in_matches_input_count(self):
        """Audit record documents_in equals the number of input documents."""
        ctx = _ctx()
        docs = [_doc(document_id=f"doc-{i}") for i in range(4)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_in == 4

    def test_34_audit_documents_out_matches_permitted(self):
        """Audit record documents_out counts only non-denied documents."""
        ctx = _ctx(has_explicit_consent=True, involves_sensitive_data=False)
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_out == 3

    def test_35_audit_denied_document_reduces_documents_out(self):
        """documents_out is reduced by denied documents."""
        ctx = _ctx(
            jurisdiction="AR",
            involves_sensitive_data=True,
            has_explicit_consent=False,
        )
        docs = [_doc(document_id="doc-deny")]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_in == 1
        assert record.documents_out == 0

    def test_36_audit_to_audit_log_returns_dict(self):
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
# [37-38] Full-stack and edge cases
# ---------------------------------------------------------------------------

class TestFullStackAndEdgeCases:
    def setup_method(self):
        self.pipeline = LatAmRAGPipeline()

    def test_37_latam_context_is_frozen(self):
        """LatAmContext is immutable (frozen=True)."""
        import dataclasses
        ctx = _ctx()
        assert dataclasses.is_dataclass(ctx)
        try:
            ctx.role = "data_subject"  # type: ignore[misc]
            raised = False
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            raised = True
        assert raised, "LatAmContext should be frozen"

    def test_38_filter_result_is_denied_semantics(self):
        """FilterResult.is_denied is True only for DENIED; False for APPROVED and REQUIRES_HUMAN_REVIEW."""
        denied = FilterResult(layer="L", decision="DENIED", reason="r", regulation_citation="c")
        approved = FilterResult(layer="L", decision="APPROVED", reason="r", regulation_citation="c")
        review = FilterResult(layer="L", decision="REQUIRES_HUMAN_REVIEW", reason="r", regulation_citation="c")
        assert denied.is_denied
        assert not approved.is_denied
        assert not review.is_denied
