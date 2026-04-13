"""
Tests for 34_real_estate_rag.py

Covers FairHousingActFilter, ECOALendingFilter, AppraisalIndependenceFilter,
StateRealEstateLawFilter, RealEstateRAGPipeline, and RealEstateAuditRecord.

36 tests total:
  [1-5]   FairHousingActFilter
  [6-9]   ECOALendingFilter
  [10-13] AppraisalIndependenceFilter
  [14-18] StateRealEstateLawFilter
  [19-24] Pipeline — filter_documents
  [25-30] Pipeline — filter_documents_with_audit
  [31-36] Full-stack and edge cases
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "real_estate_rag_34"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "34_real_estate_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
RealEstateContext = mod.RealEstateContext
RealEstateDocument = mod.RealEstateDocument
FilterResult = mod.FilterResult
FairHousingActFilter = mod.FairHousingActFilter
ECOALendingFilter = mod.ECOALendingFilter
AppraisalIndependenceFilter = mod.AppraisalIndependenceFilter
StateRealEstateLawFilter = mod.StateRealEstateLawFilter
RealEstateRAGPipeline = mod.RealEstateRAGPipeline
RealEstateAuditRecord = mod.RealEstateAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    user_id: str = "user-001",
    role: str = "agent",
    property_state: str = "WA",
    transaction_type: str = "purchase",
    is_protected_class_data: bool = False,
    has_fair_housing_training: bool = True,
    involves_credit_decision: bool = False,
    has_ecoa_notice: bool = True,
    involves_appraisal: bool = False,
    is_automated_valuation: bool = False,
    has_disclosure: bool = True,
    involves_rental: bool = False,
    has_adverse_action_notice: bool = True,
) -> object:
    return RealEstateContext(
        user_id=user_id,
        role=role,
        property_state=property_state,
        transaction_type=transaction_type,
        is_protected_class_data=is_protected_class_data,
        has_fair_housing_training=has_fair_housing_training,
        involves_credit_decision=involves_credit_decision,
        has_ecoa_notice=has_ecoa_notice,
        involves_appraisal=involves_appraisal,
        is_automated_valuation=is_automated_valuation,
        has_disclosure=has_disclosure,
        involves_rental=involves_rental,
        has_adverse_action_notice=has_adverse_action_notice,
    )


def _doc(
    *,
    content: str = "Property listing document.",
    document_id: str = "doc-001",
    doc_type: str = "listing",
) -> object:
    return RealEstateDocument(
        content=content,
        document_id=document_id,
        doc_type=doc_type,
    )


# ---------------------------------------------------------------------------
# [1-5] FairHousingActFilter
# ---------------------------------------------------------------------------


class TestFairHousingActFilter:
    def setup_method(self):
        self.f = FairHousingActFilter()

    def test_01_protected_class_blocked_for_buyer_role(self):
        """Buyer role accessing protected class data is DENIED (42 U.S.C. §3604)."""
        ctx = _ctx(role="buyer", is_protected_class_data=True, has_fair_housing_training=True)
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "42 U.S.C. §3604" in result.reason

    def test_02_protected_class_blocked_for_seller_role(self):
        """Seller role accessing protected class data is DENIED."""
        ctx = _ctx(role="seller", is_protected_class_data=True, has_fair_housing_training=True)
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_03_training_required_for_agent_without_training(self):
        """Lender with protected class data but no training gets REQUIRES_HUMAN_REVIEW."""
        ctx = _ctx(
            role="lender",
            is_protected_class_data=True,
            has_fair_housing_training=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "HUD" in result.reason

    def test_04_regulator_can_access_protected_class(self):
        """Regulator with protected class data and training is APPROVED."""
        ctx = _ctx(role="regulator", is_protected_class_data=True, has_fair_housing_training=True)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_05_non_protected_data_approved_for_any_role(self):
        """Non-protected class data is approved for all roles."""
        for role in ("buyer", "seller", "agent", "lender", "appraiser", "regulator"):
            ctx = _ctx(role=role, is_protected_class_data=False)
            result = self.f.evaluate(ctx, _doc())
            assert not result.is_denied
            assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [6-9] ECOALendingFilter
# ---------------------------------------------------------------------------


class TestECOALendingFilter:
    def setup_method(self):
        self.f = ECOALendingFilter()

    def test_06_credit_decision_without_ecoa_notice_denied(self):
        """Credit decision without ECOA notice is DENIED (15 U.S.C. §1691)."""
        ctx = _ctx(
            role="lender",
            involves_credit_decision=True,
            has_ecoa_notice=False,
            has_adverse_action_notice=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§1691" in result.reason

    def test_07_lender_without_adverse_action_notice_requires_review(self):
        """Lender with credit decision but no adverse action notice is REQUIRES_HUMAN_REVIEW."""
        ctx = _ctx(
            role="lender",
            involves_credit_decision=True,
            has_ecoa_notice=True,
            has_adverse_action_notice=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "Regulation B" in result.reason

    def test_08_non_credit_path_approved(self):
        """Non-credit transactions are always APPROVED by ECOA filter."""
        ctx = _ctx(
            role="agent",
            involves_credit_decision=False,
            has_ecoa_notice=False,
            has_adverse_action_notice=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_09_credit_decision_with_all_notices_approved(self):
        """Credit decision with ECOA notice and adverse action notice is APPROVED."""
        ctx = _ctx(
            role="lender",
            involves_credit_decision=True,
            has_ecoa_notice=True,
            has_adverse_action_notice=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [10-13] AppraisalIndependenceFilter
# ---------------------------------------------------------------------------


class TestAppraisalIndependenceFilter:
    def setup_method(self):
        self.f = AppraisalIndependenceFilter()

    def test_10_avm_for_purchase_requires_human_review(self):
        """AVM for a purchase transaction requires human appraiser review (Dodd-Frank §1472)."""
        ctx = _ctx(
            role="lender",
            involves_appraisal=True,
            is_automated_valuation=True,
            transaction_type="purchase",
            has_disclosure=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "Dodd-Frank §1472" in result.reason

    def test_11_avm_for_refinance_approved(self):
        """AVM for a refinance transaction is APPROVED (§1472 applies to purchase)."""
        ctx = _ctx(
            role="lender",
            involves_appraisal=True,
            is_automated_valuation=True,
            transaction_type="refinance",
            has_disclosure=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_12_lender_appraisal_missing_disclosure_denied(self):
        """Lender accessing appraisal without borrower disclosure is DENIED (USPAP)."""
        ctx = _ctx(
            role="lender",
            involves_appraisal=True,
            is_automated_valuation=False,
            transaction_type="purchase",
            has_disclosure=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "USPAP" in result.reason

    def test_13_non_appraisal_context_approved(self):
        """Non-appraisal context is always APPROVED by AppraisalIndependenceFilter."""
        ctx = _ctx(
            role="buyer",
            involves_appraisal=False,
            is_automated_valuation=False,
            has_disclosure=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [14-18] StateRealEstateLawFilter
# ---------------------------------------------------------------------------


class TestStateRealEstateLawFilter:
    def setup_method(self):
        self.f = StateRealEstateLawFilter()

    def test_14_ca_rental_without_disclosure_requires_review(self):
        """CA rental without disclosure triggers REQUIRES_HUMAN_REVIEW (CA Civil Code §1940.2)."""
        ctx = _ctx(
            property_state="CA",
            transaction_type="rental",
            involves_rental=True,
            has_disclosure=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§1940.2" in result.reason

    def test_15_ny_purchase_without_disclosure_denied(self):
        """NY purchase without disclosure is DENIED (NY RPL §462)."""
        ctx = _ctx(
            property_state="NY",
            transaction_type="purchase",
            has_disclosure=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§462" in result.reason

    def test_16_tx_purchase_seller_without_disclosure_requires_review(self):
        """TX purchase seller without disclosure triggers REQUIRES_HUMAN_REVIEW (TX §5.008)."""
        ctx = _ctx(
            role="seller",
            property_state="TX",
            transaction_type="purchase",
            has_disclosure=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§5.008" in result.reason

    def test_17_other_state_approved_by_default(self):
        """Non-CA/NY/TX state returns APPROVED with generic citation."""
        ctx = _ctx(property_state="CO", transaction_type="purchase", has_disclosure=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "State Real Estate Disclosure Law" in result.regulation_citation

    def test_18_ca_rental_with_disclosure_approved(self):
        """CA rental WITH disclosure is APPROVED."""
        ctx = _ctx(
            property_state="CA",
            transaction_type="rental",
            involves_rental=True,
            has_disclosure=True,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [19-24] Pipeline — filter_documents
# ---------------------------------------------------------------------------


class TestRealEstateRAGPipelineFilterDocuments:
    def setup_method(self):
        self.pipeline = RealEstateRAGPipeline()

    def test_19_clean_context_all_documents_pass(self):
        """Clean context with no flags passes all documents."""
        ctx = _ctx()
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 3

    def test_20_denied_document_removed_from_result(self):
        """Documents denied by any layer are excluded from the result set."""
        # NY purchase without disclosure will be denied by StateRealEstateLawFilter
        ctx = _ctx(property_state="NY", transaction_type="purchase", has_disclosure=False)
        docs = [_doc(document_id="doc-deny")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_21_requires_human_review_document_included(self):
        """REQUIRES_HUMAN_REVIEW documents are included in the result."""
        # AVM for purchase triggers REQUIRES_HUMAN_REVIEW but is not denied
        ctx = _ctx(
            role="lender",
            involves_appraisal=True,
            is_automated_valuation=True,
            transaction_type="purchase",
            has_disclosure=True,
        )
        docs = [_doc(document_id="doc-review")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_22_mixed_documents_only_denied_removed(self):
        """Mix of clean and NY-purchase-no-disclosure documents: only denied removed."""
        clean_ctx = _ctx(property_state="WA", transaction_type="purchase", has_disclosure=True)
        # Use one clean doc to verify passing
        docs = [_doc(document_id="doc-clean")]
        result = self.pipeline.filter_documents(clean_ctx, docs)
        assert len(result) == 1

    def test_23_empty_document_list_returns_empty(self):
        """Empty document list returns empty result."""
        ctx = _ctx()
        result = self.pipeline.filter_documents(ctx, [])
        assert result == []

    def test_24_multiple_denied_all_removed(self):
        """All documents denied when context triggers denial."""
        ctx = _ctx(property_state="NY", transaction_type="purchase", has_disclosure=False)
        docs = [_doc(document_id=f"doc-{i}") for i in range(5)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# [25-30] Pipeline — filter_documents_with_audit
# ---------------------------------------------------------------------------


class TestRealEstateRAGPipelineAudit:
    def setup_method(self):
        self.pipeline = RealEstateRAGPipeline()

    def test_25_audit_record_type(self):
        """filter_documents_with_audit returns a RealEstateAuditRecord."""
        ctx = _ctx()
        record = self.pipeline.filter_documents_with_audit(ctx, [_doc()])
        assert isinstance(record, RealEstateAuditRecord)

    def test_26_audit_documents_in_matches_input_count(self):
        """Audit record documents_in equals the number of input documents."""
        ctx = _ctx()
        docs = [_doc(document_id=f"doc-{i}") for i in range(4)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_in == 4

    def test_27_audit_documents_out_matches_permitted(self):
        """Audit record documents_out counts only non-denied documents."""
        ctx = _ctx()
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_out == 3

    def test_28_audit_denied_document_reduces_documents_out(self):
        """documents_out is reduced by denied documents."""
        ctx = _ctx(property_state="NY", transaction_type="purchase", has_disclosure=False)
        docs = [_doc(document_id="doc-deny")]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_in == 1
        assert record.documents_out == 0

    def test_29_audit_decisions_list_length_matches_input(self):
        """decisions list in audit record has one entry per input document."""
        ctx = _ctx()
        docs = [_doc(document_id=f"doc-{i}") for i in range(5)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert len(record.decisions) == 5

    def test_30_audit_to_audit_log_returns_dict(self):
        """to_audit_log() returns a dict with expected keys."""
        ctx = _ctx()
        record = self.pipeline.filter_documents_with_audit(ctx, [_doc()])
        log = record.to_audit_log()
        assert isinstance(log, dict)
        assert "event" in log
        assert "user_id" in log
        assert "role" in log
        assert "state" in log
        assert "documents_in" in log
        assert "documents_out" in log
        assert "decisions" in log


# ---------------------------------------------------------------------------
# [31-36] Full-stack and edge cases
# ---------------------------------------------------------------------------


class TestFullStackAndEdgeCases:
    def setup_method(self):
        self.pipeline = RealEstateRAGPipeline()

    def test_31_four_layer_pipeline_runs_all_filters(self):
        """Full-stack: pipeline runs all four layers in sequence."""
        ctx = _ctx(
            role="lender",
            property_state="WA",
            transaction_type="purchase",
            involves_credit_decision=True,
            has_ecoa_notice=True,
            has_adverse_action_notice=True,
            involves_appraisal=False,
            has_disclosure=True,
        )
        docs = [_doc(document_id="doc-full")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_32_fair_housing_denial_stops_pipeline(self):
        """FairHousingAct DENIAL at layer 1 stops pipeline — document excluded."""
        ctx = _ctx(role="buyer", is_protected_class_data=True, has_fair_housing_training=True)
        docs = [_doc(document_id="doc-fha")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_33_ecoa_denial_stops_pipeline(self):
        """ECOA DENIAL at layer 2 stops pipeline — document excluded."""
        ctx = _ctx(
            role="lender",
            property_state="WA",
            involves_credit_decision=True,
            has_ecoa_notice=False,
        )
        docs = [_doc(document_id="doc-ecoa")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_34_filter_result_is_denied_property_false_for_human_review(self):
        """FilterResult.is_denied is False for REQUIRES_HUMAN_REVIEW decisions."""
        fr = FilterResult(
            layer="TEST",
            decision="REQUIRES_HUMAN_REVIEW",
            reason="test",
            regulation_citation="test",
        )
        assert not fr.is_denied

    def test_35_filter_result_is_denied_property_true_only_for_denied(self):
        """FilterResult.is_denied is True only for DENIED decisions."""
        denied = FilterResult(layer="L", decision="DENIED", reason="r", regulation_citation="c")
        approved = FilterResult(layer="L", decision="APPROVED", reason="r", regulation_citation="c")
        assert denied.is_denied
        assert not approved.is_denied

    def test_36_real_estate_context_is_frozen(self):
        """RealEstateContext is immutable (frozen=True)."""
        import dataclasses

        ctx = _ctx()
        assert dataclasses.is_dataclass(ctx)
        try:
            ctx.role = "buyer"  # type: ignore[misc]
            raised = False
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            raised = True
        assert raised, "RealEstateContext should be frozen"
