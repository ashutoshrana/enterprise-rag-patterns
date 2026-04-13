"""
Tests for 33_insurance_naic_rag.py

Covers NAICModelActFilter, FCRAInsuranceFilter, StateInsuranceAIFilter,
InsuranceLoBFilter, InsuranceNAICRAGPipeline, and InsuranceRAGAuditRecord.

36 tests total:
  [1-5]   NAICModelActFilter
  [6-9]   FCRAInsuranceFilter
  [10-13] StateInsuranceAIFilter
  [14-17] InsuranceLoBFilter
  [18-23] Full pipeline integration
  [24-28] InsuranceRAGAuditRecord.to_audit_log() structure
  [29-36] Edge cases and additional coverage
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "insurance_naic_rag_33"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "33_insurance_naic_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
InsuranceRAGContext = mod.InsuranceRAGContext
InsuranceRAGDocument = mod.InsuranceRAGDocument
InsuranceRequesterRole = mod.InsuranceRequesterRole
InsuranceDocumentCategory = mod.InsuranceDocumentCategory
FilterResult = mod.FilterResult
NAICModelActFilter = mod.NAICModelActFilter
FCRAInsuranceFilter = mod.FCRAInsuranceFilter
StateInsuranceAIFilter = mod.StateInsuranceAIFilter
InsuranceLoBFilter = mod.InsuranceLoBFilter
InsuranceNAICRAGPipeline = mod.InsuranceNAICRAGPipeline
InsuranceRAGAuditRecord = mod.InsuranceRAGAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    user_id: str = "user-001",
    role: object = None,
    company_id: str = "company-001",
    state: str = "NY",
    is_consumer_request: bool = False,
    has_underwriting_authority: bool = True,
    is_ai_model_decision: bool = False,
    ai_model_registered: bool = False,
    has_adverse_action_basis: bool = False,
    adverse_action_notice_sent: bool = False,
    authorized_lines_of_business: object = None,
    is_state_regulator_exam: bool = False,
    customer_consent_given: bool = True,
    processing_purpose: str = "underwriting_review",
) -> object:
    if role is None:
        role = InsuranceRequesterRole.UNDERWRITER
    if authorized_lines_of_business is None:
        authorized_lines_of_business = frozenset({"AUTO", "PROPERTY"})
    return InsuranceRAGContext(
        user_id=user_id,
        role=role,
        company_id=company_id,
        state=state,
        is_consumer_request=is_consumer_request,
        has_underwriting_authority=has_underwriting_authority,
        is_ai_model_decision=is_ai_model_decision,
        ai_model_registered=ai_model_registered,
        has_adverse_action_basis=has_adverse_action_basis,
        adverse_action_notice_sent=adverse_action_notice_sent,
        authorized_lines_of_business=authorized_lines_of_business,
        is_state_regulator_exam=is_state_regulator_exam,
        customer_consent_given=customer_consent_given,
        processing_purpose=processing_purpose,
    )


def _doc(
    *,
    document_id: str = "doc-001",
    category: object = None,
    consumer_id: str = "cons-001",
    line_of_business: str = "AUTO",
    state: str = "NY",
    contains_consumer_report_info: bool = False,
    contains_credit_score: bool = False,
    contains_medical_info: bool = False,
    is_adverse_action_doc: bool = False,
    requires_state_approval: bool = False,
) -> object:
    if category is None:
        category = InsuranceDocumentCategory.POLICY_FILE
    return InsuranceRAGDocument(
        document_id=document_id,
        category=category,
        consumer_id=consumer_id,
        line_of_business=line_of_business,
        state=state,
        contains_consumer_report_info=contains_consumer_report_info,
        contains_credit_score=contains_credit_score,
        contains_medical_info=contains_medical_info,
        is_adverse_action_doc=is_adverse_action_doc,
        requires_state_approval=requires_state_approval,
    )


def _consumer_report_doc(document_id: str = "doc-cr") -> object:
    return _doc(
        document_id=document_id,
        category=InsuranceDocumentCategory.CONSUMER_REPORT,
        contains_consumer_report_info=True,
    )


def _underwriting_doc(document_id: str = "doc-uw", state: str = "NY") -> object:
    return _doc(
        document_id=document_id,
        category=InsuranceDocumentCategory.UNDERWRITING_FILE,
        state=state,
    )


def _credit_score_doc(document_id: str = "doc-cs", state: str = "NY") -> object:
    return _doc(
        document_id=document_id,
        category=InsuranceDocumentCategory.CREDIT_BASED_INSURANCE_SCORE,
        contains_consumer_report_info=True,
        contains_credit_score=True,
        state=state,
    )


def _medical_doc(document_id: str = "doc-med", state: str = "NY") -> object:
    return _doc(
        document_id=document_id,
        category=InsuranceDocumentCategory.MEDICAL_RECORD,
        contains_medical_info=True,
        state=state,
    )


def _public_doc(document_id: str = "doc-pub") -> object:
    return _doc(
        document_id=document_id,
        category=InsuranceDocumentCategory.PUBLIC_FILING,
        line_of_business="",
    )


# ---------------------------------------------------------------------------
# Tests 1–5: NAICModelActFilter
# ---------------------------------------------------------------------------


class TestNAICModelActFilter:
    """Tests 1-5: NAIC Model Privacy Protection Act §13, §7, and AI Guidance."""

    def test_01_consumer_own_file_approved(self):
        """Test 1: Consumer self-access to own consumer report is approved (§13)."""
        f = NAICModelActFilter()
        ctx = _ctx(
            role=InsuranceRequesterRole.CONSUMER,
            is_consumer_request=True,
        )
        doc = _consumer_report_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "APPROVED"
        assert "13" in result.regulation_citation or "§13" in result.regulation_citation

    def test_02_regulator_access_approved(self):
        """Test 2: Regulator role always gets approved access (market conduct exam)."""
        f = NAICModelActFilter()
        ctx = _ctx(role=InsuranceRequesterRole.REGULATOR)
        doc = _underwriting_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "APPROVED"
        assert "NAIC Market Conduct" in result.reason or "regulatory" in result.reason.lower()

    def test_03_consumer_blocked_from_underwriting_file(self):
        """Test 3: Consumer access to underwriting file is denied (not own records)."""
        f = NAICModelActFilter()
        ctx = _ctx(
            role=InsuranceRequesterRole.CONSUMER,
            is_consumer_request=False,
        )
        doc = _underwriting_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "DENIED"
        assert "Consumer" in result.reason or "consumer" in result.reason

    def test_04_medical_info_restricted_to_authorized_roles(self):
        """Test 4: Agent accessing medical record is denied (§7 — not authorized role)."""
        f = NAICModelActFilter()
        ctx = _ctx(role=InsuranceRequesterRole.AGENT)
        doc = _medical_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "DENIED"
        assert "7" in result.regulation_citation or "§7" in result.regulation_citation

    def test_05_ai_model_unregistered_in_ca_requires_human_review(self):
        """Test 5: Unregistered AI model in CA triggers REQUIRES_HUMAN_REVIEW."""
        f = NAICModelActFilter()
        ctx = _ctx(
            state="CA",
            is_ai_model_decision=True,
            ai_model_registered=False,
        )
        doc = _underwriting_doc(state="CA")
        result = f.evaluate(ctx, doc)
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "CA" in result.reason


# ---------------------------------------------------------------------------
# Tests 6–9: FCRAInsuranceFilter
# ---------------------------------------------------------------------------


class TestFCRAInsuranceFilter:
    """Tests 6-9: FCRA §1681b permissible purpose and §1681m adverse action."""

    def test_06_no_consumer_report_info_approved(self):
        """Test 6: Documents without consumer report info are approved (FCRA not applicable)."""
        f = FCRAInsuranceFilter()
        ctx = _ctx()
        doc = _doc(contains_consumer_report_info=False, contains_credit_score=False)
        result = f.evaluate(ctx, doc)
        assert result.decision == "APPROVED"
        assert "FCRA" in result.reason

    def test_07_credit_score_adverse_action_no_notice_denied(self):
        """Test 7: Credit score + adverse action + no notice sent → DENIED (§1681m(a))."""
        f = FCRAInsuranceFilter()
        ctx = _ctx(
            role=InsuranceRequesterRole.UNDERWRITER,
            has_adverse_action_basis=True,
            adverse_action_notice_sent=False,
        )
        doc = _credit_score_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "DENIED"
        assert "1681m" in result.regulation_citation

    def test_08_credit_score_wrong_role_denied(self):
        """Test 8: Agent accessing credit score is denied (not authorized for credit scores)."""
        f = FCRAInsuranceFilter()
        ctx = _ctx(
            role=InsuranceRequesterRole.AGENT,
            has_adverse_action_basis=False,
        )
        doc = _credit_score_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "DENIED"
        assert "1681b" in result.regulation_citation

    def test_09_authorized_underwriter_approved(self):
        """Test 9: Underwriter with no adverse action basis is approved for consumer report."""
        f = FCRAInsuranceFilter()
        ctx = _ctx(
            role=InsuranceRequesterRole.UNDERWRITER,
            has_adverse_action_basis=False,
        )
        doc = _consumer_report_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "APPROVED"
        assert "1681b" in result.regulation_citation


# ---------------------------------------------------------------------------
# Tests 10–13: StateInsuranceAIFilter
# ---------------------------------------------------------------------------


class TestStateInsuranceAIFilter:
    """Tests 10-13: CA CDI 2022-5, IL IDOI 2021, CA Prop 103, state medical consent."""

    def test_10_ca_ai_unregistered_requires_human_review(self):
        """Test 10: Unregistered AI model in CA triggers REQUIRES_HUMAN_REVIEW (CDI 2022-5)."""
        f = StateInsuranceAIFilter()
        ctx = _ctx(
            state="CA",
            is_ai_model_decision=True,
            ai_model_registered=False,
        )
        doc = _underwriting_doc(state="CA")
        result = f.evaluate(ctx, doc)
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "California CDI" in result.regulation_citation or "CDI" in result.reason

    def test_11_il_ai_underwriting_requires_human_review(self):
        """Test 11: AI model accessing IL underwriting file triggers REQUIRES_HUMAN_REVIEW (IDOI 2021)."""
        f = StateInsuranceAIFilter()
        ctx = _ctx(
            state="IL",
            is_ai_model_decision=True,
            ai_model_registered=True,
        )
        doc = _underwriting_doc(state="IL")
        result = f.evaluate(ctx, doc)
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "Illinois" in result.regulation_citation or "IDOI" in result.reason

    def test_12_ca_credit_score_document_requires_human_review(self):
        """Test 12: Credit score document in CA triggers REQUIRES_HUMAN_REVIEW (Prop 103)."""
        f = StateInsuranceAIFilter()
        ctx = _ctx(state="CA", is_ai_model_decision=False)
        doc = _credit_score_doc(state="CA")
        result = f.evaluate(ctx, doc)
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "Proposition 103" in result.regulation_citation or "Prop" in result.reason

    def test_13_medical_no_consent_non_exempt_state_denied(self):
        """Test 13: Medical info without consumer consent in NY is denied."""
        f = StateInsuranceAIFilter()
        ctx = _ctx(state="NY", customer_consent_given=False, is_ai_model_decision=False)
        doc = _medical_doc(state="NY")
        result = f.evaluate(ctx, doc)
        assert result.decision == "DENIED"
        assert "consent" in result.reason.lower() or "Medical" in result.reason


# ---------------------------------------------------------------------------
# Tests 14–17: InsuranceLoBFilter
# ---------------------------------------------------------------------------


class TestInsuranceLoBFilter:
    """Tests 14-17: Line of Business authorization and actuarial data access."""

    def test_14_consumer_blocked_from_underwriting_file(self):
        """Test 14: Consumer cannot access underwriting files."""
        f = InsuranceLoBFilter()
        ctx = _ctx(role=InsuranceRequesterRole.CONSUMER)
        doc = _underwriting_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "DENIED"
        assert "Underwriting" in result.reason or "underwriting" in result.reason

    def test_15_unauthorized_lob_denied(self):
        """Test 15: User not authorized for a LoB is denied access to that LoB's document."""
        f = InsuranceLoBFilter()
        ctx = _ctx(
            role=InsuranceRequesterRole.AGENT,
            authorized_lines_of_business=frozenset({"AUTO"}),
        )
        doc = _doc(
            category=InsuranceDocumentCategory.POLICY_FILE,
            line_of_business="LIFE",
        )
        result = f.evaluate(ctx, doc)
        assert result.decision == "DENIED"
        assert "LIFE" in result.reason

    def test_16_actuarial_data_restricted_non_actuary(self):
        """Test 16: Claims adjuster cannot access actuarial data."""
        f = InsuranceLoBFilter()
        ctx = _ctx(role=InsuranceRequesterRole.CLAIMS_ADJUSTER)
        doc = _doc(category=InsuranceDocumentCategory.ACTUARIAL_DATA)
        result = f.evaluate(ctx, doc)
        assert result.decision == "DENIED"
        assert "Actuarial" in result.reason or "actuarial" in result.reason.lower()

    def test_17_authorized_lob_approved(self):
        """Test 17: User authorized for the document's LoB is approved."""
        f = InsuranceLoBFilter()
        ctx = _ctx(
            role=InsuranceRequesterRole.AGENT,
            authorized_lines_of_business=frozenset({"AUTO", "PROPERTY"}),
        )
        doc = _doc(
            category=InsuranceDocumentCategory.POLICY_FILE,
            line_of_business="AUTO",
        )
        result = f.evaluate(ctx, doc)
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# Tests 18–23: Full pipeline integration
# ---------------------------------------------------------------------------


class TestPipelineIntegration:
    """Tests 18-23: end-to-end InsuranceNAICRAGPipeline behavior."""

    def test_18_compliant_request_approved(self):
        """Test 18: A fully compliant underwriter request passes all four layers."""
        pipeline = InsuranceNAICRAGPipeline()
        ctx = _ctx(
            role=InsuranceRequesterRole.UNDERWRITER,
            state="NY",
            is_ai_model_decision=False,
            has_adverse_action_basis=False,
            authorized_lines_of_business=frozenset({"AUTO"}),
            customer_consent_given=True,
        )
        doc = _doc(
            category=InsuranceDocumentCategory.UNDERWRITING_FILE,
            line_of_business="AUTO",
            state="NY",
        )
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 1
        assert results[0].document_id == doc.document_id

    def test_19_stop_on_first_denial(self):
        """Test 19: Pipeline stops at first DENIED and excludes the document."""
        pipeline = InsuranceNAICRAGPipeline()
        ctx = _ctx(
            role=InsuranceRequesterRole.CONSUMER,
            is_consumer_request=False,
        )
        # Consumer requesting underwriting file is denied at layer 1 (NAIC) and layer 4 (LoB)
        doc = _underwriting_doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 0

    def test_20_audit_record_structure(self):
        """Test 20: retrieve_with_audit returns an InsuranceRAGAuditRecord with correct fields."""
        pipeline = InsuranceNAICRAGPipeline()
        ctx = _ctx()
        doc = _doc()
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        assert isinstance(audit, InsuranceRAGAuditRecord)
        assert audit.documents_evaluated == 1

    def test_21_to_audit_log_event_name(self):
        """Test 21: to_audit_log() returns the correct INSURANCE_NAIC_RAG_RETRIEVAL event name."""
        pipeline = InsuranceNAICRAGPipeline()
        ctx = _ctx()
        doc = _doc()
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        log = audit.to_audit_log()
        assert log["event"] == "INSURANCE_NAIC_RAG_RETRIEVAL"

    def test_22_requires_human_review_not_a_denial(self):
        """Test 22: REQUIRES_HUMAN_REVIEW document is included in pipeline results (not denied)."""
        pipeline = InsuranceNAICRAGPipeline()
        ctx = _ctx(
            state="CA",
            is_ai_model_decision=True,
            ai_model_registered=False,
            role=InsuranceRequesterRole.UNDERWRITER,
            authorized_lines_of_business=frozenset({"AUTO"}),
        )
        # CA unregistered AI model → REQUIRES_HUMAN_REVIEW at layer 1 (and possibly layer 3)
        doc = _doc(
            category=InsuranceDocumentCategory.UNDERWRITING_FILE,
            line_of_business="AUTO",
            state="CA",
        )
        results = pipeline.retrieve(ctx, [doc])
        # REQUIRES_HUMAN_REVIEW is not a denial; document should pass through
        assert len(results) == 1

    def test_23_regulator_override_all_layers(self):
        """Test 23: Regulator role passes all four pipeline layers on any document."""
        pipeline = InsuranceNAICRAGPipeline()
        ctx = _ctx(
            role=InsuranceRequesterRole.REGULATOR,
            state="CA",
            is_ai_model_decision=False,
            customer_consent_given=False,
            authorized_lines_of_business=frozenset(),
            is_state_regulator_exam=True,
        )
        docs = [
            _underwriting_doc(),
            _consumer_report_doc(),
            _public_doc(),
        ]
        results = pipeline.retrieve(ctx, docs)
        assert len(results) == 3


# ---------------------------------------------------------------------------
# Tests 24–28: InsuranceRAGAuditRecord.to_audit_log() structure
# ---------------------------------------------------------------------------


class TestInsuranceRAGAuditRecord:
    """Tests 24-28: audit log structure and field correctness."""

    def _run_audit(self, docs, ctx=None):
        if ctx is None:
            ctx = _ctx()
        pipeline = InsuranceNAICRAGPipeline()
        return pipeline.retrieve_with_audit(ctx, docs)

    def test_24_audit_log_required_fields(self):
        """Test 24: Audit log contains all required top-level fields."""
        audit = self._run_audit([_doc()])
        log = audit.to_audit_log()
        required = {
            "event",
            "user_id",
            "role",
            "company_id",
            "state",
            "is_consumer_request",
            "is_ai_model_decision",
            "ai_model_registered",
            "has_adverse_action_basis",
            "adverse_action_notice_sent",
            "is_state_regulator_exam",
            "processing_purpose",
            "documents_evaluated",
            "documents_permitted",
            "documents_denied",
            "documents_redacted",
            "filter_results",
            "timestamp",
        }
        assert required.issubset(set(log.keys()))

    def test_25_audit_log_document_counts(self):
        """Test 25: Audit log permitted/denied counts are correct for a mixed batch."""
        ctx = _ctx(
            role=InsuranceRequesterRole.UNDERWRITER,
            state="NY",
            authorized_lines_of_business=frozenset({"AUTO"}),
            customer_consent_given=True,
        )
        # doc1 passes (POLICY_FILE, AUTO, no sensitive content)
        doc1 = _doc(
            document_id="d1",
            category=InsuranceDocumentCategory.POLICY_FILE,
            line_of_business="AUTO",
        )
        # doc2 denied (LIFE line, user only authorized for AUTO)
        doc2 = _doc(
            document_id="d2",
            category=InsuranceDocumentCategory.POLICY_FILE,
            line_of_business="LIFE",
        )
        pipeline = InsuranceNAICRAGPipeline()
        audit = pipeline.retrieve_with_audit(ctx, [doc1, doc2])
        log = audit.to_audit_log()
        assert log["documents_evaluated"] == 2
        assert log["documents_permitted"] == 1
        assert log["documents_denied"] == 1

    def test_26_audit_log_filter_results_structure(self):
        """Test 26: filter_results entries contain document_id, final_decision, layer_results."""
        audit = self._run_audit([_doc(document_id="doc-x")])
        log = audit.to_audit_log()
        assert len(log["filter_results"]) == 1
        fr = log["filter_results"][0]
        assert fr["document_id"] == "doc-x"
        assert "final_decision" in fr
        assert "layer_results" in fr

    def test_27_audit_log_timestamp_present(self):
        """Test 27: Audit log timestamp field is present and is a positive float."""
        audit = self._run_audit([_doc()])
        log = audit.to_audit_log()
        assert isinstance(log["timestamp"], float)
        assert log["timestamp"] > 0

    def test_28_requires_human_review_counted_as_permitted(self):
        """Test 28: REQUIRES_HUMAN_REVIEW documents are counted as permitted (not denied)."""
        ctx = _ctx(
            state="CA",
            is_ai_model_decision=True,
            ai_model_registered=False,
            role=InsuranceRequesterRole.UNDERWRITER,
            authorized_lines_of_business=frozenset({"AUTO"}),
        )
        doc = _doc(
            category=InsuranceDocumentCategory.UNDERWRITING_FILE,
            line_of_business="AUTO",
            state="CA",
        )
        pipeline = InsuranceNAICRAGPipeline()
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        log = audit.to_audit_log()
        assert log["documents_denied"] == 0
        assert log["documents_evaluated"] == 1


# ---------------------------------------------------------------------------
# Tests 29–36: Edge cases and additional coverage
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests 29-36: edge cases, is_denied property, and boundary conditions."""

    def test_29_is_denied_false_for_requires_human_review(self):
        """Test 29: FilterResult.is_denied is False for REQUIRES_HUMAN_REVIEW."""
        result = FilterResult(
            layer="TEST",
            decision="REQUIRES_HUMAN_REVIEW",
            reason="test",
            regulation_citation="test",
        )
        assert result.is_denied is False

    def test_30_is_denied_false_for_redacted(self):
        """Test 30: FilterResult.is_denied is False for REDACTED decision."""
        result = FilterResult(
            layer="TEST",
            decision="REDACTED",
            reason="test",
            regulation_citation="test",
        )
        assert result.is_denied is False

    def test_31_is_denied_true_for_denied(self):
        """Test 31: FilterResult.is_denied is True only for DENIED."""
        result = FilterResult(
            layer="TEST",
            decision="DENIED",
            reason="test",
            regulation_citation="test",
        )
        assert result.is_denied is True

    def test_32_is_denied_false_for_approved(self):
        """Test 32: FilterResult.is_denied is False for APPROVED decision."""
        result = FilterResult(
            layer="TEST",
            decision="APPROVED",
            reason="test",
            regulation_citation="test",
        )
        assert result.is_denied is False

    def test_33_public_filing_accessible_to_agent(self):
        """Test 33: Public filing is accessible to an agent with no LoB restriction."""
        pipeline = InsuranceNAICRAGPipeline()
        ctx = _ctx(
            role=InsuranceRequesterRole.AGENT,
            authorized_lines_of_business=frozenset({"AUTO"}),
            state="NY",
            customer_consent_given=True,
            is_ai_model_decision=False,
        )
        doc = _public_doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 1

    def test_34_regulator_override_medical_no_consent(self):
        """Test 34: Regulator bypasses consent requirement for medical documents."""
        pipeline = InsuranceNAICRAGPipeline()
        ctx = _ctx(
            role=InsuranceRequesterRole.REGULATOR,
            state="NY",
            customer_consent_given=False,
            is_state_regulator_exam=True,
            authorized_lines_of_business=frozenset(),
        )
        doc = _medical_doc(state="NY")
        results = pipeline.retrieve(ctx, [doc])
        # Regulator is approved at layer 1 immediately; layer 3 medical check doesn't matter
        assert len(results) == 1

    def test_35_tx_medical_no_consent_exempt_approved(self):
        """Test 35: Medical info in TX does not require consumer consent (exempt state)."""
        f = StateInsuranceAIFilter()
        ctx = _ctx(
            state="TX",
            customer_consent_given=False,
            is_ai_model_decision=False,
        )
        doc = _medical_doc(state="TX")
        result = f.evaluate(ctx, doc)
        # TX is exempt from consent requirement for medical info
        assert result.decision == "APPROVED"

    def test_36_state_regulator_exam_approved_at_naic_layer(self):
        """Test 36: is_state_regulator_exam=True grants approval at the NAIC layer."""
        f = NAICModelActFilter()
        ctx = _ctx(
            role=InsuranceRequesterRole.AUDIT,
            is_state_regulator_exam=True,
        )
        doc = _underwriting_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == "APPROVED"
        assert "regulatory" in result.reason.lower() or "NAIC" in result.reason
