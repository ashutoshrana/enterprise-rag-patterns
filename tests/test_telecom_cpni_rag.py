"""
Tests for 30_telecom_cpni_rag.py

Covers CPNIAccessFilter, CALEAFilter, FCCBroadbandPrivacyFilter,
StateTelecomPrivacyFilter, TelecomCPNIRAGPipeline, and TelecomAuditRecord.

36 tests total:
  [1-5]   CPNI consent gate
  [6-7]   CPNI authentication gate for call detail records
  [8-10]  CALEA lawful intercept
  [11-14] FCC broadband privacy
  [15-17] State CPNI (California)
  [18-22] Full pipeline integration
  [23-26] TelecomAuditRecord.to_audit_log() structure
  [27-30] Role-based access (carrier agent, authenticated)
  [31-36] Edge cases and additional coverage
"""

from __future__ import annotations

import os
import sys
import importlib.util
import types

# ---------------------------------------------------------------------------
# Load module via importlib (required for frozen dataclasses)
# ---------------------------------------------------------------------------

_name = "telecom_cpni_rag_30"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "30_telecom_cpni_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
TelecomContext = mod.TelecomContext
TelecomDocument = mod.TelecomDocument
TelecomRole = mod.TelecomRole
TelecomDocumentType = mod.TelecomDocumentType
Decision = mod.Decision
FilterResult = mod.FilterResult
CPNIAccessFilter = mod.CPNIAccessFilter
CALEAFilter = mod.CALEAFilter
FCCBroadbandPrivacyFilter = mod.FCCBroadbandPrivacyFilter
StateTelecomPrivacyFilter = mod.StateTelecomPrivacyFilter
TelecomCPNIRAGPipeline = mod.TelecomCPNIRAGPipeline
TelecomAuditRecord = mod.TelecomAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def _ctx(
    *,
    user_id: str = "u-001",
    role: object = None,
    customer_id: str = "cust-001",
    carrier_id: str = "carrier-test",
    has_cpni_consent: bool = False,
    has_broadband_privacy_consent: bool = False,
    has_ccpa_consent: bool = False,
    is_authenticated: bool = False,
    has_court_order: bool = False,
    access_purpose: str = "service_provisioning",
    customer_state: str = "TX",
    is_law_enforcement: bool = False,
) -> object:
    if role is None:
        role = TelecomRole.CARRIER_AGENT
    return TelecomContext(
        user_id=user_id,
        role=role,
        customer_id=customer_id,
        carrier_id=carrier_id,
        has_cpni_consent=has_cpni_consent,
        has_broadband_privacy_consent=has_broadband_privacy_consent,
        has_ccpa_consent=has_ccpa_consent,
        is_authenticated=is_authenticated,
        has_court_order=has_court_order,
        access_purpose=access_purpose,
        customer_state=customer_state,
        is_law_enforcement=is_law_enforcement,
    )


def _cpni_doc(
    *,
    document_id: str = "doc-cpni",
    document_type: object = None,
    is_call_detail_record: bool = False,
    is_sensitive_broadband_data: bool = False,
    is_lawful_intercept_record: bool = False,
    contains_inferred_data: bool = False,
    classification: str = "CPNI",
) -> object:
    if document_type is None:
        document_type = TelecomDocumentType.ACCOUNT_INFO
    return TelecomDocument(
        document_id=document_id,
        document_type=document_type,
        customer_id="cust-001",
        is_call_detail_record=is_call_detail_record,
        is_sensitive_broadband_data=is_sensitive_broadband_data,
        is_lawful_intercept_record=is_lawful_intercept_record,
        contains_inferred_data=contains_inferred_data,
        classification=classification,
    )


def _public_doc(document_id: str = "doc-public") -> object:
    return _cpni_doc(document_id=document_id, classification="PUBLIC")


def _cdr_doc(document_id: str = "doc-cdr") -> object:
    return _cpni_doc(
        document_id=document_id,
        document_type=TelecomDocumentType.CALL_DETAIL_RECORD,
        is_call_detail_record=True,
    )


def _intercept_doc(document_id: str = "doc-intercept") -> object:
    return _cpni_doc(
        document_id=document_id,
        document_type=TelecomDocumentType.LAWFUL_INTERCEPT_RECORD,
        is_lawful_intercept_record=True,
        classification="LAWFUL_INTERCEPT",
    )


def _broadband_doc(
    *,
    document_id: str = "doc-bb",
    is_sensitive_broadband_data: bool = True,
    contains_inferred_data: bool = False,
) -> object:
    return _cpni_doc(
        document_id=document_id,
        document_type=TelecomDocumentType.BROADBAND_USAGE,
        is_sensitive_broadband_data=is_sensitive_broadband_data,
        contains_inferred_data=contains_inferred_data,
    )


def _inferred_doc(document_id: str = "doc-inferred") -> object:
    return _cpni_doc(
        document_id=document_id,
        document_type=TelecomDocumentType.INFERRED_PROFILE,
        is_sensitive_broadband_data=True,
        contains_inferred_data=True,
    )


# ---------------------------------------------------------------------------
# Tests 1–5: CPNI consent gate (CPNIAccessFilter)
# ---------------------------------------------------------------------------

class TestCPNIConsentGate:
    """Tests 1-5: consent rules under 47 CFR §64.2005 / §64.2009."""

    def test_01_cpni_permitted_with_consent(self):
        """Test 1: CPNI doc permitted when customer has given opt-in consent."""
        f = CPNIAccessFilter()
        ctx = _ctx(has_cpni_consent=True, is_authenticated=True)
        doc = _cpni_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_02_cpni_denied_without_consent(self):
        """Test 2: CPNI doc denied when consent is absent and no bypass applies."""
        f = CPNIAccessFilter()
        ctx = _ctx(has_cpni_consent=False, is_authenticated=True, access_purpose="marketing")
        doc = _cpni_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "§64.2005" in result.regulation_citation

    def test_03_cpni_emergency_bypass(self):
        """Test 3: Emergency 911 purpose bypasses CPNI consent gate (§64.2009)."""
        f = CPNIAccessFilter()
        ctx = _ctx(has_cpni_consent=False, is_authenticated=True, access_purpose="emergency_911")
        doc = _cpni_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED
        assert "§64.2009" in result.regulation_citation

    def test_04_cpni_law_enforcement_bypass(self):
        """Test 4: Law enforcement court order purpose bypasses CPNI consent gate."""
        f = CPNIAccessFilter()
        ctx = _ctx(
            has_cpni_consent=False,
            is_authenticated=True,
            access_purpose="law_enforcement_court_order",
            is_law_enforcement=True,
        )
        doc = _cpni_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_05_cpni_billing_dispute_bypass(self):
        """Test 5: Billing dispute purpose bypasses CPNI consent gate (§64.2009)."""
        f = CPNIAccessFilter()
        ctx = _ctx(has_cpni_consent=False, is_authenticated=True, access_purpose="billing_dispute")
        doc = _cpni_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 6–7: CPNI authentication gate for call detail records (§64.2007)
# ---------------------------------------------------------------------------

class TestCPNIAuthenticationGate:
    """Tests 6-7: authentication required for call detail records (§64.2007)."""

    def test_06_cdr_denied_without_authentication(self):
        """Test 6: CDR denied when request is not authenticated, even with consent."""
        f = CPNIAccessFilter()
        ctx = _ctx(has_cpni_consent=True, is_authenticated=False)
        doc = _cdr_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "§64.2007" in result.regulation_citation

    def test_07_cdr_permitted_when_authenticated_with_consent(self):
        """Test 7: CDR permitted when authenticated and CPNI consent is present."""
        f = CPNIAccessFilter()
        ctx = _ctx(has_cpni_consent=True, is_authenticated=True)
        doc = _cdr_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 8–10: CALEA lawful intercept (CALEAFilter)
# ---------------------------------------------------------------------------

class TestCALEAFilter:
    """Tests 8-10: CALEA 47 USC §1002 lawful intercept gate."""

    def test_08_intercept_denied_without_court_order(self):
        """Test 8: Lawful intercept record denied when no court order is present."""
        f = CALEAFilter()
        ctx = _ctx(has_court_order=False)
        doc = _intercept_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "CALEA" in result.regulation_citation
        assert "court order" in result.reason.lower()

    def test_09_intercept_permitted_with_court_order(self):
        """Test 9: Lawful intercept record permitted when valid court order exists."""
        f = CALEAFilter()
        ctx = _ctx(has_court_order=True, is_law_enforcement=True)
        doc = _intercept_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_10_non_intercept_passes_calea(self):
        """Test 10: Non-intercept document passes CALEA filter without restriction."""
        f = CALEAFilter()
        ctx = _ctx(has_court_order=False)
        doc = _cpni_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 11–14: FCC broadband privacy (FCCBroadbandPrivacyFilter)
# ---------------------------------------------------------------------------

class TestFCCBroadbandPrivacyFilter:
    """Tests 11-14: 47 CFR Part 64 Subpart U broadband privacy controls."""

    def test_11_sensitive_broadband_denied_without_consent(self):
        """Test 11: Sensitive broadband data denied without opt-in consent."""
        f = FCCBroadbandPrivacyFilter()
        ctx = _ctx(has_broadband_privacy_consent=False)
        doc = _broadband_doc(is_sensitive_broadband_data=True)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "Subpart U" in result.regulation_citation

    def test_12_sensitive_broadband_permitted_with_consent(self):
        """Test 12: Sensitive broadband data permitted when opt-in consent is present."""
        f = FCCBroadbandPrivacyFilter()
        ctx = _ctx(has_broadband_privacy_consent=True)
        doc = _broadband_doc(is_sensitive_broadband_data=True)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_13_non_sensitive_broadband_billing_permitted(self):
        """Test 13: Non-sensitive broadband data for billing is permitted without opt-in."""
        f = FCCBroadbandPrivacyFilter()
        ctx = _ctx(has_broadband_privacy_consent=False, access_purpose="billing_dispute")
        # Non-sensitive broadband doc (billing totals only)
        doc = _broadband_doc(is_sensitive_broadband_data=False)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_14_non_broadband_passes_filter(self):
        """Test 14: Non-broadband document passes FCC broadband privacy filter."""
        f = FCCBroadbandPrivacyFilter()
        ctx = _ctx(has_broadband_privacy_consent=False)
        doc = _cpni_doc(
            document_type=TelecomDocumentType.CALL_DETAIL_RECORD,
            is_call_detail_record=True,
            is_sensitive_broadband_data=False,
        )
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 15–17: State CPNI — California (StateTelecomPrivacyFilter)
# ---------------------------------------------------------------------------

class TestStateTelecomPrivacyFilter:
    """Tests 15-17: CalOPPA + CCPA §1798.100 California subscriber rules."""

    def test_15_ca_inferred_denied_without_ccpa_consent(self):
        """Test 15: Inferred profile for CA subscriber denied without CCPA consent."""
        f = StateTelecomPrivacyFilter()
        ctx = _ctx(customer_state="CA", has_ccpa_consent=False)
        doc = _inferred_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "CCPA" in result.regulation_citation

    def test_16_ca_inferred_permitted_with_ccpa_consent(self):
        """Test 16: Inferred profile for CA subscriber permitted when CCPA consent is given."""
        f = StateTelecomPrivacyFilter()
        ctx = _ctx(
            customer_state="CA",
            has_ccpa_consent=True,
            has_broadband_privacy_consent=True,
        )
        doc = _inferred_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_17_non_ca_inferred_passes_state_filter(self):
        """Test 17: Inferred profile for non-CA subscriber passes state privacy filter."""
        f = StateTelecomPrivacyFilter()
        ctx = _ctx(customer_state="NY", has_ccpa_consent=False)
        doc = _inferred_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED


# ---------------------------------------------------------------------------
# Tests 18–22: Full pipeline integration
# ---------------------------------------------------------------------------

class TestPipelineIntegration:
    """Tests 18-22: end-to-end TelecomCPNIRAGPipeline behavior."""

    def test_18_fully_permitted_path(self):
        """Test 18: A fully compliant request permits the document through all layers."""
        pipeline = TelecomCPNIRAGPipeline()
        ctx = _ctx(
            has_cpni_consent=True,
            has_broadband_privacy_consent=True,
            has_ccpa_consent=True,
            is_authenticated=True,
            customer_state="CA",
        )
        doc = _cpni_doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 1
        assert results[0][0].document_id == doc.document_id

    def test_19_denied_path_no_cpni_consent(self):
        """Test 19: Document denied by CPNIAccessFilter when consent is missing."""
        pipeline = TelecomCPNIRAGPipeline()
        ctx = _ctx(has_cpni_consent=False, is_authenticated=True, access_purpose="marketing")
        doc = _cpni_doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 0

    def test_20_intercept_denied_without_court_order(self):
        """Test 20: Intercept record denied by CALEA layer when court order is absent."""
        pipeline = TelecomCPNIRAGPipeline()
        ctx = _ctx(
            has_cpni_consent=True,
            is_authenticated=True,
            has_court_order=False,
            access_purpose="law_enforcement_court_order",
        )
        doc = _intercept_doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 0

    def test_21_public_doc_passes_all_layers(self):
        """Test 21: A PUBLIC-classified document passes all four pipeline layers."""
        pipeline = TelecomCPNIRAGPipeline()
        ctx = _ctx()  # no consents, unauthenticated — doesn't matter for PUBLIC
        doc = _public_doc()
        results = pipeline.retrieve(ctx, [doc])
        assert len(results) == 1

    def test_22_mixed_batch_filters_correctly(self):
        """Test 22: Pipeline correctly permits and denies in a mixed batch."""
        pipeline = TelecomCPNIRAGPipeline()
        # Context has consent so CPNI doc passes; no broadband consent so sensitive bb denied
        ctx = _ctx(
            has_cpni_consent=True,
            has_broadband_privacy_consent=False,
            is_authenticated=True,
        )
        cpni = _cpni_doc(document_id="cpni-ok")
        bb = _broadband_doc(document_id="bb-denied", is_sensitive_broadband_data=True)
        results = pipeline.retrieve(ctx, [cpni, bb])
        permitted_ids = [r[0].document_id for r in results]
        assert "cpni-ok" in permitted_ids
        assert "bb-denied" not in permitted_ids


# ---------------------------------------------------------------------------
# Tests 23–26: TelecomAuditRecord.to_audit_log() structure
# ---------------------------------------------------------------------------

class TestTelecomAuditRecord:
    """Tests 23-26: audit log structure and field correctness."""

    def _run_audit(self, docs, ctx=None):
        if ctx is None:
            ctx = _ctx(
                has_cpni_consent=True,
                has_broadband_privacy_consent=True,
                is_authenticated=True,
            )
        pipeline = TelecomCPNIRAGPipeline()
        return pipeline.retrieve_with_audit(ctx, docs)

    def test_23_audit_log_event_name(self):
        """Test 23: to_audit_log() returns the correct event name."""
        audit = self._run_audit([_cpni_doc()])
        log = audit.to_audit_log()
        assert log["event"] == "TELECOM_CPNI_RAG_RETRIEVAL"

    def test_24_audit_log_document_counts(self):
        """Test 24: Audit log documents_evaluated / permitted / denied counts are correct."""
        ctx = _ctx(
            has_cpni_consent=True,
            has_broadband_privacy_consent=False,
            is_authenticated=True,
            access_purpose="service_provisioning",
        )
        docs = [
            _cpni_doc(document_id="d1"),  # passes all layers
            _broadband_doc(document_id="d2", is_sensitive_broadband_data=True),  # denied at bb layer
        ]
        pipeline = TelecomCPNIRAGPipeline()
        audit = pipeline.retrieve_with_audit(ctx, docs)
        log = audit.to_audit_log()
        assert log["documents_evaluated"] == 2
        assert log["documents_permitted"] == 1
        assert log["documents_denied"] == 1

    def test_25_audit_log_contains_required_fields(self):
        """Test 25: Audit log contains all required top-level fields."""
        audit = self._run_audit([_cpni_doc()])
        log = audit.to_audit_log()
        required_fields = {
            "event", "user_id", "carrier_id", "customer_id", "role",
            "access_purpose", "documents_evaluated", "documents_permitted",
            "documents_denied", "filter_results", "timestamp",
        }
        assert required_fields.issubset(set(log.keys()))

    def test_26_audit_log_filter_results_structure(self):
        """Test 26: filter_results list contains document_id and final_decision keys."""
        audit = self._run_audit([_cpni_doc(document_id="doc-x")])
        log = audit.to_audit_log()
        assert len(log["filter_results"]) == 1
        fr = log["filter_results"][0]
        assert fr["document_id"] == "doc-x"
        assert "final_decision" in fr
        assert "layer_results" in fr


# ---------------------------------------------------------------------------
# Tests 27–30: Role-based access (carrier agent with authenticated access)
# ---------------------------------------------------------------------------

class TestRoleBasedAccess:
    """Tests 27-30: role and authentication interactions."""

    def test_27_carrier_agent_authenticated_with_consent_permitted(self):
        """Test 27: Authenticated carrier agent with CPNI consent accesses CDR."""
        f = CPNIAccessFilter()
        ctx = _ctx(
            role=TelecomRole.CARRIER_AGENT,
            has_cpni_consent=True,
            is_authenticated=True,
        )
        doc = _cdr_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_28_billing_system_role_with_billing_purpose(self):
        """Test 28: Billing system role with billing_dispute purpose bypasses CPNI consent."""
        f = CPNIAccessFilter()
        ctx = _ctx(
            role=TelecomRole.BILLING_SYSTEM,
            has_cpni_consent=False,
            is_authenticated=True,
            access_purpose="billing_dispute",
        )
        doc = _cpni_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_29_regulator_without_consent_denied_for_non_bypass_purpose(self):
        """Test 29: Regulator role does not bypass CPNI consent for non-bypass purposes."""
        f = CPNIAccessFilter()
        ctx = _ctx(
            role=TelecomRole.REGULATOR,
            has_cpni_consent=False,
            is_authenticated=True,
            access_purpose="regulatory_audit",
        )
        doc = _cpni_doc()
        result = f.evaluate(ctx, doc)
        # regulatory_audit is not an enumerated §64.2009 bypass purpose
        assert result.decision == Decision.DENIED

    def test_30_law_enforcement_without_court_order_denied_intercept(self):
        """Test 30: Law enforcement role alone does not bypass CALEA court order requirement."""
        f = CALEAFilter()
        ctx = _ctx(
            role=TelecomRole.LAW_ENFORCEMENT,
            is_law_enforcement=True,
            has_court_order=False,
        )
        doc = _intercept_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED


# ---------------------------------------------------------------------------
# Tests 31–36: Edge cases and additional coverage
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Tests 31-36: edge cases, citation checks, and boundary conditions."""

    def test_31_non_cpni_document_passes_cpni_filter(self):
        """Test 31: PUBLIC-classified document passes CPNIAccessFilter regardless of consent."""
        f = CPNIAccessFilter()
        ctx = _ctx(has_cpni_consent=False, is_authenticated=False)
        doc = _public_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_32_cdr_authentication_check_precedes_consent_check(self):
        """Test 32: CDR authentication denial fires even when consent is present."""
        f = CPNIAccessFilter()
        # Consent is True but authentication is False — should still be DENIED on auth
        ctx = _ctx(has_cpni_consent=True, is_authenticated=False)
        doc = _cdr_doc()
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.DENIED
        assert "§64.2007" in result.regulation_citation

    def test_33_calea_intercept_court_order_overrides_missing_cpni_consent(self):
        """Test 33: Pipeline permits intercept doc with court order even without CPNI consent."""
        pipeline = TelecomCPNIRAGPipeline()
        ctx = _ctx(
            role=TelecomRole.LAW_ENFORCEMENT,
            has_cpni_consent=False,
            is_authenticated=True,
            has_court_order=True,
            access_purpose="law_enforcement_court_order",
            is_law_enforcement=True,
        )
        doc = _intercept_doc()
        results = pipeline.retrieve(ctx, [doc])
        # CPNI filter passes (law_enforcement_court_order bypass), CALEA passes (court order)
        assert len(results) == 1

    def test_34_ca_customer_non_inferred_doc_no_ccpa_required(self):
        """Test 34: CA customer accessing non-inferred CPNI doc doesn't trigger CCPA denial."""
        f = StateTelecomPrivacyFilter()
        ctx = _ctx(customer_state="CA", has_ccpa_consent=False)
        doc = _cpni_doc(contains_inferred_data=False)
        result = f.evaluate(ctx, doc)
        assert result.decision == Decision.PERMITTED

    def test_35_filter_result_is_denied_property(self):
        """Test 35: FilterResult.is_denied returns True only for DENIED decisions."""
        denied = FilterResult(
            layer="TEST",
            decision=Decision.DENIED,
            reason="test",
            regulation_citation="test",
        )
        permitted = FilterResult(
            layer="TEST",
            decision=Decision.PERMITTED,
            reason="test",
            regulation_citation="test",
        )
        assert denied.is_denied is True
        assert permitted.is_denied is False

    def test_36_pipeline_stops_on_first_denial(self):
        """Test 36: Pipeline stops processing layers after the first DENIED result."""
        pipeline = TelecomCPNIRAGPipeline()
        ctx = _ctx(
            has_cpni_consent=False,
            is_authenticated=True,
            access_purpose="marketing",  # no bypass
        )
        doc = _cpni_doc()
        results = pipeline.retrieve(ctx, [doc])
        # Document should be denied; verify pipeline ran and returned empty list
        assert results == []
        # Verify via retrieve_with_audit that the denial was caught at layer 1
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        log = audit.to_audit_log()
        fr = log["filter_results"][0]
        assert fr["final_decision"] == "DENIED"
        # Only layer 1 should have run (pipeline stops on first denial)
        assert len(fr["layer_results"]) == 1
        assert fr["layer_results"][0]["layer"] == CPNIAccessFilter.LAYER_NAME
