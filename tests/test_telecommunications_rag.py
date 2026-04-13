"""
Tests for 38_telecommunications_rag.py

Covers FCCCPNIFilter, TCPAComplianceFilter, CALEAWiretapFilter,
TelecoCrossBorderFilter, TelecomRegulatoryRAGPipeline, and
TelecomRegulatoryAuditRecord.

40 tests total:
  [1-8]   FCCCPNIFilter
  [9-16]  TCPAComplianceFilter
  [17-23] CALEAWiretapFilter
  [24-30] TelecoCrossBorderFilter
  [31-36] Pipeline — filter_documents and filter_documents_with_audit
  [37-40] Full-stack integration and edge cases
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "telecommunications_rag_38"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "38_telecommunications_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
TelecomRegulatoryContext = mod.TelecomRegulatoryContext
TelecomRegulatoryDocument = mod.TelecomRegulatoryDocument
FilterResult = mod.FilterResult
FCCCPNIFilter = mod.FCCCPNIFilter
TCPAComplianceFilter = mod.TCPAComplianceFilter
CALEAWiretapFilter = mod.CALEAWiretapFilter
TelecoCrossBorderFilter = mod.TelecoCrossBorderFilter
TelecomRegulatoryRAGPipeline = mod.TelecomRegulatoryRAGPipeline
TelecomRegulatoryAuditRecord = mod.TelecomRegulatoryAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    user_id: str = "user-001",
    role: str = "carrier_agent",
    carrier_id: str = "carrier-test",
    customer_id: str = "cust-001",
    # CPNI
    data_type: str = "",
    purpose: str = "",
    third_party_sharing: bool = False,
    marketing_use: bool = False,
    # TCPA
    contact_method: str = "",
    prior_express_consent: bool = False,
    do_not_call_registry: bool = False,
    calling_time_hour: int | None = None,
    # CALEA
    intercept_type: str = "",
    court_order: bool = False,
    pen_register_order: bool = False,
    calea_compliance_certified: bool = True,
    # Cross-border
    destination_country: str = "US",
    international_service: bool = False,
    section_214_license: bool = True,
) -> object:
    return TelecomRegulatoryContext(
        user_id=user_id,
        role=role,
        carrier_id=carrier_id,
        customer_id=customer_id,
        data_type=data_type,
        purpose=purpose,
        third_party_sharing=third_party_sharing,
        marketing_use=marketing_use,
        contact_method=contact_method,
        prior_express_consent=prior_express_consent,
        do_not_call_registry=do_not_call_registry,
        calling_time_hour=calling_time_hour,
        intercept_type=intercept_type,
        court_order=court_order,
        pen_register_order=pen_register_order,
        calea_compliance_certified=calea_compliance_certified,
        destination_country=destination_country,
        international_service=international_service,
        section_214_license=section_214_license,
    )


def _doc(
    *,
    content: str = "Telecommunications record.",
    document_id: str = "doc-001",
    doc_type: str = "cpni_record",
) -> object:
    return TelecomRegulatoryDocument(
        content=content,
        document_id=document_id,
        doc_type=doc_type,
    )


# ---------------------------------------------------------------------------
# [1-8] FCCCPNIFilter
# ---------------------------------------------------------------------------


class TestFCCCPNIFilter:
    def setup_method(self):
        self.f = FCCCPNIFilter()

    def test_01_cpni_non_billing_purpose_without_consent_denied(self):
        """CPNI with analytics purpose and no consent is DENIED (§222(c)(1))."""
        ctx = _ctx(data_type="cpni", purpose="analytics", prior_express_consent=False)
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§222(c)(1)" in result.regulation_citation

    def test_02_cpni_non_billing_purpose_with_consent_approved(self):
        """CPNI with analytics purpose but opt-in consent is APPROVED."""
        ctx = _ctx(data_type="cpni", purpose="analytics", prior_express_consent=True)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_03_cpni_billing_purpose_approved(self):
        """CPNI for billing purpose without opt-in is APPROVED (§222(d))."""
        ctx = _ctx(data_type="cpni", purpose="billing", prior_express_consent=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_04_cpni_repair_purpose_approved(self):
        """CPNI for repair purpose without opt-in is APPROVED (§222(d))."""
        ctx = _ctx(data_type="cpni", purpose="repair", prior_express_consent=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_05_cpni_support_purpose_approved(self):
        """CPNI for support purpose without opt-in is APPROVED (§222(d))."""
        ctx = _ctx(data_type="cpni", purpose="support", prior_express_consent=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_06_cpni_third_party_sharing_without_consent_denied(self):
        """CPNI with third-party sharing flag and no consent is DENIED (§222(c)(1))."""
        ctx = _ctx(
            data_type="cpni",
            purpose="billing",
            third_party_sharing=True,
            prior_express_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§222(c)(1)" in result.regulation_citation
        assert (
            "third-party" in result.reason.lower()
            or "third_party" in result.reason.lower()
            or "third" in result.reason.lower()
        )  # noqa: E501

    def test_07_cpni_marketing_use_requires_human_review(self):
        """CPNI with marketing_use flag triggers REQUIRES_HUMAN_REVIEW (§222(c)(3))."""
        ctx = _ctx(
            data_type="cpni",
            purpose="billing",
            marketing_use=True,
            prior_express_consent=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§222(c)(3)" in result.regulation_citation

    def test_08_non_cpni_data_type_passes_through(self):
        """Non-CPNI data type is APPROVED immediately (not applicable)."""
        ctx = _ctx(data_type="public_network_info", purpose="")
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "Not applicable" in result.reason


# ---------------------------------------------------------------------------
# [9-16] TCPAComplianceFilter
# ---------------------------------------------------------------------------


class TestTCPAComplianceFilter:
    def setup_method(self):
        self.f = TCPAComplianceFilter()

    def test_09_robocall_without_consent_denied(self):
        """Robocall to wireless without prior express consent is DENIED (§227(b)(1)(A))."""
        ctx = _ctx(contact_method="robocall", prior_express_consent=False)
        result = self.f.evaluate(ctx, _doc(doc_type="contact_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§227(b)(1)(A)" in result.regulation_citation

    def test_10_autodialer_without_consent_denied(self):
        """Autodialer call without prior express consent is DENIED (§227(b)(1)(A))."""
        ctx = _ctx(contact_method="autodialer", prior_express_consent=False)
        result = self.f.evaluate(ctx, _doc(doc_type="contact_record"))
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_11_prerecorded_without_consent_denied(self):
        """Prerecorded voice call without prior express consent is DENIED (§227(b)(1)(A))."""
        ctx = _ctx(contact_method="prerecorded", prior_express_consent=False)
        result = self.f.evaluate(ctx, _doc(doc_type="contact_record"))
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_12_autodialer_with_consent_approved(self):
        """Autodialer call WITH prior express consent is APPROVED."""
        ctx = _ctx(contact_method="autodialer", prior_express_consent=True)
        result = self.f.evaluate(ctx, _doc(doc_type="contact_record"))
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_13_sms_without_consent_denied(self):
        """SMS without prior express consent is DENIED (§227(b)(1)(A) + FCC 2012 Order)."""
        ctx = _ctx(contact_method="sms", prior_express_consent=False)
        result = self.f.evaluate(ctx, _doc(doc_type="contact_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§227(b)(1)(A)" in result.regulation_citation

    def test_14_dnc_registry_flag_denied(self):
        """Contact on National DNC Registry is DENIED (§227(c)(5))."""
        ctx = _ctx(
            contact_method="human_agent",
            prior_express_consent=False,
            do_not_call_registry=True,
        )
        result = self.f.evaluate(ctx, _doc(doc_type="contact_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§227(c)(5)" in result.regulation_citation

    def test_15_call_before_8am_denied(self):
        """Outbound call at 7 AM local time is DENIED (47 CFR §64.1200(c)(1))."""
        ctx = _ctx(contact_method="human_agent", prior_express_consent=True, calling_time_hour=7)
        result = self.f.evaluate(ctx, _doc(doc_type="contact_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§64.1200(c)(1)" in result.regulation_citation

    def test_16_call_after_9pm_denied(self):
        """Outbound call at 22:00 (10 PM) local time is DENIED (47 CFR §64.1200(c)(1))."""
        ctx = _ctx(contact_method="human_agent", prior_express_consent=True, calling_time_hour=22)
        result = self.f.evaluate(ctx, _doc(doc_type="contact_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§64.1200(c)(1)" in result.regulation_citation


# ---------------------------------------------------------------------------
# [17-23] CALEAWiretapFilter
# ---------------------------------------------------------------------------


class TestCALEAWiretapFilter:
    def setup_method(self):
        self.f = CALEAWiretapFilter()

    def test_17_content_intercept_without_court_order_denied(self):
        """Content intercept without court order is DENIED (18 U.S.C. §2511)."""
        ctx = _ctx(intercept_type="content", court_order=False)
        result = self.f.evaluate(ctx, _doc(doc_type="intercept_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§2511" in result.regulation_citation

    def test_18_call_records_intercept_without_court_order_denied(self):
        """Call-record intercept without court order is DENIED (18 U.S.C. §2511)."""
        ctx = _ctx(intercept_type="call_records", court_order=False)
        result = self.f.evaluate(ctx, _doc(doc_type="call_detail_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§2511" in result.regulation_citation

    def test_19_content_intercept_with_court_order_approved(self):
        """Content intercept WITH valid court order is APPROVED."""
        ctx = _ctx(intercept_type="content", court_order=True)
        result = self.f.evaluate(ctx, _doc(doc_type="intercept_record"))
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_20_pen_register_without_order_denied(self):
        """Pen register data without pen-register court order is DENIED (18 U.S.C. §3121)."""
        ctx = _ctx(data_type="pen_register", pen_register_order=False)
        result = self.f.evaluate(ctx, _doc(doc_type="pen_register_record"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§3121" in result.regulation_citation

    def test_21_pen_register_with_order_approved(self):
        """Pen register data WITH pen-register court order is APPROVED."""
        ctx = _ctx(data_type="pen_register", pen_register_order=True)
        result = self.f.evaluate(ctx, _doc(doc_type="pen_register_record"))
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_22_calea_non_certified_requires_human_review(self):
        """Carrier without CALEA certification triggers REQUIRES_HUMAN_REVIEW (§1002)."""
        ctx = _ctx(calea_compliance_certified=False)
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§1002" in result.regulation_citation

    def test_23_non_intercept_non_pen_register_approved(self):
        """Non-intercept, non-pen-register record passes CALEA filter cleanly."""
        ctx = _ctx(intercept_type="", data_type="cpni", calea_compliance_certified=True)
        result = self.f.evaluate(ctx, _doc(doc_type="cpni_record"))
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [24-30] TelecoCrossBorderFilter
# ---------------------------------------------------------------------------


class TestTelecoCrossBorderFilter:
    def setup_method(self):
        self.f = TelecoCrossBorderFilter()

    def test_24_china_destination_denied(self):
        """Transfer to China is DENIED (FCC Order FCC 21-114)."""
        ctx = _ctx(destination_country="China")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "FCC 21-114" in result.regulation_citation or "FCC" in result.regulation_citation

    def test_25_russia_destination_denied(self):
        """Transfer to Russia is DENIED (OFAC sanctions)."""
        ctx = _ctx(destination_country="Russia")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_26_iran_destination_denied(self):
        """Transfer to Iran is DENIED (OFAC sanctions)."""
        ctx = _ctx(destination_country="Iran")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_27_north_korea_destination_denied(self):
        """Transfer to North Korea is DENIED (OFAC sanctions)."""
        ctx = _ctx(destination_country="North Korea")
        result = self.f.evaluate(ctx, _doc())
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_28_lawful_intercept_data_non_us_destination_denied(self):
        """Lawful-intercept data routed outside the US is DENIED (CALEA §1004)."""
        ctx = _ctx(data_type="lawful_intercept", destination_country="UK")
        result = self.f.evaluate(ctx, _doc(doc_type="lawful_intercept_capability"))
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§1004" in result.regulation_citation

    def test_29_no_section_214_license_international_service_requires_review(self):
        """International service without Section 214 license triggers REQUIRES_HUMAN_REVIEW."""
        ctx = _ctx(
            destination_country="Germany",
            international_service=True,
            section_214_license=False,
        )
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§214" in result.regulation_citation

    def test_30_us_domestic_transfer_approved(self):
        """US domestic transfer is APPROVED under CLOUD Act MLAT framework."""
        ctx = _ctx(destination_country="US")
        result = self.f.evaluate(ctx, _doc())
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "CLOUD Act" in result.regulation_citation or "§2713" in result.regulation_citation


# ---------------------------------------------------------------------------
# [31-36] Pipeline — filter_documents and filter_documents_with_audit
# ---------------------------------------------------------------------------


class TestTelecomRegulatoryRAGPipeline:
    def setup_method(self):
        self.pipeline = TelecomRegulatoryRAGPipeline()

    def test_31_clean_billing_context_all_documents_pass(self):
        """Clean billing context with no restricted flags passes all documents."""
        ctx = _ctx(
            data_type="cpni",
            purpose="billing",
            prior_express_consent=False,
            destination_country="US",
            calea_compliance_certified=True,
            section_214_license=True,
        )
        docs = [_doc(document_id=f"doc-{i}") for i in range(3)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 3

    def test_32_cpni_analytics_without_consent_denied(self):
        """CPNI analytics document without consent is excluded from pipeline result."""
        ctx = _ctx(data_type="cpni", purpose="analytics", prior_express_consent=False)
        docs = [_doc(document_id="doc-deny-cpni")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_33_tcpa_autodialer_without_consent_denied_in_pipeline(self):
        """Autodialer contact record without consent is excluded from pipeline result."""
        ctx = _ctx(contact_method="autodialer", prior_express_consent=False)
        docs = [_doc(document_id="doc-deny-tcpa", doc_type="contact_record")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_34_calea_requires_human_review_document_included(self):
        """CALEA REQUIRES_HUMAN_REVIEW (non-certified carrier) does not exclude document."""
        ctx = _ctx(
            data_type="",
            purpose="",
            calea_compliance_certified=False,
            destination_country="US",
        )
        docs = [_doc(document_id="doc-review-calea")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_35_empty_document_list_returns_empty(self):
        """Empty document list returns empty result."""
        ctx = _ctx()
        result = self.pipeline.filter_documents(ctx, [])
        assert result == []

    def test_36_audit_record_type_and_structure(self):
        """filter_documents_with_audit returns TelecomRegulatoryAuditRecord with correct keys."""
        ctx = _ctx(
            data_type="cpni",
            purpose="billing",
            destination_country="US",
        )
        docs = [_doc()]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert isinstance(record, TelecomRegulatoryAuditRecord)
        log = record.to_audit_log()
        assert isinstance(log, dict)
        required_keys = {
            "event",
            "user_id",
            "carrier_id",
            "data_type",
            "purpose",
            "documents_in",
            "documents_out",
            "decisions",
            "timestamp",
        }
        assert required_keys.issubset(set(log.keys()))
        assert log["event"] == "TELECOM_REGULATORY_RAG_RETRIEVAL"
        assert log["documents_in"] == 1


# ---------------------------------------------------------------------------
# [37-40] Full-stack integration and edge cases
# ---------------------------------------------------------------------------


class TestFullStackAndEdgeCases:
    def setup_method(self):
        self.pipeline = TelecomRegulatoryRAGPipeline()

    def test_37_cross_filter_integration_all_four_pass(self):
        """A fully compliant document passes all four filter layers end-to-end."""
        ctx = _ctx(
            data_type="cpni",
            purpose="support",
            prior_express_consent=False,
            third_party_sharing=False,
            marketing_use=False,
            contact_method="human_agent",
            do_not_call_registry=False,
            calling_time_hour=10,  # 10 AM — within allowed window
            intercept_type="",
            court_order=False,
            calea_compliance_certified=True,
            destination_country="US",
            international_service=False,
            section_214_license=True,
        )
        docs = [_doc(document_id="doc-all-pass")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_38_context_and_document_are_frozen_dataclasses(self):
        """TelecomRegulatoryContext and TelecomRegulatoryDocument are frozen=True."""
        import dataclasses

        ctx = _ctx()
        assert dataclasses.is_dataclass(ctx)
        ctx_raised = False
        try:
            ctx.role = "hacker"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            ctx_raised = True
        assert ctx_raised, "TelecomRegulatoryContext must be frozen"

        doc = _doc()
        assert dataclasses.is_dataclass(doc)
        doc_raised = False
        try:
            doc.content = "tampered"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            doc_raised = True
        assert doc_raised, "TelecomRegulatoryDocument must be frozen"

    def test_39_filter_result_is_denied_semantics(self):
        """FilterResult.is_denied is True only for DENIED; False for APPROVED and REQUIRES_HUMAN_REVIEW."""
        denied = FilterResult(layer="L", decision="DENIED", reason="r", regulation_citation="c")
        approved = FilterResult(layer="L", decision="APPROVED", reason="r", regulation_citation="c")
        review = FilterResult(layer="L", decision="REQUIRES_HUMAN_REVIEW", reason="r", regulation_citation="c")
        assert denied.is_denied is True
        assert approved.is_denied is False
        assert review.is_denied is False

    def test_40_missing_keys_default_to_safe_approved(self):
        """Context with all-default values (no restricted flags set) produces APPROVED pipeline."""
        # Minimal context — all defaults, no CPNI data_type, no contact method,
        # no intercept type, US destination, certified CALEA — should pass all four layers.
        ctx = TelecomRegulatoryContext(
            user_id="default-user",
            role="carrier_agent",
        )
        docs = [_doc(document_id="doc-default")]
        result = self.pipeline.filter_documents(ctx, docs)
        # With default values (data_type="", contact_method="", intercept_type="",
        # destination_country="US", calea_compliance_certified=True),
        # all layers should approve.
        assert len(result) == 1
