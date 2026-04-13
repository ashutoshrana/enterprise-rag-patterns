"""
Tests for 40_financial_services_rag.py

Covers DoddFrankFilter, SECRegulationSPFilter, FINRAComplianceFilter,
FinancialServicesCrossBorderFilter, FinancialServicesRAGPipeline, and
FinancialServicesAuditRecord.

52 tests total:
  [1-10]  DoddFrankFilter
  [11-20] SECRegulationSPFilter
  [21-30] FINRAComplianceFilter
  [31-41] FinancialServicesCrossBorderFilter
  [42-46] Pipeline — filter_documents and filter_documents_with_audit
  [47-52] Integration and edge cases
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "financial_services_rag_40"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "40_financial_services_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
FinancialServicesContext = mod.FinancialServicesContext
FinancialServicesDocument = mod.FinancialServicesDocument
FilterResult = mod.FilterResult
DoddFrankFilter = mod.DoddFrankFilter
SECRegulationSPFilter = mod.SECRegulationSPFilter
FINRAComplianceFilter = mod.FINRAComplianceFilter
FinancialServicesCrossBorderFilter = mod.FinancialServicesCrossBorderFilter
FinancialServicesRAGPipeline = mod.FinancialServicesRAGPipeline
FinancialServicesAuditRecord = mod.FinancialServicesAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    institution_type: str = "bank",
    is_broker_dealer: bool = False,
    is_investment_adviser: bool = False,
    has_swap_dealer_registration: bool = False,
) -> object:
    return FinancialServicesContext(
        institution_type=institution_type,
        is_broker_dealer=is_broker_dealer,
        is_investment_adviser=is_investment_adviser,
        has_swap_dealer_registration=has_swap_dealer_registration,
    )


def _doc(
    *,
    doc_id: str = "doc-001",
    data_classification: str = "general",
    contains_pii: bool = False,
    regulatory_scope: list | None = None,
    # Layer 1 — Dodd-Frank
    swap_data: bool = False,
    authorized_regulator_access: bool = False,
    systemically_important: bool = False,
    fsoc_oversight_documented: bool = False,
    volcker_rule_applicable: bool = False,
    proprietary_trading_data: bool = False,
    compliance_program_documented: bool = False,
    # Layer 2 — SEC Reg S-P
    nonpublic_personal_information: bool = False,
    privacy_notice_delivered: bool = False,
    opt_out_opportunity: bool = False,
    material_cybersecurity_incident: bool = False,
    sec_4day_disclosure_made: bool = False,
    # Layer 3 — FINRA
    customer_communication: bool = False,
    principal_approved: bool = False,
    order_data: bool = False,
    supervision_documented: bool = False,
    bcp_required: bool = False,
    bcp_filed_with_finra: bool = False,
    # Layer 4 — Cross-border
    fatca_reportable: bool = False,
    irs_reporting_completed: bool = False,
    suspicious_activity: bool = False,
    sar_filed: bool = False,
    destination_country: str = "",
    eu_financial_data: bool = False,
    scc_executed: bool = False,
) -> object:
    return FinancialServicesDocument(
        doc_id=doc_id,
        data_classification=data_classification,
        contains_pii=contains_pii,
        regulatory_scope=regulatory_scope if regulatory_scope is not None else [],
        swap_data=swap_data,
        authorized_regulator_access=authorized_regulator_access,
        systemically_important=systemically_important,
        fsoc_oversight_documented=fsoc_oversight_documented,
        volcker_rule_applicable=volcker_rule_applicable,
        proprietary_trading_data=proprietary_trading_data,
        compliance_program_documented=compliance_program_documented,
        nonpublic_personal_information=nonpublic_personal_information,
        privacy_notice_delivered=privacy_notice_delivered,
        opt_out_opportunity=opt_out_opportunity,
        material_cybersecurity_incident=material_cybersecurity_incident,
        sec_4day_disclosure_made=sec_4day_disclosure_made,
        customer_communication=customer_communication,
        principal_approved=principal_approved,
        order_data=order_data,
        supervision_documented=supervision_documented,
        bcp_required=bcp_required,
        bcp_filed_with_finra=bcp_filed_with_finra,
        fatca_reportable=fatca_reportable,
        irs_reporting_completed=irs_reporting_completed,
        suspicious_activity=suspicious_activity,
        sar_filed=sar_filed,
        destination_country=destination_country,
        eu_financial_data=eu_financial_data,
        scc_executed=scc_executed,
    )


# ---------------------------------------------------------------------------
# [1-10] DoddFrankFilter
# ---------------------------------------------------------------------------


class TestDoddFrankFilter:
    def setup_method(self):
        self.f = DoddFrankFilter()

    def test_01_swap_data_without_regulator_access_denied(self):
        """Dodd-Frank §728: swap_data without authorized_regulator_access is DENIED."""
        doc = _doc(swap_data=True, authorized_regulator_access=False)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§728" in result.reason

    def test_02_swap_data_with_regulator_access_approved(self):
        """Dodd-Frank §728: swap_data WITH authorized_regulator_access is APPROVED."""
        doc = _doc(swap_data=True, authorized_regulator_access=True)
        result = self.f.evaluate(_ctx(has_swap_dealer_registration=True), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_03_no_swap_data_approved(self):
        """Dodd-Frank: document with no swap_data flag is APPROVED."""
        doc = _doc(swap_data=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_04_fsoc_without_oversight_requires_review(self):
        """Dodd-Frank §113: systemically_important without fsoc_oversight_documented is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(systemically_important=True, fsoc_oversight_documented=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§113" in result.reason

    def test_05_fsoc_with_oversight_documented_approved(self):
        """Dodd-Frank §113: systemically_important WITH fsoc_oversight_documented is APPROVED."""
        doc = _doc(systemically_important=True, fsoc_oversight_documented=True)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_06_volcker_proprietary_trading_without_compliance_program_denied(self):
        """Dodd-Frank §619: volcker + proprietary_trading_data without compliance_program is DENIED."""
        doc = _doc(
            volcker_rule_applicable=True,
            proprietary_trading_data=True,
            compliance_program_documented=False,
        )
        result = self.f.evaluate(_ctx(institution_type="bank"), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§619" in result.reason or "Volcker" in result.reason

    def test_07_volcker_with_compliance_program_approved(self):
        """Dodd-Frank §619: volcker + proprietary_trading_data WITH compliance_program is APPROVED."""
        doc = _doc(
            volcker_rule_applicable=True,
            proprietary_trading_data=True,
            compliance_program_documented=True,
        )
        result = self.f.evaluate(_ctx(institution_type="bank"), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_08_volcker_applicable_no_proprietary_trading_data_approved(self):
        """Dodd-Frank §619: volcker_rule_applicable but no proprietary_trading_data is APPROVED."""
        doc = _doc(volcker_rule_applicable=True, proprietary_trading_data=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_09_swap_data_denied_before_fsoc_review(self):
        """Dodd-Frank: swap_data denial fires before FSOC review check (evaluation order)."""
        doc = _doc(
            swap_data=True,
            authorized_regulator_access=False,
            systemically_important=True,
            fsoc_oversight_documented=False,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert "§728" in result.reason

    def test_10_clean_document_approved_with_citation(self):
        """Dodd-Frank: clean document APPROVED with 12 U.S.C. §5301 citation."""
        doc = _doc()
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "§5301" in result.regulation_citation


# ---------------------------------------------------------------------------
# [11-20] SECRegulationSPFilter
# ---------------------------------------------------------------------------


class TestSECRegulationSPFilter:
    def setup_method(self):
        self.f = SECRegulationSPFilter()

    def test_11_npi_without_privacy_notice_denied(self):
        """Reg S-P §248.4: NPI without privacy_notice_delivered is DENIED."""
        doc = _doc(
            nonpublic_personal_information=True,
            privacy_notice_delivered=False,
            opt_out_opportunity=True,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§248.4" in result.regulation_citation

    def test_12_npi_with_privacy_notice_but_no_opt_out_denied(self):
        """Reg S-P §248.7: NPI with privacy notice but without opt_out_opportunity is DENIED."""
        doc = _doc(
            nonpublic_personal_information=True,
            privacy_notice_delivered=True,
            opt_out_opportunity=False,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§248.7" in result.regulation_citation

    def test_13_npi_with_both_notice_and_opt_out_approved(self):
        """Reg S-P: NPI with privacy notice AND opt-out opportunity is APPROVED."""
        doc = _doc(
            nonpublic_personal_information=True,
            privacy_notice_delivered=True,
            opt_out_opportunity=True,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_14_no_npi_approved(self):
        """Reg S-P: document without NPI flag is APPROVED."""
        doc = _doc(nonpublic_personal_information=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_15_material_cyber_incident_without_disclosure_requires_review(self):
        """Reg S-P §229.106: material_cybersecurity_incident without sec_4day_disclosure is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(
            material_cybersecurity_incident=True,
            sec_4day_disclosure_made=False,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§229.106" in result.regulation_citation

    def test_16_material_cyber_incident_with_disclosure_approved(self):
        """Reg S-P §229.106: material_cybersecurity_incident WITH sec_4day_disclosure is APPROVED."""
        doc = _doc(
            material_cybersecurity_incident=True,
            sec_4day_disclosure_made=True,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_17_npi_no_notice_denied_before_cyber_incident_review(self):
        """Reg S-P: NPI no-notice denial fires before cybersecurity incident review check."""
        doc = _doc(
            nonpublic_personal_information=True,
            privacy_notice_delivered=False,
            opt_out_opportunity=False,
            material_cybersecurity_incident=True,
            sec_4day_disclosure_made=False,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert "§248.4" in result.regulation_citation

    def test_18_clean_document_approved_with_citation(self):
        """Reg S-P: clean document APPROVED with 17 CFR Part 248 citation."""
        doc = _doc()
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "248" in result.regulation_citation

    def test_19_investment_adviser_npi_without_notice_denied(self):
        """Reg S-P applies to investment advisers: NPI without notice is DENIED regardless of institution type."""
        doc = _doc(
            nonpublic_personal_information=True,
            privacy_notice_delivered=False,
            opt_out_opportunity=True,
        )
        result = self.f.evaluate(_ctx(institution_type="investment_adviser", is_investment_adviser=True), doc)
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_20_no_cyber_incident_approved(self):
        """Reg S-P: document without cybersecurity incident flag is APPROVED."""
        doc = _doc(material_cybersecurity_incident=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [21-30] FINRAComplianceFilter
# ---------------------------------------------------------------------------


class TestFINRAComplianceFilter:
    def setup_method(self):
        self.f = FINRAComplianceFilter()

    def test_21_customer_communication_without_principal_approval_denied(self):
        """FINRA Rule 2210(b)(1): customer_communication without principal_approved is DENIED."""
        doc = _doc(customer_communication=True, principal_approved=False)
        result = self.f.evaluate(_ctx(institution_type="broker_dealer", is_broker_dealer=True), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "2210" in result.regulation_citation

    def test_22_customer_communication_with_principal_approval_approved(self):
        """FINRA Rule 2210(b)(1): customer_communication WITH principal_approved is APPROVED."""
        doc = _doc(customer_communication=True, principal_approved=True)
        result = self.f.evaluate(_ctx(is_broker_dealer=True), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_23_no_customer_communication_approved(self):
        """FINRA Rule 2210: document without customer_communication flag is APPROVED."""
        doc = _doc(customer_communication=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_24_order_data_without_supervision_requires_review(self):
        """FINRA Rule 3110: order_data without supervision_documented is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(order_data=True, supervision_documented=False)
        result = self.f.evaluate(_ctx(is_broker_dealer=True), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "3110" in result.regulation_citation

    def test_25_order_data_with_supervision_approved(self):
        """FINRA Rule 3110: order_data WITH supervision_documented is APPROVED."""
        doc = _doc(order_data=True, supervision_documented=True)
        result = self.f.evaluate(_ctx(is_broker_dealer=True), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_26_bcp_required_without_bcp_filed_denied(self):
        """FINRA Rule 4370: bcp_required without bcp_filed_with_finra is DENIED."""
        doc = _doc(bcp_required=True, bcp_filed_with_finra=False)
        result = self.f.evaluate(_ctx(is_broker_dealer=True), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "4370" in result.regulation_citation

    def test_27_bcp_required_with_bcp_filed_approved(self):
        """FINRA Rule 4370: bcp_required WITH bcp_filed_with_finra is APPROVED."""
        doc = _doc(bcp_required=True, bcp_filed_with_finra=True)
        result = self.f.evaluate(_ctx(is_broker_dealer=True), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_28_communication_denied_before_supervision_review(self):
        """FINRA: unapproved communication denial fires before supervision review check."""
        doc = _doc(
            customer_communication=True,
            principal_approved=False,
            order_data=True,
            supervision_documented=False,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert "2210" in result.regulation_citation

    def test_29_clean_document_approved_with_citation(self):
        """FINRA: clean document APPROVED with FINRA Rules citation."""
        doc = _doc()
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "4370" in result.regulation_citation or "FINRA" in result.reason

    def test_30_no_bcp_not_required_approved(self):
        """FINRA Rule 4370: bcp_required=False means no BCP check — APPROVED."""
        doc = _doc(bcp_required=False, bcp_filed_with_finra=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [31-41] FinancialServicesCrossBorderFilter
# ---------------------------------------------------------------------------


class TestFinancialServicesCrossBorderFilter:
    def setup_method(self):
        self.f = FinancialServicesCrossBorderFilter()

    def test_31_fatca_reportable_without_irs_reporting_denied(self):
        """FATCA §1471: fatca_reportable without irs_reporting_completed is DENIED."""
        doc = _doc(fatca_reportable=True, irs_reporting_completed=False)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "FATCA" in result.reason or "§1471" in result.reason

    def test_32_fatca_reportable_with_irs_reporting_approved(self):
        """FATCA §1471: fatca_reportable WITH irs_reporting_completed is APPROVED."""
        doc = _doc(fatca_reportable=True, irs_reporting_completed=True)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_33_suspicious_activity_without_sar_denied(self):
        """FinCEN §1010.320: suspicious_activity without sar_filed is DENIED."""
        doc = _doc(suspicious_activity=True, sar_filed=False)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§1010.320" in result.regulation_citation

    def test_34_suspicious_activity_with_sar_filed_approved(self):
        """FinCEN §1010.320: suspicious_activity WITH sar_filed is APPROVED."""
        doc = _doc(suspicious_activity=True, sar_filed=True)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_35_ofac_iran_denied(self):
        """OFAC: destination_country='Iran' is DENIED."""
        doc = _doc(destination_country="Iran")
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "OFAC" in result.reason or "31 CFR" in result.regulation_citation

    def test_36_ofac_russia_denied(self):
        """OFAC: destination_country='Russia' is DENIED."""
        doc = _doc(destination_country="Russia")
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_37_ofac_north_korea_denied(self):
        """OFAC: destination_country='North Korea' is DENIED."""
        doc = _doc(destination_country="North Korea")
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_38_ofac_cuba_denied(self):
        """OFAC: destination_country='Cuba' is DENIED."""
        doc = _doc(destination_country="Cuba")
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_39_ofac_syria_denied(self):
        """OFAC: destination_country='Syria' is DENIED."""
        doc = _doc(destination_country="Syria")
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_40_eu_financial_data_without_scc_requires_review(self):
        """GDPR Art. 46 + DORA: eu_financial_data without scc_executed is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(eu_financial_data=True, scc_executed=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "GDPR" in result.reason or "DORA" in result.reason

    def test_41_eu_financial_data_with_scc_approved(self):
        """GDPR Art. 46 + DORA: eu_financial_data WITH scc_executed is APPROVED."""
        doc = _doc(eu_financial_data=True, scc_executed=True)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"


# ---------------------------------------------------------------------------
# [42-46] Pipeline — filter_documents and filter_documents_with_audit
# ---------------------------------------------------------------------------


class TestFinancialServicesRAGPipeline:
    def setup_method(self):
        self.pipeline = FinancialServicesRAGPipeline()

    def test_42_clean_documents_all_pass(self):
        """Pipeline: clean documents with no regulatory flags all pass."""
        ctx = _ctx(institution_type="bank")
        docs = [_doc(doc_id=f"doc-{i}") for i in range(3)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 3

    def test_43_blocked_document_excluded(self):
        """Pipeline: document with swap_data and no regulator access is excluded."""
        ctx = _ctx()
        docs = [_doc(doc_id="blocked-swap", swap_data=True, authorized_regulator_access=False)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_44_empty_document_list_returns_empty(self):
        """Pipeline: empty document list returns empty result."""
        ctx = _ctx()
        result = self.pipeline.filter_documents(ctx, [])
        assert result == []

    def test_45_audit_record_type_and_structure(self):
        """Pipeline: filter_documents_with_audit returns FinancialServicesAuditRecord with required keys."""
        ctx = _ctx(institution_type="bank")
        docs = [_doc()]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert isinstance(record, FinancialServicesAuditRecord)
        log = record.to_audit_log()
        assert isinstance(log, dict)
        required_keys = {
            "event",
            "institution_type",
            "is_broker_dealer",
            "is_investment_adviser",
            "documents_in",
            "documents_out",
            "decisions",
            "timestamp",
        }
        assert required_keys.issubset(set(log.keys()))
        assert log["event"] == "FINANCIAL_SERVICES_RAG_RETRIEVAL"
        assert log["documents_in"] == 1

    def test_46_audit_denied_document_not_counted_in_documents_out(self):
        """Audit: DENIED document is excluded from documents_out count."""
        ctx = _ctx()
        docs = [_doc(doc_id="denied-doc", swap_data=True, authorized_regulator_access=False)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_out == 0
        assert record.documents_in == 1
        log = record.to_audit_log()
        assert log["documents_out"] == 0
        assert log["decisions"][0]["final_decision"] == "DENIED"


# ---------------------------------------------------------------------------
# [47-52] Integration and edge cases
# ---------------------------------------------------------------------------


class TestIntegrationAndEdgeCases:
    def setup_method(self):
        self.pipeline = FinancialServicesRAGPipeline()

    def test_47_context_and_document_are_frozen_dataclasses(self):
        """FinancialServicesContext and FinancialServicesDocument are frozen=True."""
        import dataclasses

        ctx = _ctx()
        assert dataclasses.is_dataclass(ctx)
        ctx_raised = False
        try:
            ctx.institution_type = "hacker"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            ctx_raised = True
        assert ctx_raised, "FinancialServicesContext must be frozen"

        doc = _doc()
        assert dataclasses.is_dataclass(doc)
        doc_raised = False
        try:
            doc.doc_id = "tampered"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            doc_raised = True
        assert doc_raised, "FinancialServicesDocument must be frozen"

    def test_48_filter_result_is_denied_semantics(self):
        """FilterResult.is_denied is True only for DENIED; False for APPROVED and REQUIRES_HUMAN_REVIEW."""
        denied = FilterResult(layer="L", decision="DENIED", reason="r", regulation_citation="c")
        approved = FilterResult(layer="L", decision="APPROVED", reason="r", regulation_citation="c")
        review = FilterResult(layer="L", decision="REQUIRES_HUMAN_REVIEW", reason="r", regulation_citation="c")
        assert denied.is_denied is True
        assert approved.is_denied is False
        assert review.is_denied is False

    def test_49_requires_human_review_document_included_in_pipeline(self):
        """Pipeline: REQUIRES_HUMAN_REVIEW (FSOC) does not exclude document."""
        ctx = _ctx()
        docs = [_doc(doc_id="fsoc-doc", systemically_important=True, fsoc_oversight_documented=False)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_50_missing_keys_default_to_approved(self):
        """Document with all defaults (no flags set) produces APPROVED pipeline result."""
        ctx = FinancialServicesContext(institution_type="general")
        docs = [FinancialServicesDocument(doc_id="default-doc")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_51_ofac_denied_before_eu_scc_review(self):
        """Pipeline evaluation order: OFAC denial fires before EU SCC review check."""
        ctx = _ctx()
        doc = _doc(
            doc_id="ofac-eu-doc",
            destination_country="Syria",
            eu_financial_data=True,
            scc_executed=False,
        )
        result = self.pipeline.filter_documents(ctx, [doc])
        assert len(result) == 0
        # Verify that the cross-border layer is the one that denies
        record = self.pipeline.filter_documents_with_audit(ctx, [doc])
        decisions = record.decisions[0]["layer_results"]
        cross_border_result = next((d for d in decisions if d["layer"] == "FINANCIAL_SERVICES_CROSS_BORDER"), None)
        assert cross_border_result is not None
        assert cross_border_result["decision"] == "DENIED"
        assert "OFAC" in cross_border_result["reason"] or "31 CFR" in cross_border_result["regulation_citation"]

    def test_52_full_stack_compliant_document_passes_all_layers(self):
        """A fully compliant document passes all four filter layers end-to-end."""
        ctx = _ctx(
            institution_type="bank",
            is_broker_dealer=False,
            is_investment_adviser=False,
            has_swap_dealer_registration=False,
        )
        doc = _doc(
            doc_id="all-pass-doc",
            data_classification="internal",
        )
        result = self.pipeline.filter_documents(ctx, [doc])
        assert len(result) == 1
