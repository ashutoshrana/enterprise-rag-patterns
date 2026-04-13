"""
Tests for 41_healthcare_ai_fda_rag.py

Covers FDASaMDFilter, ONCCuresActFilter, CMSInteroperabilityFilter,
HealthcareAICrossBorderFilter, HealthcareAIRAGPipeline, and
HealthcareAIAuditRecord.

55 tests total:
  [1-12]  FDASaMDFilter
  [13-22] ONCCuresActFilter
  [23-32] CMSInteroperabilityFilter
  [33-41] HealthcareAICrossBorderFilter
  [42-46] Pipeline — filter_documents and filter_documents_with_audit
  [47-55] Integration and edge cases
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load module via importlib
# ---------------------------------------------------------------------------

_name = "healthcare_ai_fda_rag_41"
spec = importlib.util.spec_from_file_location(
    _name,
    os.path.join(os.path.dirname(__file__), "..", "examples", "41_healthcare_ai_fda_rag.py"),
)
mod = types.ModuleType(_name)
sys.modules[_name] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
HealthcareAIContext = mod.HealthcareAIContext
HealthcareAIDocument = mod.HealthcareAIDocument
FilterResult = mod.FilterResult
FDASaMDFilter = mod.FDASaMDFilter
ONCCuresActFilter = mod.ONCCuresActFilter
CMSInteroperabilityFilter = mod.CMSInteroperabilityFilter
HealthcareAICrossBorderFilter = mod.HealthcareAICrossBorderFilter
HealthcareAIRAGPipeline = mod.HealthcareAIRAGPipeline
HealthcareAIAuditRecord = mod.HealthcareAIAuditRecord


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    institution_type: str = "hospital",
    is_cms_covered_payer: bool = False,
    has_fda_clearance: bool = False,
    hipaa_covered_entity: bool = True,
) -> object:
    return HealthcareAIContext(
        institution_type=institution_type,
        is_cms_covered_payer=is_cms_covered_payer,
        has_fda_clearance=has_fda_clearance,
        hipaa_covered_entity=hipaa_covered_entity,
    )


def _doc(
    *,
    doc_id: str = "doc-001",
    data_classification: str = "general",
    contains_phi: bool = False,
    clinical_context: list | None = None,
    # Layer 1 — FDA SaMD
    samd_class: str = "",
    fda_premarket_approval: bool = False,
    fda_510k_cleared: bool = False,
    ai_ml_samd: bool = False,
    predetermined_change_control_plan: bool = False,
    quality_management_system: bool = False,
    # Layer 2 — ONC Cures Act
    ehr_data: bool = False,
    fhir_r4_compliant: bool = False,
    information_blocking: bool = False,
    patient_data_access_request: bool = False,
    access_provided_within_timelimit: bool = False,
    ai_clinical_decision_support: bool = False,
    cds_transparency_documented: bool = False,
    # Layer 3 — CMS Interoperability
    cms_covered_payer: bool = False,
    patient_access_api_implemented: bool = False,
    prior_authorization_required: bool = False,
    ai_pa_decision: bool = False,
    human_review_available: bool = False,
    provider_directory_api: bool = False,
    medicare_advantage: bool = False,
    ai_coverage_determination: bool = False,
    clinical_criteria_documented: bool = False,
    # Layer 4 — Cross-border PHI
    phi: bool = False,
    hipaa_authorization: bool = False,
    treatment_payment_operations: bool = False,
    destination_country: str = "",
    adverse_event: bool = False,
    medwatch_report_filed: bool = False,
    eu_health_data: bool = False,
    ehds_compliant: bool = False,
) -> object:
    return HealthcareAIDocument(
        doc_id=doc_id,
        data_classification=data_classification,
        contains_phi=contains_phi,
        clinical_context=clinical_context if clinical_context is not None else [],
        samd_class=samd_class,
        fda_premarket_approval=fda_premarket_approval,
        fda_510k_cleared=fda_510k_cleared,
        ai_ml_samd=ai_ml_samd,
        predetermined_change_control_plan=predetermined_change_control_plan,
        quality_management_system=quality_management_system,
        ehr_data=ehr_data,
        fhir_r4_compliant=fhir_r4_compliant,
        information_blocking=information_blocking,
        patient_data_access_request=patient_data_access_request,
        access_provided_within_timelimit=access_provided_within_timelimit,
        ai_clinical_decision_support=ai_clinical_decision_support,
        cds_transparency_documented=cds_transparency_documented,
        cms_covered_payer=cms_covered_payer,
        patient_access_api_implemented=patient_access_api_implemented,
        prior_authorization_required=prior_authorization_required,
        ai_pa_decision=ai_pa_decision,
        human_review_available=human_review_available,
        provider_directory_api=provider_directory_api,
        medicare_advantage=medicare_advantage,
        ai_coverage_determination=ai_coverage_determination,
        clinical_criteria_documented=clinical_criteria_documented,
        phi=phi,
        hipaa_authorization=hipaa_authorization,
        treatment_payment_operations=treatment_payment_operations,
        destination_country=destination_country,
        adverse_event=adverse_event,
        medwatch_report_filed=medwatch_report_filed,
        eu_health_data=eu_health_data,
        ehds_compliant=ehds_compliant,
    )


# ---------------------------------------------------------------------------
# [1-12] FDASaMDFilter
# ---------------------------------------------------------------------------


class TestFDASaMDFilter:
    def setup_method(self):
        self.f = FDASaMDFilter()

    def test_01_class_iii_no_pma_denied(self):
        """21 CFR §814.1: Class III SaMD without FDA PMA is DENIED."""
        doc = _doc(samd_class="III", fda_premarket_approval=False, quality_management_system=True)
        result = self.f.evaluate(_ctx(institution_type="device_manufacturer"), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§814.1" in result.reason

    def test_02_class_iib_no_pma_denied(self):
        """21 CFR §814.1: Class IIb SaMD without FDA PMA is DENIED."""
        doc = _doc(samd_class="IIb", fda_premarket_approval=False, quality_management_system=True)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§814.1" in result.reason

    def test_03_class_iii_with_pma_and_qms_approved(self):
        """21 CFR §814.1: Class III SaMD with PMA AND QMS is APPROVED."""
        doc = _doc(samd_class="III", fda_premarket_approval=True, quality_management_system=True)
        result = self.f.evaluate(_ctx(has_fda_clearance=True), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_04_class_ii_no_510k_denied(self):
        """21 CFR §807.87: Class II SaMD without FDA 510(k) clearance is DENIED."""
        doc = _doc(samd_class="II", fda_510k_cleared=False, quality_management_system=True)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§807.87" in result.reason

    def test_05_class_iia_no_510k_denied(self):
        """21 CFR §807.87: Class IIa SaMD without FDA 510(k) clearance is DENIED."""
        doc = _doc(samd_class="IIa", fda_510k_cleared=False, quality_management_system=True)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§807.87" in result.reason

    def test_06_class_ii_with_510k_and_qms_approved(self):
        """21 CFR §807.87: Class II SaMD with 510(k) AND QMS is APPROVED."""
        doc = _doc(samd_class="II", fda_510k_cleared=True, quality_management_system=True)
        result = self.f.evaluate(_ctx(has_fda_clearance=True), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_07_ai_ml_samd_no_pccp_requires_review(self):
        """FDA AI/ML Action Plan: AI/ML SaMD without PCCP is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(ai_ml_samd=True, predetermined_change_control_plan=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "PCCP" in result.reason or "predetermined" in result.reason.lower()

    def test_08_ai_ml_samd_with_pccp_approved(self):
        """FDA AI/ML Action Plan: AI/ML SaMD WITH PCCP is APPROVED."""
        doc = _doc(ai_ml_samd=True, predetermined_change_control_plan=True)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_09_class_iii_no_qms_denied(self):
        """21 CFR Part 820: Class III SaMD without QMS is DENIED (after PMA check passes)."""
        doc = _doc(samd_class="III", fda_premarket_approval=True, quality_management_system=False)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "820" in result.regulation_citation

    def test_10_class_ii_no_qms_denied(self):
        """21 CFR Part 820: Class II SaMD without QMS is DENIED (after 510(k) check passes)."""
        doc = _doc(samd_class="II", fda_510k_cleared=True, quality_management_system=False)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "820" in result.regulation_citation

    def test_11_clean_document_no_samd_approved(self):
        """FDASaMDFilter: document with no SaMD class set is APPROVED."""
        doc = _doc()
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_12_pma_check_fires_before_qms_check(self):
        """Evaluation order: Class III without PMA is DENIED before QMS check."""
        doc = _doc(samd_class="III", fda_premarket_approval=False, quality_management_system=False)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert "§814.1" in result.reason


# ---------------------------------------------------------------------------
# [13-22] ONCCuresActFilter
# ---------------------------------------------------------------------------


class TestONCCuresActFilter:
    def setup_method(self):
        self.f = ONCCuresActFilter()

    def test_13_ehr_data_no_fhir_denied(self):
        """45 CFR §170.215: EHR data without FHIR R4 compliance is DENIED."""
        doc = _doc(ehr_data=True, fhir_r4_compliant=False)
        result = self.f.evaluate(_ctx(institution_type="ehr_vendor"), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§170.215" in result.regulation_citation

    def test_14_ehr_data_with_fhir_approved(self):
        """45 CFR §170.215: EHR data WITH FHIR R4 compliance is APPROVED."""
        doc = _doc(ehr_data=True, fhir_r4_compliant=True)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_15_information_blocking_denied(self):
        """45 CFR §171.103: document flagging information blocking is DENIED."""
        doc = _doc(information_blocking=True)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§171.103" in result.regulation_citation

    def test_16_no_information_blocking_approved(self):
        """45 CFR §171.103: document without information_blocking flag is APPROVED."""
        doc = _doc(information_blocking=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_17_patient_access_request_delayed_denied(self):
        """45 CFR §171.301: patient_data_access_request without timely access is DENIED."""
        doc = _doc(patient_data_access_request=True, access_provided_within_timelimit=False)
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§171.301" in result.regulation_citation

    def test_18_patient_access_request_timely_approved(self):
        """45 CFR §171.301: patient_data_access_request WITH timely access is APPROVED."""
        doc = _doc(patient_data_access_request=True, access_provided_within_timelimit=True)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_19_ai_cds_no_transparency_requires_review(self):
        """21st Century Cures Act §3060: EHR + AI CDS without transparency is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(
            ehr_data=True,
            fhir_r4_compliant=True,
            ai_clinical_decision_support=True,
            cds_transparency_documented=False,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§3060" in result.reason or "CDS" in result.reason

    def test_20_ai_cds_with_transparency_approved(self):
        """21st Century Cures Act §3060: EHR + AI CDS WITH transparency documented is APPROVED."""
        doc = _doc(
            ehr_data=True,
            fhir_r4_compliant=True,
            ai_clinical_decision_support=True,
            cds_transparency_documented=True,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_21_fhir_check_fires_before_cds_review(self):
        """ONC evaluation order: FHIR R4 denial fires before AI CDS review."""
        doc = _doc(
            ehr_data=True,
            fhir_r4_compliant=False,
            ai_clinical_decision_support=True,
            cds_transparency_documented=False,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert "§170.215" in result.regulation_citation

    def test_22_clean_document_approved_with_citation(self):
        """ONCCuresActFilter: clean document APPROVED with 45 CFR Part 170 citation."""
        doc = _doc()
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "170" in result.regulation_citation


# ---------------------------------------------------------------------------
# [23-32] CMSInteroperabilityFilter
# ---------------------------------------------------------------------------


class TestCMSInteroperabilityFilter:
    def setup_method(self):
        self.f = CMSInteroperabilityFilter()

    def test_23_cms_payer_no_patient_access_api_denied(self):
        """CMS 85 FR 25510: CMS-covered payer without Patient Access API is DENIED."""
        doc = _doc(cms_covered_payer=True, patient_access_api_implemented=False, provider_directory_api=True)
        result = self.f.evaluate(_ctx(is_cms_covered_payer=True), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "85 FR 25510" in result.regulation_citation

    def test_24_cms_payer_with_patient_access_api_proceeds(self):
        """CMS 85 FR 25510: CMS-covered payer with Patient Access API passes this check."""
        doc = _doc(cms_covered_payer=True, patient_access_api_implemented=True, provider_directory_api=True)
        result = self.f.evaluate(_ctx(is_cms_covered_payer=True), doc)
        assert not result.is_denied

    def test_25_ai_pa_no_human_review_denied(self):
        """CMS 88 FR 82510: AI-assisted prior auth without human review is DENIED."""
        doc = _doc(
            cms_covered_payer=True,
            patient_access_api_implemented=True,
            provider_directory_api=True,
            prior_authorization_required=True,
            ai_pa_decision=True,
            human_review_available=False,
        )
        result = self.f.evaluate(_ctx(is_cms_covered_payer=True), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "88 FR 82510" in result.regulation_citation

    def test_26_ai_pa_with_human_review_approved(self):
        """CMS 88 FR 82510: AI-assisted prior auth WITH human review is APPROVED."""
        doc = _doc(
            cms_covered_payer=True,
            patient_access_api_implemented=True,
            provider_directory_api=True,
            prior_authorization_required=True,
            ai_pa_decision=True,
            human_review_available=True,
        )
        result = self.f.evaluate(_ctx(is_cms_covered_payer=True), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_27_cms_payer_no_provider_directory_requires_review(self):
        """CMS 85 FR 25510: CMS-covered payer without Provider Directory API is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(
            cms_covered_payer=True,
            patient_access_api_implemented=True,
            provider_directory_api=False,
        )
        result = self.f.evaluate(_ctx(is_cms_covered_payer=True), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "Provider Directory" in result.reason

    def test_28_cms_payer_with_provider_directory_approved(self):
        """CMS 85 FR 25510: CMS-covered payer WITH Provider Directory API is APPROVED."""
        doc = _doc(
            cms_covered_payer=True,
            patient_access_api_implemented=True,
            provider_directory_api=True,
        )
        result = self.f.evaluate(_ctx(is_cms_covered_payer=True), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_29_medicare_advantage_ai_no_criteria_denied(self):
        """CMS MA AI policy: Medicare Advantage AI coverage determination without criteria is DENIED."""
        doc = _doc(
            medicare_advantage=True,
            ai_coverage_determination=True,
            clinical_criteria_documented=False,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "Medicare Advantage" in result.reason or "422.101" in result.regulation_citation

    def test_30_medicare_advantage_ai_with_criteria_approved(self):
        """CMS MA AI policy: Medicare Advantage AI coverage determination WITH criteria is APPROVED."""
        doc = _doc(
            medicare_advantage=True,
            ai_coverage_determination=True,
            clinical_criteria_documented=True,
        )
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_31_patient_access_api_check_fires_before_prior_auth(self):
        """CMS evaluation order: Patient Access API denial fires before prior auth check."""
        doc = _doc(
            cms_covered_payer=True,
            patient_access_api_implemented=False,
            provider_directory_api=True,
            prior_authorization_required=True,
            ai_pa_decision=True,
            human_review_available=False,
        )
        result = self.f.evaluate(_ctx(is_cms_covered_payer=True), doc)
        assert result.is_denied
        assert "85 FR 25510" in result.regulation_citation

    def test_32_clean_document_approved_with_citation(self):
        """CMSInteroperabilityFilter: clean document APPROVED with CMS citation."""
        doc = _doc()
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "85 FR 25510" in result.regulation_citation or "CMS" in result.reason


# ---------------------------------------------------------------------------
# [33-41] HealthcareAICrossBorderFilter
# ---------------------------------------------------------------------------


class TestHealthcareAICrossBorderFilter:
    def setup_method(self):
        self.f = HealthcareAICrossBorderFilter()

    def test_33_phi_no_auth_no_tpo_denied(self):
        """45 CFR §164.502: PHI without authorization or TPO is DENIED."""
        doc = _doc(phi=True, hipaa_authorization=False, treatment_payment_operations=False)
        result = self.f.evaluate(_ctx(institution_type="hospital"), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§164.502" in result.regulation_citation

    def test_34_phi_with_hipaa_authorization_approved(self):
        """45 CFR §164.502: PHI WITH valid HIPAA authorization is APPROVED."""
        doc = _doc(phi=True, hipaa_authorization=True, treatment_payment_operations=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_35_phi_with_tpo_approved(self):
        """45 CFR §164.502: PHI under TPO exception is APPROVED (no separate auth required)."""
        doc = _doc(phi=True, hipaa_authorization=False, treatment_payment_operations=True)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"

    def test_36_phi_to_russia_denied(self):
        """45 CFR §164.514(b): PHI transfer to Russia is DENIED."""
        doc = _doc(phi=True, hipaa_authorization=True, destination_country="Russia")
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"
        assert "§164.514" in result.regulation_citation

    def test_37_phi_to_china_denied(self):
        """45 CFR §164.514(b): PHI transfer to China is DENIED."""
        doc = _doc(phi=True, hipaa_authorization=True, destination_country="China")
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_38_phi_to_iran_denied(self):
        """45 CFR §164.514(b): PHI transfer to Iran is DENIED."""
        doc = _doc(phi=True, hipaa_authorization=True, destination_country="Iran")
        result = self.f.evaluate(_ctx(), doc)
        assert result.is_denied
        assert result.decision == "DENIED"

    def test_39_adverse_event_no_medwatch_requires_review(self):
        """21 CFR §803: adverse event without MedWatch report is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(adverse_event=True, medwatch_report_filed=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "§803" in result.regulation_citation or "MedWatch" in result.reason

    def test_40_eu_health_data_no_ehds_requires_review(self):
        """EHDS 2024: EU health data without EHDS compliance is REQUIRES_HUMAN_REVIEW."""
        doc = _doc(eu_health_data=True, ehds_compliant=False)
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "REQUIRES_HUMAN_REVIEW"
        assert "EHDS" in result.reason

    def test_41_clean_document_approved_with_citation(self):
        """HealthcareAICrossBorderFilter: clean document APPROVED with HIPAA citation."""
        doc = _doc()
        result = self.f.evaluate(_ctx(), doc)
        assert not result.is_denied
        assert result.decision == "APPROVED"
        assert "164" in result.regulation_citation


# ---------------------------------------------------------------------------
# [42-46] Pipeline — filter_documents and filter_documents_with_audit
# ---------------------------------------------------------------------------


class TestHealthcareAIRAGPipeline:
    def setup_method(self):
        self.pipeline = HealthcareAIRAGPipeline()

    def test_42_clean_documents_all_pass(self):
        """Pipeline: clean documents with no regulatory flags all pass."""
        ctx = _ctx(institution_type="hospital")
        docs = [_doc(doc_id=f"doc-{i}") for i in range(3)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 3

    def test_43_blocked_document_excluded(self):
        """Pipeline: Class III SaMD without PMA is excluded from results."""
        ctx = _ctx(institution_type="device_manufacturer")
        docs = [_doc(doc_id="blocked-samd", samd_class="III", fda_premarket_approval=False)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 0

    def test_44_empty_document_list_returns_empty(self):
        """Pipeline: empty document list returns empty result."""
        ctx = _ctx()
        result = self.pipeline.filter_documents(ctx, [])
        assert result == []

    def test_45_audit_record_type_and_structure(self):
        """Pipeline: filter_documents_with_audit returns HealthcareAIAuditRecord with required keys."""
        ctx = _ctx(institution_type="hospital")
        docs = [_doc()]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert isinstance(record, HealthcareAIAuditRecord)
        log = record.to_audit_log()
        assert isinstance(log, dict)
        required_keys = {
            "event",
            "institution_type",
            "is_cms_covered_payer",
            "hipaa_covered_entity",
            "documents_in",
            "documents_out",
            "decisions",
            "timestamp",
        }
        assert required_keys.issubset(set(log.keys()))
        assert log["event"] == "HEALTHCARE_AI_RAG_RETRIEVAL"
        assert log["documents_in"] == 1

    def test_46_audit_denied_document_not_counted_in_documents_out(self):
        """Audit: DENIED document is excluded from documents_out count."""
        ctx = _ctx(institution_type="device_manufacturer")
        docs = [_doc(doc_id="denied-doc", samd_class="III", fda_premarket_approval=False)]
        record = self.pipeline.filter_documents_with_audit(ctx, docs)
        assert record.documents_out == 0
        assert record.documents_in == 1
        log = record.to_audit_log()
        assert log["documents_out"] == 0
        assert log["decisions"][0]["final_decision"] == "DENIED"


# ---------------------------------------------------------------------------
# [47-55] Integration and edge cases
# ---------------------------------------------------------------------------


class TestIntegrationAndEdgeCases:
    def setup_method(self):
        self.pipeline = HealthcareAIRAGPipeline()

    def test_47_context_and_document_are_frozen_dataclasses(self):
        """HealthcareAIContext and HealthcareAIDocument are frozen=True."""
        import dataclasses

        ctx = _ctx()
        assert dataclasses.is_dataclass(ctx)
        ctx_raised = False
        try:
            ctx.institution_type = "hacker"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            ctx_raised = True
        assert ctx_raised, "HealthcareAIContext must be frozen"

        doc = _doc()
        assert dataclasses.is_dataclass(doc)
        doc_raised = False
        try:
            doc.doc_id = "tampered"  # type: ignore[misc]
        except (dataclasses.FrozenInstanceError, TypeError, AttributeError):
            doc_raised = True
        assert doc_raised, "HealthcareAIDocument must be frozen"

    def test_48_filter_result_is_denied_semantics(self):
        """FilterResult.is_denied is True only for DENIED; False for APPROVED and REQUIRES_HUMAN_REVIEW."""
        denied = FilterResult(layer="L", decision="DENIED", reason="r", regulation_citation="c")
        approved = FilterResult(layer="L", decision="APPROVED", reason="r", regulation_citation="c")
        review = FilterResult(layer="L", decision="REQUIRES_HUMAN_REVIEW", reason="r", regulation_citation="c")
        assert denied.is_denied is True
        assert approved.is_denied is False
        assert review.is_denied is False

    def test_49_requires_human_review_document_included_in_pipeline(self):
        """Pipeline: REQUIRES_HUMAN_REVIEW (AI/ML PCCP) does not exclude document."""
        ctx = _ctx()
        docs = [_doc(doc_id="pccp-doc", ai_ml_samd=True, predetermined_change_control_plan=False)]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_50_missing_keys_default_to_approved(self):
        """Document with all defaults (no flags set) produces APPROVED pipeline result."""
        ctx = HealthcareAIContext(institution_type="general")
        docs = [HealthcareAIDocument(doc_id="default-doc")]
        result = self.pipeline.filter_documents(ctx, docs)
        assert len(result) == 1

    def test_51_phi_denied_before_adverse_event_review(self):
        """Pipeline evaluation order: PHI denial fires before adverse event review check."""
        ctx = _ctx(institution_type="hospital")
        doc = _doc(
            doc_id="phi-adverse-doc",
            phi=True,
            hipaa_authorization=False,
            treatment_payment_operations=False,
            adverse_event=True,
            medwatch_report_filed=False,
        )
        result = self.pipeline.filter_documents(ctx, [doc])
        assert len(result) == 0
        record = self.pipeline.filter_documents_with_audit(ctx, [doc])
        decisions = record.decisions[0]["layer_results"]
        cross_border = next((d for d in decisions if d["layer"] == "HEALTHCARE_AI_CROSS_BORDER"), None)
        assert cross_border is not None
        assert cross_border["decision"] == "DENIED"
        assert "§164.502" in cross_border["regulation_citation"]

    def test_52_full_stack_compliant_document_passes_all_layers(self):
        """A fully compliant document passes all four filter layers end-to-end."""
        ctx = _ctx(
            institution_type="health_plan",
            is_cms_covered_payer=True,
            has_fda_clearance=True,
            hipaa_covered_entity=True,
        )
        doc = _doc(
            doc_id="all-pass-doc",
            data_classification="internal",
        )
        result = self.pipeline.filter_documents(ctx, [doc])
        assert len(result) == 1

    def test_53_phi_to_north_korea_denied(self):
        """45 CFR §164.514(b): PHI transfer to North Korea is DENIED."""
        ctx = _ctx()
        doc = _doc(phi=True, hipaa_authorization=True, destination_country="North Korea")
        result = self.pipeline.filter_documents(ctx, [doc])
        assert len(result) == 0

    def test_54_eu_health_data_requires_review_included_in_output(self):
        """Pipeline: EHDS REQUIRES_HUMAN_REVIEW does not exclude the document."""
        ctx = _ctx()
        doc = _doc(doc_id="ehds-doc", eu_health_data=True, ehds_compliant=False)
        result = self.pipeline.filter_documents(ctx, [doc])
        assert len(result) == 1

    def test_55_audit_record_layer_results_captured_correctly(self):
        """Audit: layer_results list captures all four layer names for a passing document."""
        ctx = _ctx(institution_type="hospital")
        doc = _doc(doc_id="audit-layers-doc")
        record = self.pipeline.filter_documents_with_audit(ctx, [doc])
        layer_names = [r["layer"] for r in record.decisions[0]["layer_results"]]
        assert "FDA_SAMD" in layer_names
        assert "ONC_CURES_ACT" in layer_names
        assert "CMS_INTEROPERABILITY" in layer_names
        assert "HEALTHCARE_AI_CROSS_BORDER" in layer_names
