"""
Tests for 45_pharma_clinical_trials_rag.py

Covers FDADrugDevelopmentFilter, ICHGCPFilter, EMARegulationsFilter,
PharmaCrossBorderFilter, FilterResult, and the run_pipeline helper.

56 tests total:
  [1-14]  FDADrugDevelopmentFilter    — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 7 edge
  [15-28] ICHGCPFilter               — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 7 edge
  [29-42] EMARegulationsFilter        — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 7 edge
  [43-54] PharmaCrossBorderFilter     — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [55-56] FilterResult + pipeline integration
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load the example module via importlib
# ---------------------------------------------------------------------------

_MOD_NAME = "pharma_clinical_trials_rag_45"
_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "45_pharma_clinical_trials_rag.py")

spec = importlib.util.spec_from_file_location(_MOD_NAME, _EXAMPLE_PATH)
mod = types.ModuleType(_MOD_NAME)
sys.modules[_MOD_NAME] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
FilterResult = mod.FilterResult
FDADrugDevelopmentFilter = mod.FDADrugDevelopmentFilter
ICHGCPFilter = mod.ICHGCPFilter
EMARegulationsFilter = mod.EMARegulationsFilter
PharmaCrossBorderFilter = mod.PharmaCrossBorderFilter
run_pipeline = mod.run_pipeline
ICH_MEMBER_REGIONS = mod.ICH_MEMBER_REGIONS
FDA_IMPORT_ALERT_COUNTRIES = mod.FDA_IMPORT_ALERT_COUNTRIES
NON_DEA_COMPLIANT_JURISDICTIONS = mod.NON_DEA_COMPLIANT_JURISDICTIONS


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _compliant_doc() -> dict:
    """A fully compliant pharmaceutical document that passes all four layers."""
    return {
        "doc_id": "compliant-test-001",
        # Layer 1 — FDA Drug Development
        "is_ind_application_data": True,
        "ind_part312_compliant": True,
        "is_nda_application_data": True,
        "nda_part314_compliant": True,
        "is_bla_application_data": True,
        "bla_part601_compliant": True,
        "is_drug_manufacturing_data": True,
        "cgmp_compliance_verified": True,
        # Layer 2 — ICH GCP
        "is_clinical_trial_data": True,
        "irb_iec_approval_documented": True,
        "is_informed_consent_data": True,
        "informed_consent_elements_complete": True,
        "is_clinical_investigator_data": True,
        "investigator_qualifications_confirmed": True,
        "is_serious_adverse_event_data": True,
        "sae_expedited_reporting_confirmed": True,
        # Layer 3 — EMA Regulations
        "is_eu_clinical_trial_data": True,
        "eu_ctr_authorization_confirmed": True,
        "is_pediatric_trial_data": True,
        "ema_pip_compliance_confirmed": True,
        "is_eu_marketing_authorization_application": True,
        "ema_centralized_procedure_compliant": True,
        "is_gdpr_clinical_health_data": True,
        "gdpr_art9_safeguards_documented": True,
        # Layer 4 — Cross-border
        "is_clinical_trial_data_transfer": True,
        "destination_country": "GB",
        "data_transfer_agreement_executed": True,
        "is_drug_substance_manufacturing_data": False,
        "manufacturing_country": "US",
        "is_controlled_substance_scheduling_data": False,
        "is_biosimilar_reference_product_data": True,
        "fda_ema_parallel_review_agreement_confirmed": True,
    }


# ---------------------------------------------------------------------------
# [1-14] FDADrugDevelopmentFilter
# ---------------------------------------------------------------------------


class TestFDADrugDevelopmentFilter:
    def setup_method(self):
        self.f = FDADrugDevelopmentFilter()

    # --- DENIED cases ---

    def test_01_ind_no_part312_compliance_denied(self):
        """21 CFR Part 312: IND data without ind_part312_compliant → DENIED."""
        doc = {"is_ind_application_data": True, "ind_part312_compliant": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "312" in r.regulation
        assert r.filter_name == "FDADrugDevelopmentFilter"

    def test_02_nda_no_part314_compliance_denied(self):
        """21 CFR Part 314: NDA data without nda_part314_compliant → DENIED."""
        doc = {
            "is_ind_application_data": False,
            "is_nda_application_data": True,
            "nda_part314_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "314" in r.regulation

    def test_03_bla_no_part601_compliance_denied(self):
        """21 CFR Part 601: BLA data without bla_part601_compliant → DENIED."""
        doc = {
            "is_ind_application_data": False,
            "is_nda_application_data": False,
            "is_bla_application_data": True,
            "bla_part601_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "601" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_04_drug_manufacturing_no_cgmp_requires_review(self):
        """21 CFR Parts 210/211: Drug manufacturing data without cgmp_compliance_verified → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_ind_application_data": False,
            "is_nda_application_data": False,
            "is_bla_application_data": False,
            "is_drug_manufacturing_data": True,
            "cgmp_compliance_verified": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "210" in r.regulation or "211" in r.regulation or "CGMP" in r.regulation

    # --- PERMITTED cases ---

    def test_05_fully_compliant_fda_permitted(self):
        """All FDA drug development controls satisfied → PERMITTED."""
        doc = {
            "is_ind_application_data": True,
            "ind_part312_compliant": True,
            "is_nda_application_data": True,
            "nda_part314_compliant": True,
            "is_bla_application_data": True,
            "bla_part601_compliant": True,
            "is_drug_manufacturing_data": True,
            "cgmp_compliance_verified": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_06_no_fda_flags_permitted(self):
        """Document with no FDA drug development flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_07_non_manufacturing_data_no_cgmp_check(self):
        """Without is_drug_manufacturing_data, CGMP check is skipped."""
        doc = {
            "is_drug_manufacturing_data": False,
            "cgmp_compliance_verified": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_08_ind_denial_precedes_nda_check(self):
        """IND denial fires before NDA check."""
        doc = {
            "is_ind_application_data": True,
            "ind_part312_compliant": False,
            "is_nda_application_data": True,
            "nda_part314_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "312" in r.regulation

    def test_09_nda_denial_precedes_bla_check(self):
        """NDA denial fires before BLA check."""
        doc = {
            "is_ind_application_data": False,
            "is_nda_application_data": True,
            "nda_part314_compliant": False,
            "is_bla_application_data": True,
            "bla_part601_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "314" in r.regulation

    def test_10_empty_dict_permitted(self):
        """Empty document has no FDA flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_11_filter_name_is_fda_drug_development(self):
        """filter_name field is set to FDADrugDevelopmentFilter."""
        r = self.f.filter({})
        assert r.filter_name == "FDADrugDevelopmentFilter"

    def test_12_reason_non_empty_on_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"is_ind_application_data": True, "ind_part312_compliant": False}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_13_is_denied_false_for_cgmp_review(self):
        """is_denied must be False for CGMP REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_drug_manufacturing_data": True,
            "cgmp_compliance_verified": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_14_ind_with_compliance_no_denial(self):
        """IND data with ind_part312_compliant=True does not trigger IND denial."""
        doc = {"is_ind_application_data": True, "ind_part312_compliant": True}
        r = self.f.filter(doc)
        assert r.decision != "DENIED" or "312" not in r.regulation


# ---------------------------------------------------------------------------
# [15-28] ICHGCPFilter
# ---------------------------------------------------------------------------


class TestICHGCPFilter:
    def setup_method(self):
        self.f = ICHGCPFilter()

    # --- DENIED cases ---

    def test_15_clinical_trial_no_irb_approval_denied(self):
        """ICH E6 §3.1 + 21 CFR Part 56: Clinical trial data without irb_iec_approval_documented → DENIED."""
        doc = {
            "is_clinical_trial_data": True,
            "irb_iec_approval_documented": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "E6" in r.regulation or "IRB" in r.regulation or "56" in r.regulation
        assert r.filter_name == "ICHGCPFilter"

    def test_16_informed_consent_incomplete_elements_denied(self):
        """ICH E6 §4.8.10 + 21 CFR §50.25: Informed consent without informed_consent_elements_complete → DENIED."""
        doc = {
            "is_clinical_trial_data": False,
            "is_informed_consent_data": True,
            "informed_consent_elements_complete": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "4.8" in r.regulation or "50.25" in r.regulation or "Consent" in r.regulation

    def test_17_investigator_no_qualifications_denied(self):
        """ICH E6 §4.1: Investigator data without investigator_qualifications_confirmed → DENIED."""
        doc = {
            "is_clinical_trial_data": False,
            "is_informed_consent_data": False,
            "is_clinical_investigator_data": True,
            "investigator_qualifications_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "4.1" in r.regulation or "Investigator" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_18_sae_no_expedited_reporting_requires_review(self):
        """ICH E6 §4.11.1 + 21 CFR §312.32: SAE without sae_expedited_reporting_confirmed
        → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_clinical_trial_data": False,
            "is_informed_consent_data": False,
            "is_clinical_investigator_data": False,
            "is_serious_adverse_event_data": True,
            "sae_expedited_reporting_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "SAE" in r.regulation or "4.11" in r.regulation or "312.32" in r.regulation

    # --- PERMITTED cases ---

    def test_19_fully_compliant_gcp_permitted(self):
        """All ICH GCP controls satisfied → PERMITTED."""
        doc = {
            "is_clinical_trial_data": True,
            "irb_iec_approval_documented": True,
            "is_informed_consent_data": True,
            "informed_consent_elements_complete": True,
            "is_clinical_investigator_data": True,
            "investigator_qualifications_confirmed": True,
            "is_serious_adverse_event_data": True,
            "sae_expedited_reporting_confirmed": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_20_no_gcp_flags_permitted(self):
        """Document with no ICH GCP flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_21_non_sae_data_no_reporting_check(self):
        """Without is_serious_adverse_event_data, SAE reporting check is skipped."""
        doc = {
            "is_serious_adverse_event_data": False,
            "sae_expedited_reporting_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_22_irb_denial_precedes_consent_check(self):
        """IRB/IEC denial fires before informed consent check."""
        doc = {
            "is_clinical_trial_data": True,
            "irb_iec_approval_documented": False,
            "is_informed_consent_data": True,
            "informed_consent_elements_complete": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "E6" in r.regulation or "IRB" in r.regulation or "56" in r.regulation

    def test_23_consent_denial_precedes_investigator_check(self):
        """Consent denial fires before investigator check."""
        doc = {
            "is_clinical_trial_data": False,
            "is_informed_consent_data": True,
            "informed_consent_elements_complete": False,
            "is_clinical_investigator_data": True,
            "investigator_qualifications_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "4.8" in r.regulation or "50.25" in r.regulation or "Consent" in r.regulation

    def test_24_empty_dict_permitted(self):
        """Empty document has no ICH GCP flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_25_filter_name_is_ich_gcp(self):
        """filter_name field is set to ICHGCPFilter."""
        r = self.f.filter({})
        assert r.filter_name == "ICHGCPFilter"

    def test_26_reason_non_empty_on_investigator_denial(self):
        """Investigator denial must contain a non-empty reason string."""
        doc = {
            "is_clinical_investigator_data": True,
            "investigator_qualifications_confirmed": False,
        }
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_27_sae_with_reporting_confirmed_no_review(self):
        """SAE data with sae_expedited_reporting_confirmed=True does not trigger REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_serious_adverse_event_data": True,
            "sae_expedited_reporting_confirmed": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_28_irb_approval_documented_true_no_denial(self):
        """Clinical trial data with irb_iec_approval_documented=True does not trigger IRB denial."""
        doc = {
            "is_clinical_trial_data": True,
            "irb_iec_approval_documented": True,
        }
        r = self.f.filter(doc)
        assert r.decision != "DENIED"


# ---------------------------------------------------------------------------
# [29-42] EMARegulationsFilter
# ---------------------------------------------------------------------------


class TestEMARegulationsFilter:
    def setup_method(self):
        self.f = EMARegulationsFilter()

    # --- DENIED cases ---

    def test_29_eu_clinical_trial_no_ctr_authorization_denied(self):
        """EU CTR 536/2014 Art. 5/6: EU clinical trial data without eu_ctr_authorization_confirmed → DENIED."""
        doc = {
            "is_eu_clinical_trial_data": True,
            "eu_ctr_authorization_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "536" in r.regulation or "CTR" in r.regulation or "EudraCT" in r.regulation
        assert r.filter_name == "EMARegulationsFilter"

    def test_30_pediatric_trial_no_pip_compliance_denied(self):
        """EU Pediatric Regulation 1901/2006 Art. 7: Pediatric trial without ema_pip_compliance_confirmed → DENIED."""
        doc = {
            "is_eu_clinical_trial_data": False,
            "is_pediatric_trial_data": True,
            "ema_pip_compliance_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "1901" in r.regulation or "PIP" in r.regulation or "Pediatric" in r.regulation

    def test_31_eu_maa_no_centralized_procedure_denied(self):
        """Regulation 726/2004 Art. 3: EU MAA without ema_centralized_procedure_compliant → DENIED."""
        doc = {
            "is_eu_clinical_trial_data": False,
            "is_pediatric_trial_data": False,
            "is_eu_marketing_authorization_application": True,
            "ema_centralized_procedure_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "726" in r.regulation or "Centralized" in r.regulation or "centralized" in r.regulation.lower()

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_32_gdpr_health_data_no_art9_safeguards_requires_review(self):
        """GDPR Art. 9(2)(j): GDPR clinical health data without gdpr_art9_safeguards_documented
        → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_eu_clinical_trial_data": False,
            "is_pediatric_trial_data": False,
            "is_eu_marketing_authorization_application": False,
            "is_gdpr_clinical_health_data": True,
            "gdpr_art9_safeguards_documented": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "Art. 9" in r.regulation or "GDPR" in r.regulation or "9(2)" in r.regulation

    # --- PERMITTED cases ---

    def test_33_fully_compliant_ema_permitted(self):
        """All EMA regulatory controls satisfied → PERMITTED."""
        doc = {
            "is_eu_clinical_trial_data": True,
            "eu_ctr_authorization_confirmed": True,
            "is_pediatric_trial_data": True,
            "ema_pip_compliance_confirmed": True,
            "is_eu_marketing_authorization_application": True,
            "ema_centralized_procedure_compliant": True,
            "is_gdpr_clinical_health_data": True,
            "gdpr_art9_safeguards_documented": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_34_no_ema_flags_permitted(self):
        """Document with no EMA flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_35_non_gdpr_health_data_no_art9_check(self):
        """Without is_gdpr_clinical_health_data, GDPR Art. 9 check is skipped."""
        doc = {
            "is_gdpr_clinical_health_data": False,
            "gdpr_art9_safeguards_documented": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_36_ctr_denial_precedes_pip_check(self):
        """EU CTR denial fires before pediatric PIP check."""
        doc = {
            "is_eu_clinical_trial_data": True,
            "eu_ctr_authorization_confirmed": False,
            "is_pediatric_trial_data": True,
            "ema_pip_compliance_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "536" in r.regulation or "CTR" in r.regulation or "EudraCT" in r.regulation

    def test_37_pip_denial_precedes_maa_check(self):
        """Pediatric PIP denial fires before EU MAA centralized procedure check."""
        doc = {
            "is_eu_clinical_trial_data": False,
            "is_pediatric_trial_data": True,
            "ema_pip_compliance_confirmed": False,
            "is_eu_marketing_authorization_application": True,
            "ema_centralized_procedure_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "1901" in r.regulation or "PIP" in r.regulation

    def test_38_empty_dict_permitted(self):
        """Empty document has no EMA flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_39_filter_name_is_ema_regulations(self):
        """filter_name field is set to EMARegulationsFilter."""
        r = self.f.filter({})
        assert r.filter_name == "EMARegulationsFilter"

    def test_40_reason_non_empty_on_ctr_denial(self):
        """EU CTR denial must contain a non-empty reason string."""
        doc = {
            "is_eu_clinical_trial_data": True,
            "eu_ctr_authorization_confirmed": False,
        }
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_41_gdpr_art9_confirmed_no_review(self):
        """GDPR clinical health data with gdpr_art9_safeguards_documented=True → no REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_gdpr_clinical_health_data": True,
            "gdpr_art9_safeguards_documented": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_42_eu_ctr_authorization_confirmed_no_denial(self):
        """EU clinical trial data with eu_ctr_authorization_confirmed=True does not trigger CTR denial."""
        doc = {
            "is_eu_clinical_trial_data": True,
            "eu_ctr_authorization_confirmed": True,
        }
        r = self.f.filter(doc)
        assert r.decision != "DENIED"


# ---------------------------------------------------------------------------
# [43-54] PharmaCrossBorderFilter
# ---------------------------------------------------------------------------


class TestPharmaCrossBorderFilter:
    def setup_method(self):
        self.f = PharmaCrossBorderFilter()

    # --- DENIED cases ---

    def test_43_clinical_trial_data_non_ich_no_dta_denied(self):
        """ICH E6 §5.15 + GDPR Art. 46: Clinical trial data to non-ICH country without DTA → DENIED."""
        doc = {
            "is_clinical_trial_data_transfer": True,
            "destination_country": "NG",  # Nigeria — not an ICH member
            "data_transfer_agreement_executed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "E6" in r.regulation or "GDPR" in r.regulation or "SCC" in r.regulation
        assert r.filter_name == "PharmaCrossBorderFilter"

    def test_44_drug_manufacturing_import_alert_country_no_review_denied(self):
        """FDA Import Alert 66-40/66-66 + 21 CFR §314.45: Manufacturing data from
        import-alert country without review → DENIED."""
        doc = {
            "is_clinical_trial_data_transfer": False,
            "is_drug_substance_manufacturing_data": True,
            "manufacturing_country": "PK",  # Pakistan — in FDA_IMPORT_ALERT_COUNTRIES
            "fda_import_alert_reviewed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Import Alert" in r.regulation or "314.45" in r.regulation

    def test_45_controlled_substance_non_dea_compliant_no_treaty_denied(self):
        """21 U.S.C. §812 + Single Convention: Controlled substance data to non-DEA-compliant
        jurisdiction without treaty → DENIED."""
        doc = {
            "is_clinical_trial_data_transfer": False,
            "is_drug_substance_manufacturing_data": False,
            "is_controlled_substance_scheduling_data": True,
            "destination_country": "KP",  # North Korea — in NON_DEA_COMPLIANT_JURISDICTIONS
            "international_treaty_compliance_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "812" in r.regulation or "DEA" in r.regulation or "Convention" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_46_biosimilar_reference_no_parallel_review_requires_review(self):
        """FDA-EMA Parallel Scientific Advice: Biosimilar reference data without
        fda_ema_parallel_review_agreement_confirmed → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_clinical_trial_data_transfer": False,
            "is_drug_substance_manufacturing_data": False,
            "is_controlled_substance_scheduling_data": False,
            "is_biosimilar_reference_product_data": True,
            "fda_ema_parallel_review_agreement_confirmed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "FDA-EMA" in r.regulation or "Parallel" in r.regulation or "Biosimilar" in r.regulation

    # --- PERMITTED cases ---

    def test_47_fully_compliant_cross_border_permitted(self):
        """All cross-border controls satisfied → PERMITTED."""
        doc = {
            "is_clinical_trial_data_transfer": True,
            "destination_country": "GB",  # ICH member
            "data_transfer_agreement_executed": True,
            "is_drug_substance_manufacturing_data": False,
            "is_controlled_substance_scheduling_data": False,
            "is_biosimilar_reference_product_data": True,
            "fda_ema_parallel_review_agreement_confirmed": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_48_clinical_trial_to_ich_country_no_dta_required(self):
        """Clinical trial data to ICH member country without DTA does not trigger denial."""
        doc = {
            "is_clinical_trial_data_transfer": True,
            "destination_country": "JP",  # Japan — ICH member
            "data_transfer_agreement_executed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_49_no_cross_border_flags_permitted(self):
        """Document with no cross-border flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_50_ich_transfer_denial_precedes_import_alert_check(self):
        """Non-ICH transfer denial fires before FDA import alert check."""
        doc = {
            "is_clinical_trial_data_transfer": True,
            "destination_country": "NG",
            "data_transfer_agreement_executed": False,
            "is_drug_substance_manufacturing_data": True,
            "manufacturing_country": "PK",
            "fda_import_alert_reviewed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "E6" in r.regulation or "GDPR" in r.regulation or "SCC" in r.regulation

    def test_51_empty_dict_permitted(self):
        """Empty document has no cross-border flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_52_filter_name_is_pharma_cross_border(self):
        """filter_name field is set to PharmaCrossBorderFilter."""
        r = self.f.filter({})
        assert r.filter_name == "PharmaCrossBorderFilter"

    def test_53_reason_non_empty_on_non_ich_denial(self):
        """Non-ICH denial must contain a non-empty reason string."""
        doc = {
            "is_clinical_trial_data_transfer": True,
            "destination_country": "SD",
            "data_transfer_agreement_executed": False,
        }
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_54_import_alert_review_confirmed_no_denial(self):
        """Manufacturing data from import-alert country with fda_import_alert_reviewed=True does not trigger denial."""
        doc = {
            "is_drug_substance_manufacturing_data": True,
            "manufacturing_country": "PK",
            "fda_import_alert_reviewed": True,
        }
        r = self.f.filter(doc)
        assert r.decision != "DENIED"


# ---------------------------------------------------------------------------
# [55-56] FilterResult properties + pipeline integration
# ---------------------------------------------------------------------------


class TestFilterResultAndPipeline:
    def test_55_is_denied_only_true_for_denied(self):
        """FilterResult.is_denied is True only for DENIED; False for PERMITTED and REQUIRES_HUMAN_REVIEW."""
        denied = FilterResult(
            decision="DENIED",
            regulation="21 CFR Part 312",
            reason="IND non-compliant",
            filter_name="FDADrugDevelopmentFilter",
        )
        permitted = FilterResult(
            decision="PERMITTED",
            regulation="21 CFR Part 312",
            reason="Compliant",
            filter_name="FDADrugDevelopmentFilter",
        )
        review = FilterResult(
            decision="REQUIRES_HUMAN_REVIEW",
            regulation="21 CFR Parts 210/211",
            reason="CGMP review needed",
            filter_name="FDADrugDevelopmentFilter",
        )
        assert denied.is_denied is True
        assert permitted.is_denied is False
        assert review.is_denied is False

    def test_56_pipeline_short_circuits_on_first_denial(self):
        """run_pipeline short-circuits after first DENIED — only 1 result returned for IND denial."""
        doc = {
            "is_ind_application_data": True,
            "ind_part312_compliant": False,
            # All other flags False / absent — ensures later layers would also fail
            "is_clinical_trial_data": True,
            "irb_iec_approval_documented": False,
        }
        results = run_pipeline(doc)
        assert len(results) == 1
        assert results[0].decision == "DENIED"
        assert results[0].filter_name == "FDADrugDevelopmentFilter"

    def test_57_pipeline_returns_four_results_for_compliant_doc(self):
        """run_pipeline returns all 4 results for a fully compliant document."""
        doc = _compliant_doc()
        results = run_pipeline(doc)
        assert len(results) == 4
        assert all(r.decision == "PERMITTED" for r in results)

    def test_58_pipeline_short_circuits_on_layer2_denial(self):
        """run_pipeline short-circuits after Layer 2 ICHGCPFilter DENIED — 2 results returned."""
        doc = {
            # Layer 1 passes
            "is_ind_application_data": False,
            "is_nda_application_data": False,
            "is_bla_application_data": False,
            "is_drug_manufacturing_data": False,
            # Layer 2 fails
            "is_clinical_trial_data": True,
            "irb_iec_approval_documented": False,
        }
        results = run_pipeline(doc)
        assert len(results) == 2
        assert results[0].decision == "PERMITTED"
        assert results[1].decision == "DENIED"
        assert results[1].filter_name == "ICHGCPFilter"

    def test_59_pipeline_short_circuits_on_layer3_denial(self):
        """run_pipeline short-circuits after Layer 3 EMARegulationsFilter DENIED — 3 results returned."""
        doc = {
            # Layer 1 passes
            "is_ind_application_data": False,
            "is_nda_application_data": False,
            "is_bla_application_data": False,
            "is_drug_manufacturing_data": False,
            # Layer 2 passes
            "is_clinical_trial_data": False,
            "is_informed_consent_data": False,
            "is_clinical_investigator_data": False,
            "is_serious_adverse_event_data": False,
            # Layer 3 fails
            "is_eu_clinical_trial_data": True,
            "eu_ctr_authorization_confirmed": False,
        }
        results = run_pipeline(doc)
        assert len(results) == 3
        assert results[2].decision == "DENIED"
        assert results[2].filter_name == "EMARegulationsFilter"

    def test_60_all_filter_names_set_in_pipeline(self):
        """Each result from a full pipeline run has its filter_name set correctly."""
        doc = _compliant_doc()
        results = run_pipeline(doc)
        filter_names = [r.filter_name for r in results]
        assert "FDADrugDevelopmentFilter" in filter_names
        assert "ICHGCPFilter" in filter_names
        assert "EMARegulationsFilter" in filter_names
        assert "PharmaCrossBorderFilter" in filter_names

    def test_61_ich_member_regions_constant_non_empty(self):
        """ICH_MEMBER_REGIONS frozenset is non-empty and contains expected members."""
        assert len(ICH_MEMBER_REGIONS) > 0
        assert "US" in ICH_MEMBER_REGIONS
        assert "EU" in ICH_MEMBER_REGIONS
        assert "JP" in ICH_MEMBER_REGIONS

    def test_62_non_dea_compliant_jurisdictions_non_empty(self):
        """NON_DEA_COMPLIANT_JURISDICTIONS frozenset is non-empty."""
        assert len(NON_DEA_COMPLIANT_JURISDICTIONS) > 0
        assert "KP" in NON_DEA_COMPLIANT_JURISDICTIONS

    def test_63_fda_import_alert_countries_non_empty(self):
        """FDA_IMPORT_ALERT_COUNTRIES frozenset is non-empty and contains expected entries."""
        assert len(FDA_IMPORT_ALERT_COUNTRIES) > 0
        assert "PK" in FDA_IMPORT_ALERT_COUNTRIES

    def test_64_pipeline_requires_human_review_does_not_short_circuit(self):
        """REQUIRES_HUMAN_REVIEW does not short-circuit pipeline — pipeline continues to Layer 2+."""
        doc = {
            # Layer 1: CGMP REQUIRES_HUMAN_REVIEW but does not stop pipeline
            "is_ind_application_data": False,
            "is_nda_application_data": False,
            "is_bla_application_data": False,
            "is_drug_manufacturing_data": True,
            "cgmp_compliance_verified": False,
            # Layer 2: passes
            "is_clinical_trial_data": False,
            "is_informed_consent_data": False,
            "is_clinical_investigator_data": False,
            "is_serious_adverse_event_data": False,
            # Layer 3: passes
            "is_eu_clinical_trial_data": False,
            "is_pediatric_trial_data": False,
            "is_eu_marketing_authorization_application": False,
            "is_gdpr_clinical_health_data": False,
            # Layer 4: passes
            "is_clinical_trial_data_transfer": False,
            "is_drug_substance_manufacturing_data": False,
            "is_controlled_substance_scheduling_data": False,
            "is_biosimilar_reference_product_data": False,
        }
        results = run_pipeline(doc)
        assert len(results) == 4
        assert results[0].decision == "REQUIRES_HUMAN_REVIEW"
        assert results[1].decision == "PERMITTED"
        assert results[2].decision == "PERMITTED"
        assert results[3].decision == "PERMITTED"
