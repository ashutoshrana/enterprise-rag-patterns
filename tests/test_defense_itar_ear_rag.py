"""
Tests for 44_defense_itar_ear_rag.py

Covers ITARFilter, EARFilter, CFIUSDefenseFilter, DefenseCrossBorderFilter,
FilterResult, and the run_pipeline helper.

56 tests total:
  [1-13]  ITARFilter              — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [14-26] EARFilter               — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [27-39] CFIUSDefenseFilter      — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [40-52] DefenseCrossBorderFilter — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [53-56] FilterResult + pipeline integration
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load the example module via importlib
# ---------------------------------------------------------------------------

_MOD_NAME = "defense_itar_ear_rag_44"
_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "44_defense_itar_ear_rag.py")

spec = importlib.util.spec_from_file_location(_MOD_NAME, _EXAMPLE_PATH)
mod = types.ModuleType(_MOD_NAME)
sys.modules[_MOD_NAME] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
FilterResult = mod.FilterResult
ITARFilter = mod.ITARFilter
EARFilter = mod.EARFilter
CFIUSDefenseFilter = mod.CFIUSDefenseFilter
DefenseCrossBorderFilter = mod.DefenseCrossBorderFilter
run_pipeline = mod.run_pipeline
MEU_COUNTRIES = mod.MEU_COUNTRIES
SEMICONDUCTOR_CONTROL_COUNTRIES = mod.SEMICONDUCTOR_CONTROL_COUNTRIES
CFIUS_COVERED_NATIONS = mod.CFIUS_COVERED_NATIONS
DEFENSE_ADVERSARIAL_NATIONS = mod.DEFENSE_ADVERSARIAL_NATIONS
FVEY_MEMBERS = mod.FVEY_MEMBERS


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _compliant_doc() -> dict:
    """A fully compliant defense document that passes all four layers."""
    return {
        "doc_id": "compliant-test-001",
        # Layer 1 — ITAR
        "is_usml_technical_data": True,
        "itar_export_license": True,
        "is_defense_service_to_foreign_person": True,
        "dsp5_authorization": True,
        "is_controlled_electronic_transmission": True,
        "itar_exemption_applies": True,
        "is_classified_defense_data": True,
        "proper_classification_markings": True,
        # Layer 2 — EAR
        "is_ccl_military_end_use_item": True,
        "destination_country": "GB",
        "bis_meu_license": True,
        "is_entity_list_recipient": False,
        "is_advanced_computing_semiconductor_item": False,
        "is_huawei_fdpr_subject": False,
        # Layer 3 — CFIUS
        "is_defense_contractor_acquisition": False,
        "investor_country": "GB",
        "is_tid_us_business_transaction": False,
        "is_sensitive_gov_contract_data_access": False,
        "is_tid_minority_investment": False,
        # Layer 4 — Cross-border
        "recipient_country": "GB",
        "is_nato_classified_information": False,
        "is_fvey_intelligence_data": False,
        "is_defense_industrial_base_data": False,
        "is_joint_military_technology_development": False,
    }


# ---------------------------------------------------------------------------
# [1-13] ITARFilter
# ---------------------------------------------------------------------------


class TestITARFilter:
    def setup_method(self):
        self.f = ITARFilter()

    # --- DENIED cases ---

    def test_01_usml_technical_data_no_license_denied(self):
        """§120.6 USML + §120.10: USML technical data without itar_export_license → DENIED."""
        doc = {"is_usml_technical_data": True, "itar_export_license": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§120.6" in r.regulation
        assert r.filter_name == "ITARFilter"

    def test_02_defense_service_foreign_no_dsp5_denied(self):
        """§120.9 + §123.1: Defense service to foreign person without dsp5_authorization → DENIED."""
        doc = {
            "is_usml_technical_data": False,
            "is_defense_service_to_foreign_person": True,
            "dsp5_authorization": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "DSP-5" in r.regulation

    def test_03_controlled_electronic_transmission_no_exemption_denied(self):
        """§125.4: Controlled electronic transmission to foreign without exemption → DENIED."""
        doc = {
            "is_usml_technical_data": False,
            "is_defense_service_to_foreign_person": False,
            "is_controlled_electronic_transmission": True,
            "itar_exemption_applies": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§125.4" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_04_classified_defense_no_markings_requires_review(self):
        """§120.11 + DoD 5220.22-M: Classified data without proper_classification_markings → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_usml_technical_data": False,
            "is_defense_service_to_foreign_person": False,
            "is_controlled_electronic_transmission": False,
            "is_classified_defense_data": True,
            "proper_classification_markings": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "5220.22-M" in r.regulation

    # --- PERMITTED cases ---

    def test_05_fully_compliant_itar_permitted(self):
        """All ITAR controls satisfied → PERMITTED."""
        doc = {
            "is_usml_technical_data": True,
            "itar_export_license": True,
            "is_defense_service_to_foreign_person": True,
            "dsp5_authorization": True,
            "is_controlled_electronic_transmission": True,
            "itar_exemption_applies": True,
            "is_classified_defense_data": True,
            "proper_classification_markings": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_06_non_itar_document_permitted(self):
        """Document with no ITAR flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_07_no_classified_flag_no_nispom_check(self):
        """Without is_classified_defense_data, NISPOM check is skipped."""
        doc = {
            "is_classified_defense_data": False,
            "proper_classification_markings": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_08_usml_denial_precedes_dsp5_check(self):
        """USML denial fires before defense services check."""
        doc = {
            "is_usml_technical_data": True,
            "itar_export_license": False,
            "is_defense_service_to_foreign_person": True,
            "dsp5_authorization": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "§120.6" in r.regulation

    def test_09_empty_dict_permitted(self):
        """Empty document has no ITAR flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_10_filter_name_is_itar(self):
        """filter_name field is set to ITARFilter."""
        r = self.f.filter({})
        assert r.filter_name == "ITARFilter"

    def test_11_reason_non_empty_on_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"is_usml_technical_data": True, "itar_export_license": False}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_12_is_denied_false_for_review(self):
        """is_denied must be False for REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_classified_defense_data": True,
            "proper_classification_markings": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_13_usml_with_license_no_denial(self):
        """USML technical data with itar_export_license=True does not trigger USML denial."""
        doc = {"is_usml_technical_data": True, "itar_export_license": True}
        r = self.f.filter(doc)
        assert r.decision != "DENIED" or "§120.6" not in r.regulation


# ---------------------------------------------------------------------------
# [14-26] EARFilter
# ---------------------------------------------------------------------------


class TestEARFilter:
    def setup_method(self):
        self.f = EARFilter()

    # --- DENIED cases ---

    def test_14_ccl_meu_china_no_bis_license_denied(self):
        """§744.21: CCL MEU item to China (MEU country) without bis_meu_license → DENIED."""
        doc = {
            "is_ccl_military_end_use_item": True,
            "destination_country": "CN",
            "bis_meu_license": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§744.21" in r.regulation
        assert r.filter_name == "EARFilter"

    def test_15_entity_list_recipient_no_authorization_denied(self):
        """§744.11: Entity List recipient without bis_entity_list_authorization → DENIED."""
        doc = {
            "is_ccl_military_end_use_item": False,
            "is_entity_list_recipient": True,
            "bis_entity_list_authorization": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§744.11" in r.regulation

    def test_16_semiconductor_item_china_no_license_denied(self):
        """§744.23: Advanced computing/semiconductor item to China without bis_semiconductor_license → DENIED."""
        doc = {
            "is_ccl_military_end_use_item": False,
            "is_entity_list_recipient": False,
            "is_advanced_computing_semiconductor_item": True,
            "destination_country": "CN",
            "bis_semiconductor_license": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§744.23" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_17_huawei_fdpr_no_review_requires_review(self):
        """§734.9 FDPR: Huawei FDPR subject without huawei_fdpr_compliance_reviewed → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_ccl_military_end_use_item": False,
            "is_entity_list_recipient": False,
            "is_advanced_computing_semiconductor_item": False,
            "is_huawei_fdpr_subject": True,
            "huawei_fdpr_compliance_reviewed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "FDPR" in r.regulation

    # --- PERMITTED cases ---

    def test_18_fully_compliant_ear_permitted(self):
        """All EAR controls satisfied → PERMITTED."""
        doc = {
            "is_ccl_military_end_use_item": True,
            "destination_country": "GB",
            "bis_meu_license": True,
            "is_entity_list_recipient": False,
            "is_advanced_computing_semiconductor_item": False,
            "is_huawei_fdpr_subject": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_19_non_meu_destination_no_meu_control(self):
        """CCL item to non-MEU country (GB) does not trigger MEU denial."""
        doc = {
            "is_ccl_military_end_use_item": True,
            "destination_country": "GB",
            "bis_meu_license": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_20_no_ear_flags_permitted(self):
        """Document with no EAR-relevant flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_21_all_meu_countries_produce_denial(self):
        """All MEU countries (CN/RU/VE/MM/BY) trigger denial for unlicensed CCL MEU items."""
        for country in ("CN", "RU", "VE", "MM", "BY"):
            r = self.f.filter(
                {
                    "is_ccl_military_end_use_item": True,
                    "destination_country": country,
                    "bis_meu_license": False,
                }
            )
            assert r.decision == "DENIED", f"Expected DENIED for MEU country {country}"
            assert r.is_denied

    def test_22_semiconductor_item_north_korea_denied(self):
        """§744.23: Semiconductor item to North Korea (KP) without license → DENIED."""
        doc = {
            "is_advanced_computing_semiconductor_item": True,
            "destination_country": "KP",
            "bis_semiconductor_license": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "§744.23" in r.regulation

    def test_23_meu_denial_precedes_entity_list_check(self):
        """MEU denial fires before Entity List check when both conditions met."""
        doc = {
            "is_ccl_military_end_use_item": True,
            "destination_country": "CN",
            "bis_meu_license": False,
            "is_entity_list_recipient": True,
            "bis_entity_list_authorization": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "§744.21" in r.regulation

    def test_24_filter_name_is_ear(self):
        r = self.f.filter({})
        assert r.filter_name == "EARFilter"

    def test_25_is_denied_false_for_huawei_fdpr_review(self):
        doc = {
            "is_huawei_fdpr_subject": True,
            "huawei_fdpr_compliance_reviewed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_26_reason_non_empty_on_entity_list_denial(self):
        doc = {"is_entity_list_recipient": True, "bis_entity_list_authorization": False}
        r = self.f.filter(doc)
        assert r.reason


# ---------------------------------------------------------------------------
# [27-39] CFIUSDefenseFilter
# ---------------------------------------------------------------------------


class TestCFIUSDefenseFilter:
    def setup_method(self):
        self.f = CFIUSDefenseFilter()

    # --- DENIED cases ---

    def test_27_defense_contractor_acquisition_no_cfius_filing_denied(self):
        """§4565 + Part 800: Defense contractor acquisition without cfius_filing_complete → DENIED."""
        doc = {"is_defense_contractor_acquisition": True, "cfius_filing_complete": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§4565" in r.regulation
        assert r.filter_name == "CFIUSDefenseFilter"

    def test_28_tid_business_china_no_clearance_denied(self):
        """§800.248 TID + §800.212: TID US Business transaction with China without cfius_tid_clearance → DENIED."""
        doc = {
            "is_defense_contractor_acquisition": False,
            "is_tid_us_business_transaction": True,
            "investor_country": "CN",
            "cfius_tid_clearance": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§800.248" in r.regulation

    def test_29_sensitive_gov_contract_access_no_clearance_denied(self):
        """FIRRMA + §800.215: Foreign access to sensitive gov contract data without clearance → DENIED."""
        doc = {
            "is_defense_contractor_acquisition": False,
            "is_tid_us_business_transaction": False,
            "is_sensitive_gov_contract_data_access": True,
            "cfius_gov_contract_clearance": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§800.215" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_30_tid_minority_investment_russia_no_declaration_requires_review(self):
        """§800.401: Minority TID investment by Russia without mandatory declaration → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_defense_contractor_acquisition": False,
            "is_tid_us_business_transaction": False,
            "is_sensitive_gov_contract_data_access": False,
            "is_tid_minority_investment": True,
            "investor_country": "RU",
            "cfius_mandatory_declaration_filed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "§800.401" in r.regulation

    # --- PERMITTED cases ---

    def test_31_defense_acquisition_with_cfius_filing_permitted(self):
        """Defense contractor acquisition with cfius_filing_complete=True → PERMITTED."""
        doc = {
            "is_defense_contractor_acquisition": True,
            "cfius_filing_complete": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_32_non_cfius_document_permitted(self):
        """Document with no CFIUS-relevant flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_33_tid_transaction_non_covered_nation_permitted(self):
        """TID US Business transaction with non-covered nation (GB) does not trigger §800.248 denial."""
        doc = {
            "is_tid_us_business_transaction": True,
            "investor_country": "GB",
            "cfius_tid_clearance": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_34_all_cfius_covered_nations_denied_for_tid_transaction(self):
        """All CFIUS covered nations (CN/RU/KP) trigger denial for uncleaned TID transactions."""
        for country in ("CN", "RU", "KP"):
            r = self.f.filter(
                {
                    "is_tid_us_business_transaction": True,
                    "investor_country": country,
                    "cfius_tid_clearance": False,
                }
            )
            assert r.decision == "DENIED", f"Expected DENIED for CFIUS covered nation {country}"
            assert r.is_denied

    def test_35_acquisition_denial_precedes_tid_check(self):
        """Defense contractor acquisition denial fires before TID check."""
        doc = {
            "is_defense_contractor_acquisition": True,
            "cfius_filing_complete": False,
            "is_tid_us_business_transaction": True,
            "investor_country": "CN",
            "cfius_tid_clearance": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "§4565" in r.regulation

    def test_36_filter_name_is_cfius(self):
        r = self.f.filter({})
        assert r.filter_name == "CFIUSDefenseFilter"

    def test_37_is_denied_false_for_mandatory_declaration_review(self):
        doc = {
            "is_tid_minority_investment": True,
            "investor_country": "KP",
            "cfius_mandatory_declaration_filed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_38_reason_non_empty_on_gov_contract_denial(self):
        doc = {
            "is_sensitive_gov_contract_data_access": True,
            "cfius_gov_contract_clearance": False,
        }
        r = self.f.filter(doc)
        assert r.reason

    def test_39_tid_with_cfius_clearance_not_denied(self):
        """TID US Business transaction with CN but cfius_tid_clearance=True is not denied."""
        doc = {
            "is_tid_us_business_transaction": True,
            "investor_country": "CN",
            "cfius_tid_clearance": True,
        }
        r = self.f.filter(doc)
        assert r.decision != "DENIED" or "§800.248" not in r.regulation


# ---------------------------------------------------------------------------
# [40-52] DefenseCrossBorderFilter
# ---------------------------------------------------------------------------


class TestDefenseCrossBorderFilter:
    def setup_method(self):
        self.f = DefenseCrossBorderFilter()

    # --- DENIED cases ---

    def test_40_nato_classified_no_clearance_denied(self):
        """NATO MC 0049/15: NATO-classified information without nato_clearance_and_need_to_know → DENIED."""
        doc = {"is_nato_classified_information": True, "nato_clearance_and_need_to_know": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "MC 0049/15" in r.regulation
        assert r.filter_name == "DefenseCrossBorderFilter"

    def test_41_fvey_intelligence_non_fvey_no_bilateral_denied(self):
        """UKUSA/FVEY: FVEY intelligence data to non-FVEY partner without bilateral agreement → DENIED."""
        doc = {
            "is_nato_classified_information": False,
            "is_fvey_intelligence_data": True,
            "recipient_country": "DE",
            "bilateral_intelligence_agreement": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "FVEY" in r.regulation

    def test_42_defense_industrial_data_to_iran_denied(self):
        """NSPM-33 + EO 13873: Defense industrial base data to Iran (adversarial nation) → DENIED."""
        doc = {
            "is_nato_classified_information": False,
            "is_fvey_intelligence_data": False,
            "is_defense_industrial_base_data": True,
            "recipient_country": "IR",
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "NSPM-33" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_43_joint_military_tech_dev_no_dod_disclosure_requires_review(self):
        """DoDD 5230.11: Joint military tech dev without dod_foreign_disclosure_approval → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_nato_classified_information": False,
            "is_fvey_intelligence_data": False,
            "is_defense_industrial_base_data": False,
            "is_joint_military_technology_development": True,
            "dod_foreign_disclosure_approval": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "5230.11" in r.regulation

    # --- PERMITTED cases ---

    def test_44_fvey_intelligence_to_fvey_member_permitted(self):
        """FVEY intelligence data to FVEY member (GB) → PERMITTED (UKUSA Agreement n/a)."""
        doc = {
            "is_fvey_intelligence_data": True,
            "recipient_country": "GB",
            "bilateral_intelligence_agreement": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_45_defense_data_to_non_adversarial_nation_permitted(self):
        """Defense industrial base data to non-adversarial nation (JP) → PERMITTED."""
        doc = {
            "is_defense_industrial_base_data": True,
            "recipient_country": "JP",
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_46_joint_military_dev_with_approval_permitted(self):
        """Joint military technology development with dod_foreign_disclosure_approval=True → PERMITTED."""
        doc = {
            "is_joint_military_technology_development": True,
            "dod_foreign_disclosure_approval": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_47_all_defense_adversarial_nations_denied(self):
        """All adversarial nations (CN/RU/KP/IR/CU/SY) trigger denial for defense industrial data."""
        for country in ("CN", "RU", "KP", "IR", "CU", "SY"):
            r = self.f.filter(
                {
                    "is_defense_industrial_base_data": True,
                    "recipient_country": country,
                }
            )
            assert r.decision == "DENIED", f"Expected DENIED for adversarial nation {country}"
            assert r.is_denied

    def test_48_all_fvey_members_permitted_for_fvey_intelligence(self):
        """All FVEY members (US/GB/CA/AU/NZ) are permitted to receive FVEY intelligence."""
        for country in ("US", "GB", "CA", "AU", "NZ"):
            r = self.f.filter(
                {
                    "is_fvey_intelligence_data": True,
                    "recipient_country": country,
                }
            )
            assert r.decision == "PERMITTED", f"Expected PERMITTED for FVEY member {country}"

    def test_49_nato_denial_precedes_fvey_check(self):
        """NATO classified denial fires before FVEY check."""
        doc = {
            "is_nato_classified_information": True,
            "nato_clearance_and_need_to_know": False,
            "is_fvey_intelligence_data": True,
            "recipient_country": "DE",
            "bilateral_intelligence_agreement": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "MC 0049/15" in r.regulation

    def test_50_filter_name_is_defense_cross_border(self):
        r = self.f.filter({})
        assert r.filter_name == "DefenseCrossBorderFilter"

    def test_51_empty_dict_permitted(self):
        """Empty document has no cross-border flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_52_is_denied_false_for_joint_dev_review(self):
        doc = {
            "is_joint_military_technology_development": True,
            "dod_foreign_disclosure_approval": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied


# ---------------------------------------------------------------------------
# [53-56] FilterResult correctness + cross-filter pipeline integration
# ---------------------------------------------------------------------------


class TestFilterResultAndPipeline:
    def test_53_is_denied_only_for_denied_decision(self):
        """is_denied must be True for DENIED and False for all other decisions."""
        for decision, expected in (
            ("DENIED", True),
            ("PERMITTED", False),
            ("REQUIRES_HUMAN_REVIEW", False),
            ("REDACTED", False),
        ):
            r = FilterResult(
                decision=decision,
                regulation="TEST",
                reason="test reason",
                filter_name="TestFilter",
            )
            assert r.is_denied is expected, f"is_denied wrong for decision={decision!r}"

    def test_54_compliant_doc_passes_all_four_layers(self):
        """A fully compliant document must pass all four filters with PERMITTED."""
        doc = _compliant_doc()
        results = run_pipeline(doc)
        assert len(results) == 4
        for r in results:
            assert r.decision == "PERMITTED", f"Expected PERMITTED from {r.filter_name}, got {r.decision}: {r.reason}"
            assert not r.is_denied

    def test_55_pipeline_short_circuits_on_itar_denial(self):
        """Pipeline stops after first DENIED (ITAR layer) and returns only one result."""
        doc = {
            "is_usml_technical_data": True,
            "itar_export_license": False,
            # EAR would also trigger but we should never reach it
            "is_entity_list_recipient": True,
            "bis_entity_list_authorization": False,
        }
        results = run_pipeline(doc)
        assert len(results) == 1
        assert results[0].decision == "DENIED"
        assert results[0].filter_name == "ITARFilter"

    def test_56_constants_correct_membership(self):
        """Verify set constants contain the documented countries."""
        assert "CN" in MEU_COUNTRIES
        assert "RU" in MEU_COUNTRIES
        assert "BY" in MEU_COUNTRIES
        assert "CN" in SEMICONDUCTOR_CONTROL_COUNTRIES
        assert "KP" in SEMICONDUCTOR_CONTROL_COUNTRIES
        assert "CN" in CFIUS_COVERED_NATIONS
        assert "CN" in DEFENSE_ADVERSARIAL_NATIONS
        assert "SY" in DEFENSE_ADVERSARIAL_NATIONS
        assert "CU" in DEFENSE_ADVERSARIAL_NATIONS
        assert "US" in FVEY_MEMBERS
        assert "AU" in FVEY_MEMBERS
        # Non-members should not be present
        assert "DE" not in FVEY_MEMBERS
        assert "JP" not in DEFENSE_ADVERSARIAL_NATIONS
