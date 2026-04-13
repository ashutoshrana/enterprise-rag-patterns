"""
Tests for 43_energy_nerc_cip_rag.py

Covers NERCCIPFilter, FERCEnergyFilter, DOECybersecurityFilter,
EnergyCrossBorderFilter, FilterResult, and the run_pipeline helper.

54 tests total:
  [1-13]  NERCCIPFilter          — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [14-26] FERCEnergyFilter       — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [27-39] DOECybersecurityFilter — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [40-52] EnergyCrossBorderFilter — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [53-54] FilterResult + pipeline integration
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load the example module via importlib
# ---------------------------------------------------------------------------

_MOD_NAME = "energy_nerc_cip_rag_43"
_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "43_energy_nerc_cip_rag.py")

spec = importlib.util.spec_from_file_location(_MOD_NAME, _EXAMPLE_PATH)
mod = types.ModuleType(_MOD_NAME)
sys.modules[_MOD_NAME] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
FilterResult = mod.FilterResult
NERCCIPFilter = mod.NERCCIPFilter
FERCEnergyFilter = mod.FERCEnergyFilter
DOECybersecurityFilter = mod.DOECybersecurityFilter
EnergyCrossBorderFilter = mod.EnergyCrossBorderFilter
run_pipeline = mod.run_pipeline
ENERGY_ADVERSARIAL_NATIONS = mod.ENERGY_ADVERSARIAL_NATIONS
NAFTA_MEMBERS = mod.NAFTA_MEMBERS


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _compliant_doc() -> dict:
    """A fully compliant energy / NERC CIP document that passes all four layers."""
    return {
        "doc_id": "compliant-test-001",
        # Layer 1 — NERC CIP
        "is_bes_cyber_system": True,
        "cip_007_6_compliant": True,
        "is_electronic_security_perimeter": True,
        "cip_005_7_compliant": True,
        "has_physical_security_plan": True,
        "cip_006_6_compliant": True,
        "has_incident_response_plan": True,
        "cip_008_6_eisac_reporting": True,
        # Layer 2 — FERC
        "is_energy_trading_data": True,
        "oasis_compliant": True,
        "is_market_activity": True,
        "anti_manipulation_safeguards": True,
        "is_interstate_gas_pipeline": True,
        "ferc_gas_tariff_compliant": True,
        "is_hydropower_facility": True,
        "ferc_part12_dam_safety_current": True,
        # Layer 3 — DOE/CISA
        "is_energy_ot_system": True,
        "doe_100day_plan_controls": True,
        "is_energy_ics": True,
        "ics_cert_baseline_controls": True,
        "is_energy_ai_ml_system": True,
        "nist_ai_rmf_energy_profile": True,
        "is_grid_modernisation_data": True,
        "doe_ceser_threat_sharing": True,
        # Layer 4 — Cross-border
        "destination_country": "GB",
        "is_ferc_electricity_export": False,
        "is_critical_energy_infrastructure_data": False,
        "is_lng_export_terminal_data": False,
        "is_eu_energy_data": False,
    }


# ---------------------------------------------------------------------------
# [1-13] NERCCIPFilter
# ---------------------------------------------------------------------------


class TestNERCCIPFilter:
    def setup_method(self):
        self.f = NERCCIPFilter()

    # --- DENIED cases ---

    def test_01_bes_cyber_no_cip007_denied(self):
        """CIP-007-6: BES Cyber System without cip_007_6_compliant → DENIED."""
        doc = {"is_bes_cyber_system": True, "cip_007_6_compliant": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "CIP-007-6" in r.regulation
        assert r.filter_name == "NERCCIPFilter"

    def test_02_esp_no_cip005_denied(self):
        """CIP-005-7: Electronic Security Perimeter without cip_005_7_compliant → DENIED."""
        doc = {
            "is_bes_cyber_system": False,
            "is_electronic_security_perimeter": True,
            "cip_005_7_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "CIP-005-7" in r.regulation

    def test_03_physical_plan_no_cip006_denied(self):
        """CIP-006-6: Physical Security Plan without cip_006_6_compliant → DENIED."""
        doc = {
            "is_bes_cyber_system": False,
            "is_electronic_security_perimeter": False,
            "has_physical_security_plan": True,
            "cip_006_6_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "CIP-006-6" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_04_irp_no_eisac_reporting_requires_review(self):
        """CIP-008-6: Incident Response Plan without cip_008_6_eisac_reporting → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_bes_cyber_system": False,
            "is_electronic_security_perimeter": False,
            "has_physical_security_plan": False,
            "has_incident_response_plan": True,
            "cip_008_6_eisac_reporting": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "CIP-008-6" in r.regulation

    # --- PERMITTED cases ---

    def test_05_fully_compliant_nerc_permitted(self):
        """All NERC CIP controls satisfied → PERMITTED."""
        doc = {
            "is_bes_cyber_system": True,
            "cip_007_6_compliant": True,
            "is_electronic_security_perimeter": True,
            "cip_005_7_compliant": True,
            "has_physical_security_plan": True,
            "cip_006_6_compliant": True,
            "has_incident_response_plan": True,
            "cip_008_6_eisac_reporting": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_06_non_bes_document_permitted(self):
        """Document with no BES/CIP flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_07_no_irp_flag_no_cip008_check(self):
        """Without has_incident_response_plan, CIP-008-6 check is skipped."""
        doc = {"has_incident_response_plan": False, "cip_008_6_eisac_reporting": False}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_08_cip007_denial_precedes_cip005_check(self):
        """CIP-007-6 denial fires before CIP-005-7 check."""
        doc = {
            "is_bes_cyber_system": True,
            "cip_007_6_compliant": False,
            "is_electronic_security_perimeter": True,
            "cip_005_7_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "CIP-007-6" in r.regulation

    def test_09_empty_dict_permitted(self):
        """Empty document has no NERC CIP flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_10_filter_name_is_nerc_cip(self):
        """filter_name field is set to NERCCIPFilter."""
        r = self.f.filter({})
        assert r.filter_name == "NERCCIPFilter"

    def test_11_reason_non_empty_on_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"is_bes_cyber_system": True, "cip_007_6_compliant": False}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_12_is_denied_false_for_review(self):
        """is_denied must be False for REQUIRES_HUMAN_REVIEW."""
        doc = {
            "has_incident_response_plan": True,
            "cip_008_6_eisac_reporting": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_13_bes_cyber_compliant_no_denial(self):
        """BES Cyber System with cip_007_6_compliant=True does not trigger CIP-007-6 denial."""
        doc = {"is_bes_cyber_system": True, "cip_007_6_compliant": True}
        r = self.f.filter(doc)
        assert r.decision != "DENIED" or "CIP-007-6" not in r.regulation


# ---------------------------------------------------------------------------
# [14-26] FERCEnergyFilter
# ---------------------------------------------------------------------------


class TestFERCEnergyFilter:
    def setup_method(self):
        self.f = FERCEnergyFilter()

    # --- DENIED cases ---

    def test_14_energy_trading_no_oasis_denied(self):
        """Order 888/889: Energy trading without oasis_compliant → DENIED."""
        doc = {"is_energy_trading_data": True, "oasis_compliant": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "OASIS" in r.regulation
        assert r.filter_name == "FERCEnergyFilter"

    def test_15_market_activity_no_anti_manipulation_denied(self):
        """18 CFR §1c.2: Market activity without anti_manipulation_safeguards → DENIED."""
        doc = {
            "is_energy_trading_data": False,
            "is_market_activity": True,
            "anti_manipulation_safeguards": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§1c.2" in r.regulation

    def test_16_interstate_gas_no_tariff_denied(self):
        """NGA §7: Interstate gas pipeline without ferc_gas_tariff_compliant → DENIED."""
        doc = {
            "is_energy_trading_data": False,
            "is_market_activity": False,
            "is_interstate_gas_pipeline": True,
            "ferc_gas_tariff_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Gas Tariff" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_17_hydropower_no_part12_requires_review(self):
        """FERC Part 12: Hydropower without ferc_part12_dam_safety_current → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_energy_trading_data": False,
            "is_market_activity": False,
            "is_interstate_gas_pipeline": False,
            "is_hydropower_facility": True,
            "ferc_part12_dam_safety_current": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "Part 12" in r.regulation

    # --- PERMITTED cases ---

    def test_18_fully_compliant_ferc_permitted(self):
        """All FERC controls satisfied → PERMITTED."""
        doc = {
            "is_energy_trading_data": True,
            "oasis_compliant": True,
            "is_market_activity": True,
            "anti_manipulation_safeguards": True,
            "is_interstate_gas_pipeline": True,
            "ferc_gas_tariff_compliant": True,
            "is_hydropower_facility": True,
            "ferc_part12_dam_safety_current": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_19_non_ferc_document_permitted(self):
        """Document with no FERC-relevant flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_20_no_hydropower_flag_no_part12_check(self):
        """Without is_hydropower_facility, Part 12 check is skipped."""
        doc = {
            "is_hydropower_facility": False,
            "ferc_part12_dam_safety_current": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_21_oasis_denial_precedes_anti_manipulation_check(self):
        """OASIS denial fires before Anti-Manipulation Rule check."""
        doc = {
            "is_energy_trading_data": True,
            "oasis_compliant": False,
            "is_market_activity": True,
            "anti_manipulation_safeguards": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "OASIS" in r.regulation

    def test_22_empty_dict_permitted(self):
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_23_filter_name_is_ferc(self):
        r = self.f.filter({})
        assert r.filter_name == "FERCEnergyFilter"

    def test_24_is_denied_false_for_review(self):
        doc = {
            "is_hydropower_facility": True,
            "ferc_part12_dam_safety_current": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_25_reason_non_empty_on_denial(self):
        doc = {"is_energy_trading_data": True, "oasis_compliant": False}
        r = self.f.filter(doc)
        assert r.reason

    def test_26_market_activity_compliant_no_denial(self):
        """Market activity with anti_manipulation_safeguards=True is not denied."""
        doc = {
            "is_market_activity": True,
            "anti_manipulation_safeguards": True,
        }
        r = self.f.filter(doc)
        assert r.decision != "DENIED"


# ---------------------------------------------------------------------------
# [27-39] DOECybersecurityFilter
# ---------------------------------------------------------------------------


class TestDOECybersecurityFilter:
    def setup_method(self):
        self.f = DOECybersecurityFilter()

    # --- DENIED cases ---

    def test_27_energy_ot_no_doe_100day_denied(self):
        """DOE 100-Day Plan: Energy OT without doe_100day_plan_controls → DENIED."""
        doc = {"is_energy_ot_system": True, "doe_100day_plan_controls": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "100-Day" in r.regulation
        assert r.filter_name == "DOECybersecurityFilter"

    def test_28_energy_ics_no_ics_cert_denied(self):
        """CISA ICS-CERT: Energy ICS without ics_cert_baseline_controls → DENIED."""
        doc = {
            "is_energy_ot_system": False,
            "is_energy_ics": True,
            "ics_cert_baseline_controls": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "ICS-CERT" in r.regulation

    def test_29_energy_ai_ml_no_nist_rmf_denied(self):
        """NIST AI RMF: Energy AI/ML system without nist_ai_rmf_energy_profile → DENIED."""
        doc = {
            "is_energy_ot_system": False,
            "is_energy_ics": False,
            "is_energy_ai_ml_system": True,
            "nist_ai_rmf_energy_profile": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "AI RMF" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_30_grid_modernisation_no_ceser_sharing_requires_review(self):
        """DOE CESER: Grid modernisation data without doe_ceser_threat_sharing → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_energy_ot_system": False,
            "is_energy_ics": False,
            "is_energy_ai_ml_system": False,
            "is_grid_modernisation_data": True,
            "doe_ceser_threat_sharing": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "CESER" in r.regulation

    # --- PERMITTED cases ---

    def test_31_fully_compliant_doe_permitted(self):
        """All DOE/CISA controls satisfied → PERMITTED."""
        doc = {
            "is_energy_ot_system": True,
            "doe_100day_plan_controls": True,
            "is_energy_ics": True,
            "ics_cert_baseline_controls": True,
            "is_energy_ai_ml_system": True,
            "nist_ai_rmf_energy_profile": True,
            "is_grid_modernisation_data": True,
            "doe_ceser_threat_sharing": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_32_non_doe_document_permitted(self):
        """Document with no DOE/CISA-relevant flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_33_no_grid_modernisation_no_ceser_check(self):
        """Without is_grid_modernisation_data, CESER threat sharing check is skipped."""
        doc = {
            "is_grid_modernisation_data": False,
            "doe_ceser_threat_sharing": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_34_doe_100day_denial_precedes_ics_cert_check(self):
        """DOE 100-Day denial fires before ICS-CERT check."""
        doc = {
            "is_energy_ot_system": True,
            "doe_100day_plan_controls": False,
            "is_energy_ics": True,
            "ics_cert_baseline_controls": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "100-Day" in r.regulation

    def test_35_empty_dict_permitted(self):
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_36_filter_name_is_doe(self):
        r = self.f.filter({})
        assert r.filter_name == "DOECybersecurityFilter"

    def test_37_is_denied_false_for_review(self):
        doc = {
            "is_grid_modernisation_data": True,
            "doe_ceser_threat_sharing": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_38_reason_non_empty_on_denial(self):
        doc = {"is_energy_ot_system": True, "doe_100day_plan_controls": False}
        r = self.f.filter(doc)
        assert r.reason

    def test_39_energy_ai_ml_compliant_not_denied(self):
        """Energy AI/ML system with nist_ai_rmf_energy_profile=True is not denied."""
        doc = {"is_energy_ai_ml_system": True, "nist_ai_rmf_energy_profile": True}
        r = self.f.filter(doc)
        assert r.decision != "DENIED"


# ---------------------------------------------------------------------------
# [40-52] EnergyCrossBorderFilter
# ---------------------------------------------------------------------------


class TestEnergyCrossBorderFilter:
    def setup_method(self):
        self.f = EnergyCrossBorderFilter()

    # --- DENIED cases ---

    def test_40_ferc_electricity_export_non_nafta_no_auth_denied(self):
        """FPA §202(e): FERC electricity export to non-NAFTA country without authorisation → DENIED."""
        doc = {
            "is_ferc_electricity_export": True,
            "destination_country": "GB",
            "ferc_export_authorisation": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§202(e)" in r.regulation
        assert r.filter_name == "EnergyCrossBorderFilter"

    def test_41_critical_energy_data_to_china_denied(self):
        """EO 13873 / DOE ICTS: Critical energy data to China → DENIED."""
        doc = {
            "is_critical_energy_infrastructure_data": True,
            "destination_country": "CN",
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "EO 13873" in r.regulation

    def test_42_lng_terminal_no_doe_auth_denied(self):
        """NGA §3: LNG export terminal data without doe_lng_export_authorisation → DENIED."""
        doc = {
            "is_ferc_electricity_export": False,
            "is_critical_energy_infrastructure_data": False,
            "is_lng_export_terminal_data": True,
            "doe_lng_export_authorisation": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Natural Gas Act §3" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_43_eu_energy_no_nis2_art21_requires_review(self):
        """NIS2 Art. 21: EU energy data without nis2_art21_risk_measures → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_ferc_electricity_export": False,
            "is_critical_energy_infrastructure_data": False,
            "is_lng_export_terminal_data": False,
            "is_eu_energy_data": True,
            "nis2_art21_risk_measures": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "NIS2" in r.regulation

    # --- PERMITTED cases ---

    def test_44_ferc_export_to_nafta_country_permitted(self):
        """FERC electricity export to NAFTA country (CA) → PERMITTED (§202(e) n/a)."""
        doc = {
            "is_ferc_electricity_export": True,
            "destination_country": "CA",
            "ferc_export_authorisation": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_45_non_critical_data_to_china_permitted(self):
        """China destination but is_critical_energy_infrastructure_data=False → PERMITTED."""
        doc = {
            "is_critical_energy_infrastructure_data": False,
            "destination_country": "CN",
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_46_lng_terminal_with_doe_auth_permitted(self):
        """LNG terminal data with doe_lng_export_authorisation=True → PERMITTED."""
        doc = {
            "is_lng_export_terminal_data": True,
            "doe_lng_export_authorisation": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_47_all_four_adversarial_nations_denied(self):
        """All four adversarial nations (CN/RU/KP/IR) produce DENIED for critical data."""
        for country in ("CN", "RU", "KP", "IR"):
            r = self.f.filter(
                {
                    "is_critical_energy_infrastructure_data": True,
                    "destination_country": country,
                }
            )
            assert r.decision == "DENIED", f"Expected DENIED for {country}"
            assert r.is_denied

    def test_48_ferc_export_with_authorisation_to_non_nafta_permitted(self):
        """FERC electricity export to non-NAFTA with ferc_export_authorisation=True → PERMITTED."""
        doc = {
            "is_ferc_electricity_export": True,
            "destination_country": "DE",
            "ferc_export_authorisation": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_49_empty_dict_permitted(self):
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_50_filter_name_is_cross_border(self):
        r = self.f.filter({})
        assert r.filter_name == "EnergyCrossBorderFilter"

    def test_51_is_denied_false_for_review(self):
        doc = {
            "is_eu_energy_data": True,
            "nis2_art21_risk_measures": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_52_ferc_fpa_denial_precedes_eo13873_check(self):
        """FPA §202(e) denial fires before EO 13873 check when both conditions met."""
        doc = {
            "is_ferc_electricity_export": True,
            "destination_country": "RU",
            "ferc_export_authorisation": False,
            "is_critical_energy_infrastructure_data": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        # RU is both non-NAFTA (FPA §202(e)) and adversarial (EO 13873);
        # FPA §202(e) fires first in evaluation order.
        assert "§202(e)" in r.regulation


# ---------------------------------------------------------------------------
# [53-54] FilterResult correctness + cross-filter pipeline integration
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
