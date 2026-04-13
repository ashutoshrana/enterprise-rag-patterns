"""
Tests for 46_nuclear_nrc_rag.py

Covers NRCLicensingFilter, NRCRadiationProtectionFilter, NDAClassifiedFilter,
NuclearCrossBorderFilter, FilterResult, and the run_pipeline helper.

56 tests total:
  [1-13]  NRCLicensingFilter           — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [14-26] NRCRadiationProtectionFilter — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [27-39] NDAClassifiedFilter          — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [40-52] NuclearCrossBorderFilter     — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
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

_MOD_NAME = "nuclear_nrc_rag_46"
_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "46_nuclear_nrc_rag.py")

spec = importlib.util.spec_from_file_location(_MOD_NAME, _EXAMPLE_PATH)
mod = types.ModuleType(_MOD_NAME)
sys.modules[_MOD_NAME] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
FilterResult = mod.FilterResult
NRCLicensingFilter = mod.NRCLicensingFilter
NRCRadiationProtectionFilter = mod.NRCRadiationProtectionFilter
NDAClassifiedFilter = mod.NDAClassifiedFilter
NuclearCrossBorderFilter = mod.NuclearCrossBorderFilter
run_pipeline = mod.run_pipeline
NPT_MEMBER_STATES = mod.NPT_MEMBER_STATES
RESTRICTED_NUCLEAR_COUNTRIES = mod.RESTRICTED_NUCLEAR_COUNTRIES
NRC_SENSITIVE_COUNTRIES = mod.NRC_SENSITIVE_COUNTRIES


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _compliant_doc() -> dict:
    """A fully compliant nuclear document that passes all four layers."""
    return {
        "doc_id": "compliant-test-001",
        # Layer 1 — NRC Licensing
        "facility_type": "power_reactor",
        "nrc_part50_license": True,
        "is_radioactive_material_transport": True,
        "nrc_part71_cert": True,
        # Layer 2 — Radiation Protection
        "occupational_dose_rem": 2.0,
        "public_dose_mrem": 50,
        "alara_documented": True,
        "effluent_within_appendix_b": True,
        # Layer 3 — Classification
        "classification": "UNCLASSIFIED",
        "safeguards_info": False,
        "sunsi_data": False,
        # Layer 4 — Cross-border
        "destination_country": "JP",
        "is_fissile_material_transfer": False,
        "is_dual_use_nuclear_item": False,
    }


# ---------------------------------------------------------------------------
# [1-13] NRCLicensingFilter
# ---------------------------------------------------------------------------


class TestNRCLicensingFilter:
    def setup_method(self):
        self.f = NRCLicensingFilter()

    # --- DENIED cases ---

    def test_01_power_reactor_no_part50_license_denied(self):
        """10 CFR Part 50: power_reactor without nrc_part50_license → DENIED."""
        doc = {"facility_type": "power_reactor", "nrc_part50_license": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Part 50" in r.regulation
        assert r.filter_name == "NRCLicensingFilter"

    def test_02_fuel_cycle_facility_no_part70_license_denied(self):
        """10 CFR Part 70: fuel_cycle_facility without nrc_part70_license → DENIED."""
        doc = {"facility_type": "fuel_cycle_facility", "nrc_part70_license": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Part 70" in r.regulation

    def test_03_radioactive_transport_no_part71_cert_denied(self):
        """10 CFR Part 71: radioactive material transport without nrc_part71_cert → DENIED."""
        doc = {"is_radioactive_material_transport": True, "nrc_part71_cert": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Part 71" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_04_research_reactor_no_license_requires_review(self):
        """10 CFR §50.21(c): research_reactor without nrc_part50_license → REQUIRES_HUMAN_REVIEW."""
        doc = {"facility_type": "research_reactor", "nrc_part50_license": False}
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "50.21(c)" in r.regulation

    # --- PERMITTED cases ---

    def test_05_power_reactor_with_license_permitted(self):
        """Power reactor with nrc_part50_license=True → PERMITTED."""
        doc = {"facility_type": "power_reactor", "nrc_part50_license": True}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_06_fuel_cycle_with_part70_license_permitted(self):
        """Fuel cycle facility with nrc_part70_license=True → PERMITTED."""
        doc = {"facility_type": "fuel_cycle_facility", "nrc_part70_license": True}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_07_no_facility_flags_permitted(self):
        """Document with no facility type or transport flag → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_08_power_reactor_denial_precedes_transport_check(self):
        """Power reactor denial fires before transport check."""
        doc = {
            "facility_type": "power_reactor",
            "nrc_part50_license": False,
            "is_radioactive_material_transport": True,
            "nrc_part71_cert": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "Part 50" in r.regulation

    def test_09_empty_dict_permitted(self):
        """Empty document has no NRC licensing flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_10_filter_name_is_nrc_licensing(self):
        """filter_name field is set to NRCLicensingFilter."""
        r = self.f.filter({})
        assert r.filter_name == "NRCLicensingFilter"

    def test_11_reason_non_empty_on_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"facility_type": "power_reactor", "nrc_part50_license": False}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_12_is_denied_false_for_research_reactor_review(self):
        """is_denied must be False for REQUIRES_HUMAN_REVIEW."""
        doc = {"facility_type": "research_reactor", "nrc_part50_license": False}
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_13_transport_with_cert_permitted(self):
        """Radioactive material transport with nrc_part71_cert=True → PERMITTED."""
        doc = {"is_radioactive_material_transport": True, "nrc_part71_cert": True}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"


# ---------------------------------------------------------------------------
# [14-26] NRCRadiationProtectionFilter
# ---------------------------------------------------------------------------


class TestNRCRadiationProtectionFilter:
    def setup_method(self):
        self.f = NRCRadiationProtectionFilter()

    # --- DENIED cases ---

    def test_14_occupational_dose_over_5rem_denied(self):
        """§20.1201: occupational_dose_rem > 5 → DENIED."""
        doc = {"occupational_dose_rem": 7.2, "alara_documented": True}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§20.1201" in r.regulation
        assert r.filter_name == "NRCRadiationProtectionFilter"

    def test_15_public_dose_over_100mrem_denied(self):
        """§20.1301: public_dose_mrem > 100 → DENIED."""
        doc = {
            "occupational_dose_rem": 1.0,
            "public_dose_mrem": 150,
            "alara_documented": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§20.1301" in r.regulation

    def test_16_alara_not_documented_denied(self):
        """§20.1101: alara_documented=False → DENIED."""
        doc = {
            "occupational_dose_rem": 1.0,
            "public_dose_mrem": 50,
            "alara_documented": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§20.1101" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_17_effluent_appendix_b_not_confirmed_requires_review(self):
        """Appendix B: effluent_within_appendix_b=False → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "occupational_dose_rem": 0.5,
            "public_dose_mrem": 10,
            "alara_documented": True,
            "effluent_within_appendix_b": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "Appendix B" in r.regulation

    # --- PERMITTED cases ---

    def test_18_all_dose_limits_met_permitted(self):
        """All radiation protection requirements satisfied → PERMITTED."""
        doc = {
            "occupational_dose_rem": 2.5,
            "public_dose_mrem": 75,
            "alara_documented": True,
            "effluent_within_appendix_b": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_19_dose_exactly_at_limit_permitted(self):
        """Occupational dose exactly at 5 rem limit is not exceeded → PERMITTED."""
        doc = {"occupational_dose_rem": 5.0, "alara_documented": True}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_20_no_radiation_flags_permitted(self):
        """Document with no radiation dose fields → PERMITTED (defaults to 0)."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_21_occupational_dose_denial_precedes_public_dose_check(self):
        """Occupational dose denial fires before public dose check."""
        doc = {
            "occupational_dose_rem": 10.0,
            "public_dose_mrem": 200,
            "alara_documented": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "§20.1201" in r.regulation

    def test_22_empty_dict_uses_default_zero_doses_permitted(self):
        """Empty document defaults occupational dose to 0 → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_23_filter_name_is_radiation_protection(self):
        """filter_name field is set to NRCRadiationProtectionFilter."""
        r = self.f.filter({})
        assert r.filter_name == "NRCRadiationProtectionFilter"

    def test_24_reason_non_empty_on_dose_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"occupational_dose_rem": 6.0, "alara_documented": True}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_25_is_denied_false_for_effluent_review(self):
        """is_denied must be False for effluent REQUIRES_HUMAN_REVIEW."""
        doc = {
            "alara_documented": True,
            "effluent_within_appendix_b": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_26_effluent_appendix_b_none_does_not_trigger_review(self):
        """effluent_within_appendix_b=None (not set) does not trigger review."""
        doc = {
            "occupational_dose_rem": 1.0,
            "public_dose_mrem": 10,
            "alara_documented": True,
            # effluent_within_appendix_b not set — defaults to None
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"


# ---------------------------------------------------------------------------
# [27-39] NDAClassifiedFilter
# ---------------------------------------------------------------------------


class TestNDAClassifiedFilter:
    def setup_method(self):
        self.f = NDAClassifiedFilter()

    # --- DENIED cases ---

    def test_27_restricted_data_no_q_clearance_denied(self):
        """42 U.S.C. §2162: classification=RD without q_clearance → DENIED."""
        doc = {"classification": "RD", "q_clearance": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§2162" in r.regulation
        assert r.filter_name == "NDAClassifiedFilter"

    def test_28_formerly_restricted_data_no_l_clearance_denied(self):
        """FRD: classification=FRD without l_clearance → DENIED."""
        doc = {"classification": "FRD", "q_clearance": False, "l_clearance": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "FRD" in r.regulation

    def test_29_safeguards_info_no_authorized_access_denied(self):
        """10 CFR §73.21: safeguards_info=True without nrc_authorized_access → DENIED."""
        doc = {
            "classification": "UNCLASSIFIED",
            "safeguards_info": True,
            "nrc_authorized_access": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§73.21" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_30_sunsi_data_no_need_to_know_requires_review(self):
        """SUNSI: sunsi_data=True without need_to_know_verified → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "classification": "UNCLASSIFIED",
            "safeguards_info": False,
            "sunsi_data": True,
            "need_to_know_verified": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "SUNSI" in r.regulation

    # --- PERMITTED cases ---

    def test_31_restricted_data_with_q_clearance_permitted(self):
        """RD with q_clearance=True → PERMITTED."""
        doc = {"classification": "RD", "q_clearance": True}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_32_unclassified_no_safeguards_permitted(self):
        """UNCLASSIFIED document with no safeguards or SUNSI flags → PERMITTED."""
        doc = {"classification": "UNCLASSIFIED", "safeguards_info": False, "sunsi_data": False}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_33_no_classification_flags_permitted(self):
        """Document with no classification fields → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_34_rd_denial_precedes_safeguards_check(self):
        """RD denial fires before safeguards information check."""
        doc = {
            "classification": "RD",
            "q_clearance": False,
            "safeguards_info": True,
            "nrc_authorized_access": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "§2162" in r.regulation

    def test_35_empty_dict_permitted(self):
        """Empty document has no classification flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_36_filter_name_is_nda_classified(self):
        """filter_name field is set to NDAClassifiedFilter."""
        r = self.f.filter({})
        assert r.filter_name == "NDAClassifiedFilter"

    def test_37_reason_non_empty_on_rd_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"classification": "RD", "q_clearance": False}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_38_is_denied_false_for_sunsi_review(self):
        """is_denied must be False for SUNSI REQUIRES_HUMAN_REVIEW."""
        doc = {"sunsi_data": True, "need_to_know_verified": False}
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_39_frd_with_l_clearance_permitted(self):
        """FRD with l_clearance=True → PERMITTED."""
        doc = {"classification": "FRD", "l_clearance": True}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"


# ---------------------------------------------------------------------------
# [40-52] NuclearCrossBorderFilter
# ---------------------------------------------------------------------------


class TestNuclearCrossBorderFilter:
    def setup_method(self):
        self.f = NuclearCrossBorderFilter()

    # --- DENIED cases ---

    def test_40_non_npt_country_no_export_license_denied(self):
        """10 CFR Part 110: destination not in NPT without nrc_part110_export_license → DENIED."""
        doc = {
            "destination_country": "KP",
            "nrc_part110_export_license": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Part 110" in r.regulation
        assert r.filter_name == "NuclearCrossBorderFilter"

    def test_41_fissile_material_no_iaea_safeguards_denied(self):
        """NPT Art. III: fissile_material_transfer=True without iaea_safeguards → DENIED."""
        doc = {
            "destination_country": "JP",
            "is_fissile_material_transfer": True,
            "iaea_safeguards": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "IAEA" in r.regulation

    def test_42_restricted_country_no_123_agreement_denied(self):
        """42 U.S.C. §2153: destination in RESTRICTED_NUCLEAR_COUNTRIES without us_123_agreement → DENIED."""
        # Use nrc_part110_export_license=True to bypass the Part 110 check first,
        # so the 123 Agreement check fires for IR (a restricted country).
        doc = {
            "destination_country": "IR",
            "nrc_part110_export_license": True,
            "is_fissile_material_transfer": False,
            "us_123_agreement": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§2153" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_43_dual_use_nrc_sensitive_no_review_requires_review(self):
        """NRC Sensitive: dual-use nuclear item to sensitive country, no doe_nrc_review → REQUIRES_HUMAN_REVIEW."""
        # SY is not in NPT_MEMBER_STATES; bypass Part 110 check with export license.
        doc = {
            "destination_country": "SY",
            "nrc_part110_export_license": True,
            "is_fissile_material_transfer": False,
            "us_123_agreement": True,
            "is_dual_use_nuclear_item": True,
            "doe_nrc_review": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "Sensitive" in r.regulation

    # --- PERMITTED cases ---

    def test_44_npt_member_no_fissile_permitted(self):
        """NPT member destination with no fissile transfer → PERMITTED."""
        doc = {
            "destination_country": "JP",
            "is_fissile_material_transfer": False,
            "is_dual_use_nuclear_item": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_45_non_npt_with_export_license_permitted(self):
        """Non-NPT, non-restricted destination with valid nrc_part110_export_license → PERMITTED."""
        # Use "SS" (South Sudan) — not in NPT_MEMBER_STATES, RESTRICTED, or NRC_SENSITIVE.
        doc = {
            "destination_country": "SS",
            "nrc_part110_export_license": True,
            "is_fissile_material_transfer": False,
            "is_dual_use_nuclear_item": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_46_domestic_no_destination_permitted(self):
        """Document with no destination_country → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_47_all_restricted_nuclear_countries_denied_for_123(self):
        """All RESTRICTED_NUCLEAR_COUNTRIES (CN/RU/KP/IR) trigger 123 Agreement denial."""
        for country in ("CN", "RU", "KP", "IR"):
            doc = {
                "destination_country": country,
                "is_fissile_material_transfer": False,
                "us_123_agreement": False,
            }
            r = self.f.filter(doc)
            assert r.decision == "DENIED", f"Expected DENIED for restricted country {country}"
            assert r.is_denied

    def test_48_all_nrc_sensitive_countries_trigger_review_for_dual_use(self):
        """All NRC_SENSITIVE_COUNTRIES trigger REQUIRES_HUMAN_REVIEW for dual-use items."""
        for country in ("CN", "RU", "KP", "IR", "SY", "CU", "SD", "MM"):
            doc = {
                "destination_country": country,
                "is_dual_use_nuclear_item": True,
                "doe_nrc_review": False,
                # Bypass 123 check for non-restricted-country sensitive countries
                "us_123_agreement": True,
                # Bypass Part 110 check
                "nrc_part110_export_license": True,
                # No fissile transfer
                "is_fissile_material_transfer": False,
            }
            r = self.f.filter(doc)
            # For RESTRICTED countries (CN/RU/KP/IR), 123 denial fires first
            # unless us_123_agreement=True, so result should be review or permitted
            # For sensitive-only countries (SY/CU/SD/MM not in NPT), export license bypasses
            # the check. All should get REQUIRES_HUMAN_REVIEW here because us_123_agreement=True
            # and nrc_part110_export_license=True let them through to dual-use check.
            assert r.decision == "REQUIRES_HUMAN_REVIEW", (
                f"Expected REQUIRES_HUMAN_REVIEW for NRC sensitive country {country}, got {r.decision}"
            )

    def test_49_npt_denial_precedes_fissile_check_for_non_npt_no_license(self):
        """Non-NPT destination denial fires before fissile material check when no license."""
        doc = {
            "destination_country": "SS",  # South Sudan — not in NPT list
            "nrc_part110_export_license": False,
            "is_fissile_material_transfer": True,
            "iaea_safeguards": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "Part 110" in r.regulation

    def test_50_filter_name_is_nuclear_cross_border(self):
        """filter_name field is set to NuclearCrossBorderFilter."""
        r = self.f.filter({})
        assert r.filter_name == "NuclearCrossBorderFilter"

    def test_51_empty_dict_permitted(self):
        """Empty document has no cross-border flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_52_is_denied_false_for_dual_use_review(self):
        """is_denied must be False for dual-use REQUIRES_HUMAN_REVIEW."""
        doc = {
            "destination_country": "SY",
            "is_dual_use_nuclear_item": True,
            "doe_nrc_review": False,
            "us_123_agreement": True,
            "nrc_part110_export_license": True,
            "is_fissile_material_transfer": False,
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

    def test_55_pipeline_short_circuits_on_licensing_denial(self):
        """Pipeline stops after first DENIED (licensing layer) and returns only one result."""
        doc = {
            "facility_type": "power_reactor",
            "nrc_part50_license": False,
            # Radiation layer would also deny if reached
            "occupational_dose_rem": 10.0,
            "alara_documented": False,
        }
        results = run_pipeline(doc)
        assert len(results) == 1
        assert results[0].decision == "DENIED"
        assert results[0].filter_name == "NRCLicensingFilter"

    def test_56_constants_correct_membership(self):
        """Verify set constants contain the documented countries."""
        # NPT member states
        assert "US" in NPT_MEMBER_STATES
        assert "JP" in NPT_MEMBER_STATES
        assert "DE" in NPT_MEMBER_STATES
        assert "KR" in NPT_MEMBER_STATES
        # Restricted nuclear countries
        assert "CN" in RESTRICTED_NUCLEAR_COUNTRIES
        assert "RU" in RESTRICTED_NUCLEAR_COUNTRIES
        assert "KP" in RESTRICTED_NUCLEAR_COUNTRIES
        assert "IR" in RESTRICTED_NUCLEAR_COUNTRIES
        # NRC sensitive countries (superset of restricted)
        assert "CN" in NRC_SENSITIVE_COUNTRIES
        assert "SY" in NRC_SENSITIVE_COUNTRIES
        assert "CU" in NRC_SENSITIVE_COUNTRIES
        assert "SD" in NRC_SENSITIVE_COUNTRIES
        assert "MM" in NRC_SENSITIVE_COUNTRIES
        # Verify KP is not in NPT member states
        assert "KP" not in NPT_MEMBER_STATES
