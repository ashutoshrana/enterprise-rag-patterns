"""
Tests for 47_maritime_imo_rag.py

Covers IMOSafetyFilter, MARPOLFilter, ISPSFilter,
MaritimeCrossBorderFilter, FilterResult, and the run_pipeline helper.

54 tests total:
  [1-13]  IMOSafetyFilter              — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [14-26] MARPOLFilter                 — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [27-39] ISPSFilter                   — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
  [40-52] MaritimeCrossBorderFilter    — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 6 edge
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

_MOD_NAME = "maritime_imo_rag_47"
_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "47_maritime_imo_rag.py")

spec = importlib.util.spec_from_file_location(_MOD_NAME, _EXAMPLE_PATH)
mod = types.ModuleType(_MOD_NAME)
sys.modules[_MOD_NAME] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
FilterResult = mod.FilterResult
IMOSafetyFilter = mod.IMOSafetyFilter
MARPOLFilter = mod.MARPOLFilter
ISPSFilter = mod.ISPSFilter
MaritimeCrossBorderFilter = mod.MaritimeCrossBorderFilter
run_pipeline = mod.run_pipeline
PSC_DEFICIENT_PORTS = mod.PSC_DEFICIENT_PORTS
OFAC_SANCTIONED_FLAG_STATES = mod.OFAC_SANCTIONED_FLAG_STATES
OFAC_CREW_NATIONALITIES = mod.OFAC_CREW_NATIONALITIES


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _compliant_doc() -> dict:
    """A fully compliant maritime document that passes all four layers."""
    return {
        "doc_id": "compliant-imo-001",
        # Layer 1 — IMO Safety
        "vessel_type": "cargo",
        "solas_certificate": True,
        "ism_doc_smc": True,
        "lsa_cert": True,
        "ism_audit_years": 2,
        # Layer 2 — MARPOL
        "iopp_certificate": True,
        "oil_record_book": True,
        "vessel_build_year": 2018,
        "in_eca": True,
        "nox_tier3_cert": True,
        "fuel_sulfur_pct": 0.1,
        # Layer 3 — ISPS
        "issc_certificate": True,
        "ssp_approved": True,
        "facility_type": "vessel",
        "pfsp_approved": True,
        "security_level": 1,
        # Layer 4 — Cross-border
        "port_name": "Rotterdam",
        "flag_state": "NO",
        "crew_nationality": "PH",
        "us_waters": True,
        "cbp_noa_submitted": True,
    }


# ---------------------------------------------------------------------------
# [1-13] IMOSafetyFilter
# ---------------------------------------------------------------------------


class TestIMOSafetyFilter:
    def setup_method(self):
        self.f = IMOSafetyFilter()

    # --- DENIED cases ---

    def test_01_no_solas_certificate_denied(self):
        """SOLAS Chapter I: vessel without solas_certificate → DENIED."""
        doc = {"vessel_type": "cargo", "solas_certificate": False, "ism_doc_smc": True}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "SOLAS Chapter I" in r.regulation
        assert r.filter_name == "IMOSafetyFilter"

    def test_02_no_ism_doc_smc_denied(self):
        """ISM Code: vessel with solas_certificate=True but no ism_doc_smc → DENIED."""
        doc = {"solas_certificate": True, "ism_doc_smc": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "ISM Code" in r.regulation

    def test_03_passenger_vessel_no_lsa_cert_denied(self):
        """SOLAS Chapter III: passenger vessel without lsa_cert → DENIED."""
        doc = {
            "vessel_type": "passenger",
            "solas_certificate": True,
            "ism_doc_smc": True,
            "lsa_cert": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "SOLAS Chapter III" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_04_ism_audit_overdue_requires_review(self):
        """ISM Code §3.1: ism_audit_years > 5 → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "solas_certificate": True,
            "ism_doc_smc": True,
            "ism_audit_years": 7,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "ISM Code" in r.regulation

    # --- PERMITTED cases ---

    def test_05_cargo_vessel_with_all_certs_permitted(self):
        """Cargo vessel with solas_certificate and ism_doc_smc → PERMITTED."""
        doc = {
            "vessel_type": "cargo",
            "solas_certificate": True,
            "ism_doc_smc": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_06_passenger_vessel_with_lsa_cert_permitted(self):
        """Passenger vessel with all certs including lsa_cert → PERMITTED."""
        doc = {
            "vessel_type": "passenger",
            "solas_certificate": True,
            "ism_doc_smc": True,
            "lsa_cert": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_07_audit_exactly_5_years_permitted(self):
        """ISM audit exactly at 5 years (not exceeding) → PERMITTED."""
        doc = {
            "solas_certificate": True,
            "ism_doc_smc": True,
            "ism_audit_years": 5,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_08_solas_denial_precedes_ism_check(self):
        """SOLAS Chapter I denial fires before ISM Code check."""
        doc = {
            "solas_certificate": False,
            "ism_doc_smc": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "SOLAS Chapter I" in r.regulation

    def test_09_non_passenger_vessel_no_lsa_required_permitted(self):
        """Non-passenger vessel without lsa_cert does not trigger SOLAS Chapter III → PERMITTED."""
        doc = {
            "vessel_type": "tanker",
            "solas_certificate": True,
            "ism_doc_smc": True,
            "lsa_cert": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_10_filter_name_is_imo_safety(self):
        """filter_name field is set to IMOSafetyFilter."""
        doc = {"solas_certificate": True, "ism_doc_smc": True}
        r = self.f.filter(doc)
        assert r.filter_name == "IMOSafetyFilter"

    def test_11_reason_non_empty_on_solas_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"solas_certificate": False, "ism_doc_smc": True}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_12_is_denied_false_for_ism_audit_review(self):
        """is_denied must be False for ISM audit REQUIRES_HUMAN_REVIEW."""
        doc = {
            "solas_certificate": True,
            "ism_doc_smc": True,
            "ism_audit_years": 10,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_13_empty_doc_no_solas_certificate_denied(self):
        """Empty document defaults solas_certificate to False → DENIED."""
        r = self.f.filter({})
        assert r.decision == "DENIED"
        assert "SOLAS Chapter I" in r.regulation


# ---------------------------------------------------------------------------
# [14-26] MARPOLFilter
# ---------------------------------------------------------------------------


class TestMARPOLFilter:
    def setup_method(self):
        self.f = MARPOLFilter()

    # --- DENIED cases ---

    def test_14_no_iopp_certificate_denied(self):
        """MARPOL Annex I: vessel without iopp_certificate → DENIED."""
        doc = {"iopp_certificate": False, "oil_record_book": True}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "IOPP" in r.regulation
        assert r.filter_name == "MARPOLFilter"

    def test_15_no_oil_record_book_denied(self):
        """MARPOL Annex I Reg. 17: iopp_certificate=True but no oil_record_book → DENIED."""
        doc = {"iopp_certificate": True, "oil_record_book": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Oil Record Book" in r.regulation

    def test_16_post_2016_vessel_in_eca_no_nox_tier3_denied(self):
        """MARPOL Annex VI Reg. 13: post-2016 vessel in ECA without nox_tier3_cert → DENIED."""
        doc = {
            "iopp_certificate": True,
            "oil_record_book": True,
            "vessel_build_year": 2019,
            "in_eca": True,
            "nox_tier3_cert": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Tier III" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_17_fuel_sulfur_exceeds_limit_requires_review(self):
        """MARPOL Annex VI Reg. 14: fuel_sulfur_pct > 0.5 → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "iopp_certificate": True,
            "oil_record_book": True,
            "vessel_build_year": 2010,
            "in_eca": False,
            "fuel_sulfur_pct": 0.8,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "Sulfur" in r.regulation

    # --- PERMITTED cases ---

    def test_18_compliant_vessel_permitted(self):
        """All MARPOL requirements satisfied → PERMITTED."""
        doc = {
            "iopp_certificate": True,
            "oil_record_book": True,
            "vessel_build_year": 2020,
            "in_eca": True,
            "nox_tier3_cert": True,
            "fuel_sulfur_pct": 0.1,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_19_pre_2016_vessel_in_eca_no_nox_tier3_permitted(self):
        """Pre-2016 vessel in ECA is exempt from Tier III NOx requirement → PERMITTED."""
        doc = {
            "iopp_certificate": True,
            "oil_record_book": True,
            "vessel_build_year": 2014,
            "in_eca": True,
            "nox_tier3_cert": False,
            "fuel_sulfur_pct": 0.1,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_20_post_2016_not_in_eca_no_nox_tier3_permitted(self):
        """Post-2016 vessel NOT in ECA is exempt from Tier III NOx requirement → PERMITTED."""
        doc = {
            "iopp_certificate": True,
            "oil_record_book": True,
            "vessel_build_year": 2018,
            "in_eca": False,
            "nox_tier3_cert": False,
            "fuel_sulfur_pct": 0.1,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_21_iopp_denial_precedes_oil_record_book_check(self):
        """IOPP denial fires before Oil Record Book check."""
        doc = {"iopp_certificate": False, "oil_record_book": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "IOPP" in r.regulation

    def test_22_fuel_sulfur_exactly_at_limit_permitted(self):
        """fuel_sulfur_pct exactly at 0.5 m/m (not exceeding) → PERMITTED."""
        doc = {
            "iopp_certificate": True,
            "oil_record_book": True,
            "fuel_sulfur_pct": 0.5,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_23_filter_name_is_marpol(self):
        """filter_name field is set to MARPOLFilter."""
        doc = {"iopp_certificate": True, "oil_record_book": True}
        r = self.f.filter(doc)
        assert r.filter_name == "MARPOLFilter"

    def test_24_reason_non_empty_on_iopp_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"iopp_certificate": False}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_25_is_denied_false_for_sulfur_review(self):
        """is_denied must be False for fuel sulfur REQUIRES_HUMAN_REVIEW."""
        doc = {
            "iopp_certificate": True,
            "oil_record_book": True,
            "fuel_sulfur_pct": 1.2,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_26_vessel_build_year_exactly_2016_triggers_tier3_check(self):
        """vessel_build_year == 2016 (>= 2016 threshold) in ECA without cert → DENIED."""
        doc = {
            "iopp_certificate": True,
            "oil_record_book": True,
            "vessel_build_year": 2016,
            "in_eca": True,
            "nox_tier3_cert": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "Tier III" in r.regulation


# ---------------------------------------------------------------------------
# [27-39] ISPSFilter
# ---------------------------------------------------------------------------


class TestISPSFilter:
    def setup_method(self):
        self.f = ISPSFilter()

    # --- DENIED cases ---

    def test_27_no_issc_certificate_denied(self):
        """ISPS Code §19.1: vessel without issc_certificate → DENIED."""
        doc = {"issc_certificate": False, "ssp_approved": True}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "ISSC" in r.regulation
        assert r.filter_name == "ISPSFilter"

    def test_28_ssp_not_approved_denied(self):
        """ISPS Code §9.4: issc_certificate=True but ssp_approved=False → DENIED."""
        doc = {"issc_certificate": True, "ssp_approved": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "SSP" in r.regulation

    def test_29_port_facility_no_pfsp_denied(self):
        """ISPS Code §16: port facility without pfsp_approved → DENIED."""
        doc = {
            "issc_certificate": True,
            "ssp_approved": True,
            "facility_type": "port",
            "pfsp_approved": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "PFSP" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_30_security_level_3_no_communication_requires_review(self):
        """ISPS Code §9.1: security_level=3 without maritime_security_communication → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "issc_certificate": True,
            "ssp_approved": True,
            "security_level": 3,
            "maritime_security_communication": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "Security Level 3" in r.regulation

    # --- PERMITTED cases ---

    def test_31_vessel_with_issc_and_ssp_permitted(self):
        """Vessel with issc_certificate and ssp_approved=True → PERMITTED."""
        doc = {
            "issc_certificate": True,
            "ssp_approved": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_32_port_with_pfsp_approved_permitted(self):
        """Port facility with pfsp_approved=True → PERMITTED."""
        doc = {
            "issc_certificate": True,
            "ssp_approved": True,
            "facility_type": "port",
            "pfsp_approved": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_33_security_level_3_with_communication_permitted(self):
        """Security Level 3 with maritime_security_communication=True → PERMITTED."""
        doc = {
            "issc_certificate": True,
            "ssp_approved": True,
            "security_level": 3,
            "maritime_security_communication": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_34_issc_denial_precedes_ssp_check(self):
        """ISSC denial fires before SSP approval check."""
        doc = {
            "issc_certificate": False,
            "ssp_approved": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "ISSC" in r.regulation

    def test_35_non_port_facility_no_pfsp_not_denied(self):
        """Non-port facility without pfsp_approved does not trigger PFSP denial → PERMITTED."""
        doc = {
            "issc_certificate": True,
            "ssp_approved": True,
            "facility_type": "terminal",
            "pfsp_approved": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_36_filter_name_is_isps(self):
        """filter_name field is set to ISPSFilter."""
        doc = {"issc_certificate": True, "ssp_approved": True}
        r = self.f.filter(doc)
        assert r.filter_name == "ISPSFilter"

    def test_37_reason_non_empty_on_issc_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"issc_certificate": False}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_38_is_denied_false_for_security_level_3_review(self):
        """is_denied must be False for security level 3 REQUIRES_HUMAN_REVIEW."""
        doc = {
            "issc_certificate": True,
            "ssp_approved": True,
            "security_level": 3,
            "maritime_security_communication": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_39_security_level_1_default_permitted(self):
        """Default security_level (1) with certs → PERMITTED."""
        doc = {
            "issc_certificate": True,
            "ssp_approved": True,
            "security_level": 1,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"


# ---------------------------------------------------------------------------
# [40-52] MaritimeCrossBorderFilter
# ---------------------------------------------------------------------------


class TestMaritimeCrossBorderFilter:
    def setup_method(self):
        self.f = MaritimeCrossBorderFilter()

    # --- DENIED cases ---

    def test_40_psc_deficient_port_no_clearance_denied(self):
        """Paris/Tokyo MOU: vessel at PSC-deficient port without psc_clearance → DENIED."""
        doc = {"port_name": "Bandar_Abbas", "psc_clearance": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Port State Control" in r.regulation
        assert r.filter_name == "MaritimeCrossBorderFilter"

    def test_41_ofac_sanctioned_flag_state_denied(self):
        """OFAC SDN: vessel with flag_state in OFAC_SANCTIONED_FLAG_STATES → DENIED."""
        doc = {"flag_state": "IR"}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "OFAC" in r.regulation

    def test_42_ofac_crew_nationality_no_license_denied(self):
        """OFAC Crew: crew_nationality in OFAC_CREW_NATIONALITIES without ofac_license → DENIED."""
        doc = {
            "flag_state": "NO",
            "crew_nationality": "KP",
            "ofac_license": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "OFAC" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_43_us_waters_no_cbp_noa_requires_review(self):
        """33 CFR §160.212: us_waters=True without cbp_noa_submitted → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "flag_state": "NO",
            "crew_nationality": "PH",
            "us_waters": True,
            "cbp_noa_submitted": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "NOA" in r.regulation

    # --- PERMITTED cases ---

    def test_44_clean_port_call_permitted(self):
        """Non-deficient port, clean flag state, clean crew, no US waters → PERMITTED."""
        doc = {
            "port_name": "Rotterdam",
            "flag_state": "NO",
            "crew_nationality": "PH",
            "us_waters": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_45_psc_deficient_port_with_clearance_permitted(self):
        """PSC-deficient port with psc_clearance=True → PERMITTED."""
        doc = {
            "port_name": "Wonsan",
            "psc_clearance": True,
            "flag_state": "NO",
            "crew_nationality": "PH",
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_46_us_waters_with_cbp_noa_submitted_permitted(self):
        """US waters with cbp_noa_submitted=True → PERMITTED."""
        doc = {
            "flag_state": "US",
            "crew_nationality": "US",
            "us_waters": True,
            "cbp_noa_submitted": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_47_all_ofac_sanctioned_flag_states_denied(self):
        """All OFAC_SANCTIONED_FLAG_STATES (KP/IR/SY/CU) trigger denial."""
        for flag in ("KP", "IR", "SY", "CU"):
            doc = {"flag_state": flag}
            r = self.f.filter(doc)
            assert r.decision == "DENIED", f"Expected DENIED for sanctioned flag state {flag}"
            assert r.is_denied

    def test_48_all_psc_deficient_ports_denied_without_clearance(self):
        """All PSC_DEFICIENT_PORTS trigger denial without psc_clearance."""
        for port in ("Bandar_Abbas", "Bushehr", "Wonsan", "Nampo", "Tartus"):
            doc = {"port_name": port, "psc_clearance": False}
            r = self.f.filter(doc)
            assert r.decision == "DENIED", f"Expected DENIED for PSC-deficient port {port}"

    def test_49_psc_denial_precedes_flag_state_check(self):
        """PSC-deficient port denial fires before OFAC flag state check."""
        doc = {
            "port_name": "Tartus",
            "psc_clearance": False,
            "flag_state": "IR",
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "Port State Control" in r.regulation

    def test_50_filter_name_is_maritime_cross_border(self):
        """filter_name field is set to MaritimeCrossBorderFilter."""
        r = self.f.filter({})
        assert r.filter_name == "MaritimeCrossBorderFilter"

    def test_51_empty_dict_permitted(self):
        """Empty document has no cross-border flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_52_ofac_crew_with_license_permitted(self):
        """OFAC crew nationality with ofac_license=True → PERMITTED."""
        doc = {
            "flag_state": "NO",
            "crew_nationality": "IR",
            "ofac_license": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"


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
        ):
            r = FilterResult(
                decision=decision,
                regulation="TEST",
                reason="test reason",
                filter_name="TestFilter",
            )
            assert r.is_denied is expected, f"is_denied wrong for decision={decision!r}"

    def test_54_compliant_doc_passes_all_four_layers(self):
        """A fully compliant maritime document must pass all four filters with PERMITTED."""
        doc = _compliant_doc()
        results = run_pipeline(doc)
        assert len(results) == 4
        for r in results:
            assert r.decision == "PERMITTED", f"Expected PERMITTED from {r.filter_name}, got {r.decision}: {r.reason}"
            assert not r.is_denied
