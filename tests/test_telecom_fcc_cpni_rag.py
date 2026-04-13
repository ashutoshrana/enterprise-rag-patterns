"""
Tests for 48_telecom_fcc_cpni_rag.py

Covers FCCCPNIFilter, TelecomPrivacyFilter, FCC911Filter,
TelecomCrossBorderFilter, FilterResult, and the run_pipeline helper.

56 tests total:
  [1-14]  FCCCPNIFilter              — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 7 edge
  [15-28] TelecomPrivacyFilter       — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 7 edge
  [29-42] FCC911Filter               — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 7 edge
  [43-56] TelecomCrossBorderFilter   — 3 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 7 edge
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load the example module via importlib
# ---------------------------------------------------------------------------

_MOD_NAME = "telecom_fcc_cpni_rag_48"
_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "48_telecom_fcc_cpni_rag.py")

spec = importlib.util.spec_from_file_location(_MOD_NAME, _EXAMPLE_PATH)
mod = types.ModuleType(_MOD_NAME)
sys.modules[_MOD_NAME] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
FilterResult = mod.FilterResult
FCCCPNIFilter = mod.FCCCPNIFilter
TelecomPrivacyFilter = mod.TelecomPrivacyFilter
FCC911Filter = mod.FCC911Filter
TelecomCrossBorderFilter = mod.TelecomCrossBorderFilter
run_pipeline = mod.run_pipeline
OFAC_TELECOM_SANCTIONED = mod.OFAC_TELECOM_SANCTIONED
CABLE_RESTRICTED = mod.CABLE_RESTRICTED
FCC_COVERED_LIST = mod.FCC_COVERED_LIST


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _compliant_doc() -> dict:
    """A fully compliant telecom document that passes all four layers."""
    return {
        "doc_id": "compliant-fcc-001",
        # Layer 1 — FCC CPNI
        "cpni_consent_obtained": True,
        "marketing_existing_service": True,
        "cpni_opt_in": True,
        "third_party_disclosure": False,
        "third_party_safeguards": True,
        "cpni_retention_years": 1,
        # Layer 2 — Telecom Privacy
        "prior_express_consent": True,
        "do_not_call_scrubbed": True,
        "california_recording": False,
        "two_party_consent": True,
        "text_marketing": False,
        "ctia_compliant": True,
        # Layer 3 — FCC 911
        "voip_e911_routing": True,
        "wireless_dispatchable_location": True,
        "mlts_system": False,
        "karis_law_compliant": True,
        "crisis_line_routing": False,
        "fcc_988_compliant": True,
        # Layer 4 — Cross-border
        "destination_country": "CA",
        "international_carrier": False,
        "fcc_214_authorization": True,
        "cable_landing": False,
        "covered_list_equipment": "",
    }


# ---------------------------------------------------------------------------
# [1-14] FCCCPNIFilter
# ---------------------------------------------------------------------------


class TestFCCCPNIFilter:
    def setup_method(self):
        self.f = FCCCPNIFilter()

    # --- DENIED cases ---

    def test_01_no_cpni_consent_denied(self):
        """47 CFR §64.2007: CPNI without consent → DENIED."""
        doc = {"cpni_consent_obtained": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "64.2007" in r.regulation

    def test_02_cross_category_marketing_no_opt_in_denied(self):
        """47 CFR §64.2005(b): marketing outside existing service without opt-in → DENIED."""
        doc = {
            "cpni_consent_obtained": True,
            "marketing_existing_service": False,
            "cpni_opt_in": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "64.2005" in r.regulation

    def test_03_third_party_disclosure_no_safeguards_denied(self):
        """47 CFR §64.2011: third-party CPNI disclosure without safeguards → DENIED."""
        doc = {
            "cpni_consent_obtained": True,
            "marketing_existing_service": True,
            "third_party_disclosure": True,
            "third_party_safeguards": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "64.2011" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW case ---

    def test_04_cpni_retention_over_2_years_review(self):
        """CPNI retention > 2 years → REQUIRES_HUMAN_REVIEW."""
        doc = {"cpni_consent_obtained": True, "cpni_retention_years": 3}
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "2-Year" in r.regulation or "Retention" in r.regulation

    # --- PERMITTED cases ---

    def test_05_all_compliant_permitted(self):
        """Fully compliant CPNI doc → PERMITTED."""
        doc = _compliant_doc()
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_06_third_party_disclosure_with_safeguards_permitted(self):
        """Third-party disclosure with safeguards → PERMITTED."""
        doc = {
            "cpni_consent_obtained": True,
            "marketing_existing_service": True,
            "third_party_disclosure": True,
            "third_party_safeguards": True,
            "cpni_retention_years": 1,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_07_cross_category_with_opt_in_permitted(self):
        """Cross-category marketing with opt-in consent → PERMITTED."""
        doc = {
            "cpni_consent_obtained": True,
            "marketing_existing_service": False,
            "cpni_opt_in": True,
            "third_party_disclosure": False,
            "cpni_retention_years": 1,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_08_filter_name_correct(self):
        """FCCCPNIFilter sets correct filter_name."""
        doc = _compliant_doc()
        r = self.f.filter(doc)
        assert r.filter_name == "FCCCPNIFilter"

    def test_09_cpni_consent_true_no_denial(self):
        """cpni_consent_obtained=True clears the first check."""
        doc = {"cpni_consent_obtained": True, "marketing_existing_service": True}
        r = self.f.filter(doc)
        assert r.decision != "DENIED" or "64.2007" not in r.regulation

    def test_10_retention_exactly_2_permitted(self):
        """CPNI retention exactly 2 years → PERMITTED (boundary)."""
        doc = {"cpni_consent_obtained": True, "cpni_retention_years": 2}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_11_retention_zero_permitted(self):
        """CPNI retention 0 years → PERMITTED."""
        doc = {"cpni_consent_obtained": True, "cpni_retention_years": 0}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_12_no_third_party_disclosure_skips_safeguards(self):
        """No third-party disclosure means safeguard check is skipped → PERMITTED."""
        doc = {
            "cpni_consent_obtained": True,
            "marketing_existing_service": True,
            "third_party_disclosure": False,
            "third_party_safeguards": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_13_denied_reason_mentions_cpni(self):
        """DENIED reason for no consent mentions CPNI."""
        doc = {"cpni_consent_obtained": False}
        r = self.f.filter(doc)
        assert "CPNI" in r.reason or "cpni" in r.reason.lower()

    def test_14_retention_5_years_review(self):
        """CPNI retention 5 years → REQUIRES_HUMAN_REVIEW."""
        doc = {"cpni_consent_obtained": True, "cpni_retention_years": 5}
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"


# ---------------------------------------------------------------------------
# [15-28] TelecomPrivacyFilter
# ---------------------------------------------------------------------------


class TestTelecomPrivacyFilter:
    def setup_method(self):
        self.f = TelecomPrivacyFilter()

    # --- DENIED cases ---

    def test_15_no_prior_express_consent_denied(self):
        """TCPA §227: automated calls without prior express consent → DENIED."""
        doc = {"prior_express_consent": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "227" in r.regulation

    def test_16_no_dnc_scrubbing_denied(self):
        """47 CFR §64.1200: robocall without DNC scrubbing → DENIED."""
        doc = {"prior_express_consent": True, "do_not_call_scrubbed": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "64.1200" in r.regulation

    def test_17_california_recording_no_two_party_consent_denied(self):
        """CA CPUC GO 107-B: call recording in CA without two-party consent → DENIED."""
        doc = {
            "prior_express_consent": True,
            "do_not_call_scrubbed": True,
            "california_recording": True,
            "two_party_consent": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "107-B" in r.regulation or "Two-Party" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW case ---

    def test_18_text_marketing_no_ctia_compliance_review(self):
        """Text marketing without CTIA compliance → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "prior_express_consent": True,
            "do_not_call_scrubbed": True,
            "california_recording": False,
            "text_marketing": True,
            "ctia_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "CTIA" in r.regulation

    # --- PERMITTED cases ---

    def test_19_all_compliant_permitted(self):
        """Fully compliant privacy doc → PERMITTED."""
        doc = _compliant_doc()
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_20_california_recording_with_two_party_consent_permitted(self):
        """CA recording with two-party consent → PERMITTED."""
        doc = {
            "prior_express_consent": True,
            "do_not_call_scrubbed": True,
            "california_recording": True,
            "two_party_consent": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_21_text_marketing_ctia_compliant_permitted(self):
        """Text marketing with CTIA compliance → PERMITTED."""
        doc = {
            "prior_express_consent": True,
            "do_not_call_scrubbed": True,
            "california_recording": False,
            "text_marketing": True,
            "ctia_compliant": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_22_filter_name_correct(self):
        """TelecomPrivacyFilter sets correct filter_name."""
        doc = _compliant_doc()
        r = self.f.filter(doc)
        assert r.filter_name == "TelecomPrivacyFilter"

    def test_23_no_california_recording_no_two_party_required(self):
        """No CA recording flag means two-party check is skipped."""
        doc = {
            "prior_express_consent": True,
            "do_not_call_scrubbed": True,
            "california_recording": False,
            "two_party_consent": False,
        }
        r = self.f.filter(doc)
        assert r.decision != "DENIED" or "107-B" not in r.regulation

    def test_24_no_text_marketing_skips_ctia(self):
        """No text_marketing flag means CTIA check is skipped."""
        doc = {
            "prior_express_consent": True,
            "do_not_call_scrubbed": True,
            "california_recording": False,
            "text_marketing": False,
            "ctia_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_25_denied_reason_mentions_tcpa(self):
        """DENIED reason for no prior consent mentions TCPA."""
        doc = {"prior_express_consent": False}
        r = self.f.filter(doc)
        assert "TCPA" in r.reason

    def test_26_dnc_denial_reason_mentions_registry(self):
        """DENIED reason for DNC mentions registry."""
        doc = {"prior_express_consent": True, "do_not_call_scrubbed": False}
        r = self.f.filter(doc)
        assert "Do-Not-Call" in r.reason or "DNC" in r.reason

    def test_27_california_denial_reason_mentions_consent(self):
        """DENIED reason for CA recording mentions consent."""
        doc = {
            "prior_express_consent": True,
            "do_not_call_scrubbed": True,
            "california_recording": True,
            "two_party_consent": False,
        }
        r = self.f.filter(doc)
        assert "consent" in r.reason.lower() or "California" in r.reason

    def test_28_text_marketing_review_reason_mentions_ctia(self):
        """REQUIRES_HUMAN_REVIEW reason for text marketing mentions CTIA."""
        doc = {
            "prior_express_consent": True,
            "do_not_call_scrubbed": True,
            "california_recording": False,
            "text_marketing": True,
            "ctia_compliant": False,
        }
        r = self.f.filter(doc)
        assert "CTIA" in r.reason


# ---------------------------------------------------------------------------
# [29-42] FCC911Filter
# ---------------------------------------------------------------------------


class TestFCC911Filter:
    def setup_method(self):
        self.f = FCC911Filter()

    # --- DENIED cases ---

    def test_29_no_voip_e911_routing_denied(self):
        """FCC Order 05-116: VoIP without E911 geographic routing → DENIED."""
        doc = {"voip_e911_routing": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "05-116" in r.regulation

    def test_30_no_wireless_dispatchable_location_denied(self):
        """FCC 20-100: wireless without dispatchable location → DENIED."""
        doc = {"voip_e911_routing": True, "wireless_dispatchable_location": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "20-100" in r.regulation or "RAY BAUM" in r.regulation

    def test_31_mlts_without_karis_law_denied(self):
        """47 U.S.C. §1471: MLTS without Kari's Law compliance → DENIED."""
        doc = {
            "voip_e911_routing": True,
            "wireless_dispatchable_location": True,
            "mlts_system": True,
            "karis_law_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "1471" in r.regulation or "Kari" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW case ---

    def test_32_crisis_line_routing_no_988_compliance_review(self):
        """FCC 21-86: crisis line routing without 988 compliance → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "voip_e911_routing": True,
            "wireless_dispatchable_location": True,
            "mlts_system": False,
            "crisis_line_routing": True,
            "fcc_988_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "21-86" in r.regulation or "988" in r.regulation

    # --- PERMITTED cases ---

    def test_33_all_compliant_permitted(self):
        """Fully compliant 911 doc → PERMITTED."""
        doc = _compliant_doc()
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_34_mlts_with_karis_law_permitted(self):
        """MLTS with Kari's Law compliance → PERMITTED."""
        doc = {
            "voip_e911_routing": True,
            "wireless_dispatchable_location": True,
            "mlts_system": True,
            "karis_law_compliant": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_35_crisis_line_routing_with_988_compliance_permitted(self):
        """Crisis line routing with 988 compliance → PERMITTED."""
        doc = {
            "voip_e911_routing": True,
            "wireless_dispatchable_location": True,
            "mlts_system": False,
            "crisis_line_routing": True,
            "fcc_988_compliant": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_36_filter_name_correct(self):
        """FCC911Filter sets correct filter_name."""
        doc = _compliant_doc()
        r = self.f.filter(doc)
        assert r.filter_name == "FCC911Filter"

    def test_37_no_mlts_skips_karis_law_check(self):
        """No mlts_system flag means Kari's Law check is skipped."""
        doc = {
            "voip_e911_routing": True,
            "wireless_dispatchable_location": True,
            "mlts_system": False,
            "karis_law_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision != "DENIED" or "1471" not in r.regulation

    def test_38_no_crisis_routing_skips_988_check(self):
        """No crisis_line_routing flag means 988 check is skipped."""
        doc = {
            "voip_e911_routing": True,
            "wireless_dispatchable_location": True,
            "mlts_system": False,
            "crisis_line_routing": False,
            "fcc_988_compliant": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_39_voip_denial_reason_mentions_e911(self):
        """DENIED reason for VoIP mentions E911."""
        doc = {"voip_e911_routing": False}
        r = self.f.filter(doc)
        assert "E911" in r.reason or "911" in r.reason

    def test_40_dispatchable_denial_reason_mentions_location(self):
        """DENIED reason for dispatchable location mentions location."""
        doc = {"voip_e911_routing": True, "wireless_dispatchable_location": False}
        r = self.f.filter(doc)
        assert "location" in r.reason.lower() or "dispatchable" in r.reason.lower()

    def test_41_karis_law_denial_reason_mentions_mlts(self):
        """DENIED reason for Kari's Law mentions MLTS."""
        doc = {
            "voip_e911_routing": True,
            "wireless_dispatchable_location": True,
            "mlts_system": True,
            "karis_law_compliant": False,
        }
        r = self.f.filter(doc)
        assert "MLTS" in r.reason or "multi-line" in r.reason.lower()

    def test_42_988_review_reason_mentions_lifeline(self):
        """REQUIRES_HUMAN_REVIEW reason for 988 mentions Lifeline."""
        doc = {
            "voip_e911_routing": True,
            "wireless_dispatchable_location": True,
            "mlts_system": False,
            "crisis_line_routing": True,
            "fcc_988_compliant": False,
        }
        r = self.f.filter(doc)
        assert "Lifeline" in r.reason or "988" in r.reason


# ---------------------------------------------------------------------------
# [43-56] TelecomCrossBorderFilter
# ---------------------------------------------------------------------------


class TestTelecomCrossBorderFilter:
    def setup_method(self):
        self.f = TelecomCrossBorderFilter()

    # --- DENIED cases ---

    def test_43_sanctioned_country_kp_denied(self):
        """OFAC sanctions: telecom service to KP → DENIED."""
        doc = {"destination_country": "KP"}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "OFAC" in r.regulation

    def test_44_international_carrier_no_214_auth_denied(self):
        """47 U.S.C. §214: international carrier without Section 214 auth → DENIED."""
        doc = {
            "destination_country": "DE",
            "international_carrier": True,
            "fcc_214_authorization": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "214" in r.regulation

    def test_45_cable_landing_china_denied(self):
        """47 U.S.C. §35: cable landing to CN without FCC approval → DENIED."""
        doc = {
            "destination_country": "CN",
            "international_carrier": True,
            "fcc_214_authorization": True,
            "cable_landing": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§35" in r.regulation or "Cable" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW case ---

    def test_46_covered_list_equipment_review(self):
        """FCC Covered List: Huawei equipment without waiver → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "destination_country": "US",
            "international_carrier": False,
            "cable_landing": False,
            "covered_list_equipment": "Huawei",
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "Covered" in r.regulation

    # --- PERMITTED cases ---

    def test_47_all_compliant_permitted(self):
        """Fully compliant cross-border doc → PERMITTED."""
        doc = _compliant_doc()
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_48_international_carrier_with_214_auth_permitted(self):
        """International carrier with Section 214 auth → PERMITTED."""
        doc = {
            "destination_country": "GB",
            "international_carrier": True,
            "fcc_214_authorization": True,
            "cable_landing": False,
            "covered_list_equipment": "",
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_49_cable_landing_non_restricted_permitted(self):
        """Cable landing to non-restricted country (DE) → PERMITTED."""
        doc = {
            "destination_country": "DE",
            "international_carrier": True,
            "fcc_214_authorization": True,
            "cable_landing": True,
            "covered_list_equipment": "",
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_50_filter_name_correct(self):
        """TelecomCrossBorderFilter sets correct filter_name."""
        doc = _compliant_doc()
        r = self.f.filter(doc)
        assert r.filter_name == "TelecomCrossBorderFilter"

    def test_51_all_sanctioned_countries_denied(self):
        """All OFAC_TELECOM_SANCTIONED countries produce DENIED."""
        for country in OFAC_TELECOM_SANCTIONED:
            doc = {"destination_country": country}
            r = self.f.filter(doc)
            assert r.decision == "DENIED", f"Expected DENIED for country {country}"

    def test_52_cable_restricted_russia_denied(self):
        """Cable landing to RU → DENIED."""
        doc = {
            "destination_country": "RU",
            "international_carrier": True,
            "fcc_214_authorization": True,
            "cable_landing": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"

    def test_53_covered_list_zte_review(self):
        """ZTE on FCC Covered List → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "destination_country": "US",
            "international_carrier": False,
            "cable_landing": False,
            "covered_list_equipment": "ZTE",
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"

    def test_54_empty_covered_equipment_permitted(self):
        """Empty covered_list_equipment string → not on Covered List → PERMITTED."""
        doc = {
            "destination_country": "CA",
            "international_carrier": False,
            "cable_landing": False,
            "covered_list_equipment": "",
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_55_sanctioned_country_reason_mentions_ofac(self):
        """DENIED reason for sanctioned country mentions OFAC."""
        doc = {"destination_country": "IR"}
        r = self.f.filter(doc)
        assert "OFAC" in r.reason

    def test_56_covered_list_reason_mentions_equipment_name(self):
        """REQUIRES_HUMAN_REVIEW reason mentions equipment vendor name."""
        doc = {
            "destination_country": "US",
            "international_carrier": False,
            "cable_landing": False,
            "covered_list_equipment": "Hikvision",
        }
        r = self.f.filter(doc)
        assert "Hikvision" in r.reason


# ---------------------------------------------------------------------------
# FilterResult and pipeline integration
# ---------------------------------------------------------------------------


class TestFilterResultAndPipeline:
    def test_filter_result_is_denied_true(self):
        """FilterResult.is_denied returns True for DENIED decision."""
        fr = FilterResult(decision="DENIED", regulation="test", reason="test", filter_name="X")
        assert fr.is_denied is True

    def test_filter_result_is_denied_false_for_permitted(self):
        """FilterResult.is_denied returns False for PERMITTED decision."""
        fr = FilterResult(decision="PERMITTED", regulation="test", reason="test", filter_name="X")
        assert fr.is_denied is False

    def test_filter_result_is_denied_false_for_review(self):
        """FilterResult.is_denied returns False for REQUIRES_HUMAN_REVIEW."""
        fr = FilterResult(
            decision="REQUIRES_HUMAN_REVIEW",
            regulation="test",
            reason="test",
            filter_name="X",
        )
        assert fr.is_denied is False

    def test_pipeline_short_circuits_on_denied(self):
        """Pipeline short-circuits after the first DENIED result."""
        doc = {"cpni_consent_obtained": False}  # Layer 1 DENIED
        results = run_pipeline(doc)
        assert len(results) == 1
        assert results[0].decision == "DENIED"

    def test_pipeline_fully_compliant_returns_four_results(self):
        """Fully compliant doc produces four PERMITTED results."""
        doc = _compliant_doc()
        results = run_pipeline(doc)
        assert len(results) == 4
        assert all(r.decision == "PERMITTED" for r in results)

    def test_pipeline_denied_at_layer2_returns_two_results(self):
        """Layer 2 DENIED stops pipeline after two results."""
        doc = _compliant_doc()
        doc["prior_express_consent"] = False  # Layer 2 DENIED
        results = run_pipeline(doc)
        assert len(results) == 2
        assert results[-1].decision == "DENIED"
