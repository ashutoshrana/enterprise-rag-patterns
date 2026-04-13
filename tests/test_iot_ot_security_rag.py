"""
Tests for 42_iot_ot_security_rag.py

Covers NISTIoTFilter, IEC62443OTFilter, TSAOTSecurityFilter,
OTCrossBorderFilter, FilterResult, and the run_pipeline helper.

52 tests total:
  [1-13]  NISTIoTFilter          — 4 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 5 edge
  [14-26] IEC62443OTFilter       — 4 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 5 edge
  [27-38] TSAOTSecurityFilter    — 4 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 4 edge
  [39-50] OTCrossBorderFilter    — 5 DENIED, 1 REQUIRES_HUMAN_REVIEW, 3 PERMITTED, 3 edge
  [51-52] FilterResult + pipeline integration
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

# ---------------------------------------------------------------------------
# Load the example module via importlib
# ---------------------------------------------------------------------------

_MOD_NAME = "iot_ot_security_rag_42"
_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "42_iot_ot_security_rag.py")

spec = importlib.util.spec_from_file_location(_MOD_NAME, _EXAMPLE_PATH)
mod = types.ModuleType(_MOD_NAME)
sys.modules[_MOD_NAME] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Public API
FilterResult = mod.FilterResult
NISTIoTFilter = mod.NISTIoTFilter
IEC62443OTFilter = mod.IEC62443OTFilter
TSAOTSecurityFilter = mod.TSAOTSecurityFilter
OTCrossBorderFilter = mod.OTCrossBorderFilter
run_pipeline = mod.run_pipeline
OFAC_SANCTIONED = mod.OFAC_SANCTIONED


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _compliant_doc() -> dict:
    """A fully compliant IoT/OT document that passes all four layers."""
    return {
        "doc_id": "compliant-001",
        # Layer 1 — NIST IoT
        "is_iot_device": True,
        "device_identity_management": True,
        "configuration_management": True,
        "is_critical_iot": True,
        "network_access_controls": True,
        "crypto_protection_in_transit": True,
        # Layer 2 — IEC 62443
        "is_ot_scada": True,
        "security_level_assessed": True,
        "is_industrial_control_system": True,
        "zone_conduit_model": True,
        "remote_access_to_ot": True,
        "defense_in_depth_remote": True,
        "is_iacs_component": True,
        "patch_management_plan": True,
        # Layer 3 — TSA OT
        "is_critical_pipeline_ot": True,
        "tsa_incident_reporting_capable": True,
        "is_aviation_ot": True,
        "it_ot_network_segmentation": True,
        "is_rail_ot": True,
        "cybersecurity_coordinator_designated": True,
        "is_critical_infrastructure_ot": True,
        "cisa_cpg_ot_met": True,
        # Layer 4 — Cross-border
        "destination_country": "DE",
        "eccn_5e002_classification": False,
        "ot_critical_infrastructure_data": False,
        "cfius_review_completed": False,
        "nis2_essential_entity": False,
        "cross_border_ot_data": False,
        "nca_notification_filed": False,
    }


# ---------------------------------------------------------------------------
# [1-13] NISTIoTFilter
# ---------------------------------------------------------------------------


class TestNISTIoTFilter:
    def setup_method(self):
        self.f = NISTIoTFilter()

    # --- DENIED cases ---

    def test_01_no_device_identity_denied(self):
        """§3.1: IoT device without device_identity_management → DENIED."""
        doc = {"is_iot_device": True, "device_identity_management": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "800-213 §3.1" in r.regulation
        assert r.filter_name == "NISTIoTFilter"

    def test_02_no_configuration_management_denied(self):
        """§3.3: IoT device without configuration_management → DENIED."""
        doc = {
            "is_iot_device": True,
            "device_identity_management": True,
            "configuration_management": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "800-213 §3.3" in r.regulation

    def test_03_critical_iot_no_network_access_controls_denied(self):
        """§3.5: Critical IoT without network_access_controls → DENIED."""
        doc = {
            "is_iot_device": True,
            "device_identity_management": True,
            "configuration_management": True,
            "is_critical_iot": True,
            "network_access_controls": False,
            "crypto_protection_in_transit": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "800-213 §3.5" in r.regulation

    def test_04_identity_check_takes_priority_over_config(self):
        """§3.1 denial fires before §3.3 check."""
        doc = {
            "is_iot_device": True,
            "device_identity_management": False,
            "configuration_management": False,
        }
        r = self.f.filter(doc)
        assert "§3.1" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_05_no_crypto_in_transit_requires_review(self):
        """§3.6: IoT data without crypto_protection_in_transit → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_iot_device": True,
            "device_identity_management": True,
            "configuration_management": True,
            "is_critical_iot": True,
            "network_access_controls": True,
            "crypto_protection_in_transit": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "800-213 §3.6" in r.regulation

    # --- PERMITTED cases ---

    def test_06_fully_compliant_iot_permitted(self):
        """All NIST controls satisfied → PERMITTED."""
        doc = {
            "is_iot_device": True,
            "device_identity_management": True,
            "configuration_management": True,
            "is_critical_iot": True,
            "network_access_controls": True,
            "crypto_protection_in_transit": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"
        assert not r.is_denied

    def test_07_non_iot_document_permitted(self):
        """Non-IoT document (is_iot_device=False) is always PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_08_non_critical_iot_no_network_controls_permitted(self):
        """Non-critical IoT with no network_access_controls but crypto → PERMITTED (§3.5 n/a)."""
        doc = {
            "is_iot_device": True,
            "device_identity_management": True,
            "configuration_management": True,
            "is_critical_iot": False,
            "network_access_controls": False,
            "crypto_protection_in_transit": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_09_empty_dict_permitted(self):
        """Empty document has no IoT flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_10_missing_is_iot_device_key_permitted(self):
        """Missing is_iot_device key defaults to False → PERMITTED."""
        r = self.f.filter({"device_identity_management": False})
        assert r.decision == "PERMITTED"

    def test_11_filter_name_is_nist(self):
        """filter_name field is set correctly."""
        r = self.f.filter({})
        assert r.filter_name == "NISTIoTFilter"

    def test_12_reason_populated_on_denial(self):
        """Denial result must contain a non-empty reason string."""
        doc = {"is_iot_device": True, "device_identity_management": False}
        r = self.f.filter(doc)
        assert isinstance(r.reason, str) and len(r.reason) > 0

    def test_13_is_denied_false_for_review(self):
        """is_denied must be False for REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_iot_device": True,
            "device_identity_management": True,
            "configuration_management": True,
            "is_critical_iot": True,
            "network_access_controls": True,
            "crypto_protection_in_transit": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied


# ---------------------------------------------------------------------------
# [14-26] IEC62443OTFilter
# ---------------------------------------------------------------------------


class TestIEC62443OTFilter:
    def setup_method(self):
        self.f = IEC62443OTFilter()

    # --- DENIED cases ---

    def test_14_ot_scada_no_security_level_denied(self):
        """IEC 62443-3-3 SL-C(1): OT/SCADA without security_level_assessed → DENIED."""
        doc = {"is_ot_scada": True, "security_level_assessed": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "62443-3-3" in r.regulation

    def test_15_ics_no_zone_conduit_model_denied(self):
        """IEC 62443-3-2 §4.3: ICS without zone_conduit_model → DENIED."""
        doc = {
            "is_ot_scada": True,
            "security_level_assessed": True,
            "is_industrial_control_system": True,
            "zone_conduit_model": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "62443-3-2" in r.regulation

    def test_16_remote_ot_no_defense_in_depth_denied(self):
        """IEC 62443-2-4 §SP.04.01: Remote OT access without defense_in_depth_remote → DENIED."""
        doc = {
            "is_ot_scada": True,
            "security_level_assessed": True,
            "is_industrial_control_system": True,
            "zone_conduit_model": True,
            "remote_access_to_ot": True,
            "defense_in_depth_remote": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "62443-2-4" in r.regulation

    def test_17_security_level_check_precedes_zone_conduit(self):
        """IEC 62443-3-3 SL-C(1) denial fires before IEC 62443-3-2 check."""
        doc = {
            "is_ot_scada": True,
            "security_level_assessed": False,
            "is_industrial_control_system": True,
            "zone_conduit_model": False,
        }
        r = self.f.filter(doc)
        assert "62443-3-3" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_18_iacs_no_patch_management_requires_review(self):
        """IEC 62443-2-3 §5.2: IACS without patch_management_plan → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_ot_scada": True,
            "security_level_assessed": True,
            "is_industrial_control_system": True,
            "zone_conduit_model": True,
            "remote_access_to_ot": True,
            "defense_in_depth_remote": True,
            "is_iacs_component": True,
            "patch_management_plan": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "62443-2-3" in r.regulation

    # --- PERMITTED cases ---

    def test_19_fully_compliant_ot_permitted(self):
        """All IEC 62443 controls satisfied → PERMITTED."""
        doc = {
            "is_ot_scada": True,
            "security_level_assessed": True,
            "is_industrial_control_system": True,
            "zone_conduit_model": True,
            "remote_access_to_ot": True,
            "defense_in_depth_remote": True,
            "is_iacs_component": True,
            "patch_management_plan": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_20_non_ot_document_permitted(self):
        """Non-OT document → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_21_no_remote_access_no_defense_check(self):
        """Without remote_access_to_ot, defense-in-depth check is skipped."""
        doc = {
            "is_ot_scada": True,
            "security_level_assessed": True,
            "is_industrial_control_system": True,
            "zone_conduit_model": True,
            "remote_access_to_ot": False,
            "defense_in_depth_remote": False,
            "is_iacs_component": True,
            "patch_management_plan": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_22_empty_dict_permitted(self):
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_23_filter_name_is_iec(self):
        r = self.f.filter({})
        assert r.filter_name == "IEC62443OTFilter"

    def test_24_is_denied_false_for_review(self):
        doc = {
            "is_ot_scada": True,
            "security_level_assessed": True,
            "is_industrial_control_system": True,
            "zone_conduit_model": True,
            "remote_access_to_ot": False,
            "is_iacs_component": True,
            "patch_management_plan": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_25_reason_non_empty_on_denial(self):
        doc = {"is_ot_scada": True, "security_level_assessed": False}
        r = self.f.filter(doc)
        assert r.reason

    def test_26_ics_without_ot_scada_flag_only_conduit_checked(self):
        """is_industrial_control_system alone triggers zone/conduit check."""
        doc = {
            "is_ot_scada": False,
            "is_industrial_control_system": True,
            "zone_conduit_model": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert "62443-3-2" in r.regulation


# ---------------------------------------------------------------------------
# [27-38] TSAOTSecurityFilter
# ---------------------------------------------------------------------------


class TestTSAOTSecurityFilter:
    def setup_method(self):
        self.f = TSAOTSecurityFilter()

    # --- DENIED cases ---

    def test_27_pipeline_no_incident_reporting_denied(self):
        """TSA Pipeline-2021-02C §I: Critical pipeline without incident reporting → DENIED."""
        doc = {"is_critical_pipeline_ot": True, "tsa_incident_reporting_capable": False}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "Pipeline-2021-02C" in r.regulation

    def test_28_aviation_no_segmentation_denied(self):
        """TSA SD 1580/82-2022-01 §E.2: Aviation OT without IT/OT segmentation → DENIED."""
        doc = {
            "is_critical_pipeline_ot": False,
            "is_aviation_ot": True,
            "it_ot_network_segmentation": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "1580/82" in r.regulation
        assert "§E.2" in r.regulation

    def test_29_rail_no_coordinator_denied(self):
        """TSA SD 1580/82-2022-01 §B: Rail OT without cybersecurity coordinator → DENIED."""
        doc = {
            "is_critical_pipeline_ot": False,
            "is_aviation_ot": False,
            "is_rail_ot": True,
            "cybersecurity_coordinator_designated": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "§B" in r.regulation

    def test_30_pipeline_denial_precedes_aviation_check(self):
        """Pipeline incident-reporting denial fires before aviation check."""
        doc = {
            "is_critical_pipeline_ot": True,
            "tsa_incident_reporting_capable": False,
            "is_aviation_ot": True,
            "it_ot_network_segmentation": False,
        }
        r = self.f.filter(doc)
        assert "Pipeline-2021-02C" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_31_critical_infra_no_cpg_requires_review(self):
        """CISA CPG v2.0: Critical infra OT without cisa_cpg_ot_met → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "is_critical_pipeline_ot": False,
            "is_aviation_ot": False,
            "is_rail_ot": False,
            "is_critical_infrastructure_ot": True,
            "cisa_cpg_ot_met": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "CPG" in r.regulation

    # --- PERMITTED cases ---

    def test_32_fully_compliant_ot_permitted(self):
        """All TSA controls satisfied → PERMITTED."""
        doc = {
            "is_critical_pipeline_ot": True,
            "tsa_incident_reporting_capable": True,
            "is_aviation_ot": True,
            "it_ot_network_segmentation": True,
            "is_rail_ot": True,
            "cybersecurity_coordinator_designated": True,
            "is_critical_infrastructure_ot": True,
            "cisa_cpg_ot_met": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_33_non_tsa_document_permitted(self):
        """Document with no TSA-relevant flags → PERMITTED."""
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_34_non_critical_infra_no_cpg_check(self):
        """Without is_critical_infrastructure_ot, CPG check is skipped."""
        doc = {
            "is_critical_infrastructure_ot": False,
            "cisa_cpg_ot_met": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_35_empty_dict_permitted(self):
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_36_filter_name_is_tsa(self):
        r = self.f.filter({})
        assert r.filter_name == "TSAOTSecurityFilter"

    def test_37_is_denied_false_for_review(self):
        doc = {
            "is_critical_infrastructure_ot": True,
            "cisa_cpg_ot_met": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied

    def test_38_reason_populated_on_denial(self):
        doc = {"is_critical_pipeline_ot": True, "tsa_incident_reporting_capable": False}
        r = self.f.filter(doc)
        assert r.reason


# ---------------------------------------------------------------------------
# [39-50] OTCrossBorderFilter
# ---------------------------------------------------------------------------


class TestOTCrossBorderFilter:
    def setup_method(self):
        self.f = OTCrossBorderFilter()

    # --- DENIED cases ---

    def test_39_ofac_russia_denied(self):
        """OFAC: destination_country='RU' → DENIED."""
        doc = {"destination_country": "RU"}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "OFAC" in r.regulation

    def test_40_ofac_iran_denied(self):
        """OFAC: destination_country='IR' → DENIED."""
        doc = {"destination_country": "IR"}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied

    def test_41_ofac_north_korea_denied(self):
        """OFAC: destination_country='KP' → DENIED."""
        doc = {"destination_country": "KP"}
        r = self.f.filter(doc)
        assert r.decision == "DENIED"

    def test_42_eccn_5e002_no_licence_denied(self):
        """EAR ECCN 5E002: ICS export without ear_export_licence → DENIED."""
        doc = {
            "destination_country": "IN",
            "eccn_5e002_classification": True,
            "ear_export_licence": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "5E002" in r.regulation

    def test_43_china_ot_critical_infra_no_cfius_denied(self):
        """CFIUS: OT critical infra data to CN without cfius_review_completed → DENIED."""
        doc = {
            "destination_country": "CN",
            "ot_critical_infrastructure_data": True,
            "cfius_review_completed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "DENIED"
        assert r.is_denied
        assert "CFIUS" in r.regulation

    # --- REQUIRES_HUMAN_REVIEW ---

    def test_44_nis2_essential_cross_border_no_nca_requires_review(self):
        """NIS2 Art. 26: NIS2 essential entity cross-border OT without NCA notification → REQUIRES_HUMAN_REVIEW."""
        doc = {
            "destination_country": "FR",
            "nis2_essential_entity": True,
            "cross_border_ot_data": True,
            "nca_notification_filed": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "REQUIRES_HUMAN_REVIEW"
        assert not r.is_denied
        assert "NIS2" in r.regulation

    # --- PERMITTED cases ---

    def test_45_germany_no_controls_triggered_permitted(self):
        """Export to DE with no special controls → PERMITTED."""
        doc = {"destination_country": "DE"}
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_46_china_no_critical_infra_data_permitted(self):
        """China destination but ot_critical_infrastructure_data=False → PERMITTED."""
        doc = {
            "destination_country": "CN",
            "ot_critical_infrastructure_data": False,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    def test_47_eccn_classified_with_licence_permitted(self):
        """ECCN 5E002 with ear_export_licence=True → PERMITTED."""
        doc = {
            "destination_country": "JP",
            "eccn_5e002_classification": True,
            "ear_export_licence": True,
        }
        r = self.f.filter(doc)
        assert r.decision == "PERMITTED"

    # --- Edge cases ---

    def test_48_empty_dict_permitted(self):
        r = self.f.filter({})
        assert r.decision == "PERMITTED"

    def test_49_filter_name_is_cross_border(self):
        r = self.f.filter({})
        assert r.filter_name == "OTCrossBorderFilter"

    def test_50_all_five_ofac_countries_denied(self):
        """All five OFAC-sanctioned countries (RU/IR/KP/CU/SY) produce DENIED."""
        for country in ("RU", "IR", "KP", "CU", "SY"):
            r = self.f.filter({"destination_country": country})
            assert r.decision == "DENIED", f"Expected DENIED for {country}"
            assert r.is_denied


# ---------------------------------------------------------------------------
# [51-52] FilterResult correctness + cross-filter pipeline integration
# ---------------------------------------------------------------------------


class TestFilterResultAndPipeline:
    def test_51_is_denied_only_for_denied_decision(self):
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
                reason="test",
                filter_name="TestFilter",
            )
            assert r.is_denied is expected, f"is_denied wrong for decision={decision!r}"

    def test_52_compliant_doc_passes_all_four_layers(self):
        """A fully compliant document must pass all four filters with PERMITTED."""
        doc = _compliant_doc()
        results = run_pipeline(doc)
        assert len(results) == 4
        for r in results:
            assert r.decision == "PERMITTED", f"Expected PERMITTED from {r.filter_name}, got {r.decision}: {r.reason}"
            assert not r.is_denied
