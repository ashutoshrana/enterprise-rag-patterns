"""Tests for 21_energy_utilities_rag.py — NERC CIP + FERC Order 2222 + NRC 10 CFR Part 73"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------


def _load_module(name: str):
    examples_dir = Path(__file__).parent.parent / "examples"
    spec = importlib.util.spec_from_file_location(name, examples_dir / "21_energy_utilities_rag.py")
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def m():
    return _load_module("energy_utilities_rag")


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _ctx(m, **kwargs):
    defaults = dict(
        personnel_id="OPS-001",
        cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
        nerc_training_current=True,
        authorized_asset_ids=(),
        market_participant_certified=False,
        nuclear_clearance=False,
        control_area_type=m.ControlAreaType.TRANSMISSION,
    )
    defaults.update(kwargs)
    return m.EnergyAccessContext(**defaults)


def _doc(m, **kwargs):
    defaults = dict(
        doc_id="DOC-001",
        category=m.EnergyDocumentCategory.MAINTENANCE_PROCEDURE,
        title="Test Document",
        impact_level=m.BESCyberSystemImpactLevel.NOT_APPLICABLE,
        bcsi_classification=False,
        is_nuclear_safety_system=False,
        requires_q_clearance=False,
        market_sensitive=False,
        asset_id="",
        is_public=False,
    )
    defaults.update(kwargs)
    return m.EnergyDocument(**defaults)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TestEnumerations:
    def test_bes_impact_levels(self, m):
        levels = [m.BESCyberSystemImpactLevel.HIGH, m.BESCyberSystemImpactLevel.MEDIUM,
                  m.BESCyberSystemImpactLevel.LOW, m.BESCyberSystemImpactLevel.NOT_APPLICABLE]
        assert len(set(levels)) == 4

    def test_nerc_access_levels(self, m):
        levels = [m.NERCCIPAccessLevel.OPERATIONAL, m.NERCCIPAccessLevel.INFORMATIONAL,
                  m.NERCCIPAccessLevel.PUBLIC]
        assert len(set(levels)) == 3

    def test_document_categories_count(self, m):
        # 20 document categories (5 BCSI + 4 operational + 5 market + 4 nuclear + 2 public)
        cats = list(m.EnergyDocumentCategory)
        assert len(cats) == 20

    def test_control_area_types(self, m):
        types_ = [m.ControlAreaType.TRANSMISSION, m.ControlAreaType.GENERATION,
                  m.ControlAreaType.DISTRIBUTION, m.ControlAreaType.NUCLEAR,
                  m.ControlAreaType.MARKET]
        assert len(set(types_)) == 5


# ---------------------------------------------------------------------------
# NERCCIPFilter
# ---------------------------------------------------------------------------


class TestNERCCIPFilter:
    def test_public_doc_always_permitted(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="PUB-001", category=m.EnergyDocumentCategory.PUBLIC_NOTICE, is_public=True)
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.PUBLIC, nerc_training_current=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted
        assert not reasons

    def test_bcsi_blocked_for_public_access_level(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="SCADA-001", category=m.EnergyDocumentCategory.SCADA_CONFIG,
                   bcsi_classification=True, impact_level=m.BESCyberSystemImpactLevel.HIGH,
                   asset_id="BES-001")
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.PUBLIC, nerc_training_current=True)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("CIP-011-3" in r for r in reasons)

    def test_bcsi_blocked_for_lapsed_training(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="SCADA-002", category=m.EnergyDocumentCategory.SCADA_CONFIG,
                   bcsi_classification=True, impact_level=m.BESCyberSystemImpactLevel.HIGH,
                   asset_id="BES-001")
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
                   nerc_training_current=False)  # Lapsed training
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("CIP-004-7" in r for r in reasons)

    def test_high_impact_requires_operational_access(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="SCADA-003", category=m.EnergyDocumentCategory.SCADA_CONFIG,
                   bcsi_classification=True, impact_level=m.BESCyberSystemImpactLevel.HIGH,
                   asset_id="BES-001")
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.INFORMATIONAL,
                   nerc_training_current=True)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("CIP-007-7" in r for r in reasons)

    def test_medium_impact_requires_operational_access(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="NET-001", category=m.EnergyDocumentCategory.NETWORK_DIAGRAM,
                   bcsi_classification=True, impact_level=m.BESCyberSystemImpactLevel.MEDIUM,
                   asset_id="BES-CC-001")
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.INFORMATIONAL,
                   nerc_training_current=True)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("MEDIUM" in r for r in reasons)

    def test_operational_with_training_permits_high_bcsi(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="SCADA-004", category=m.EnergyDocumentCategory.SCADA_CONFIG,
                   bcsi_classification=True, impact_level=m.BESCyberSystemImpactLevel.HIGH,
                   asset_id="BES-TRANS-044")
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
                   nerc_training_current=True,
                   authorized_asset_ids=("BES-TRANS-044",))
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted
        assert not reasons

    def test_asset_authorization_required(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="SCADA-005", category=m.EnergyDocumentCategory.SCADA_CONFIG,
                   bcsi_classification=True, impact_level=m.BESCyberSystemImpactLevel.HIGH,
                   asset_id="BES-TRANS-999")
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
                   nerc_training_current=True,
                   authorized_asset_ids=("BES-TRANS-001",))  # Different asset
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("EAL" in r or "Electronic Access List" in r for r in reasons)

    def test_non_bcsi_blocked_for_public_access(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="MAINT-001", category=m.EnergyDocumentCategory.MAINTENANCE_PROCEDURE,
                   bcsi_classification=False, asset_id="")
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.PUBLIC)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("PUBLIC" in r for r in reasons)

    def test_non_bcsi_permitted_for_informational_access(self, m):
        f = m.NERCCIPFilter()
        doc = _doc(m, doc_id="MAINT-002", category=m.EnergyDocumentCategory.MAINTENANCE_PROCEDURE,
                   bcsi_classification=False, asset_id="")
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.INFORMATIONAL,
                   nerc_training_current=True)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted

    def test_bcsi_categories_set_contents(self, m):
        f = m.NERCCIPFilter()
        assert m.EnergyDocumentCategory.SCADA_CONFIG in f._BCSI_CATEGORIES
        assert m.EnergyDocumentCategory.PROTECTION_SCHEME in f._BCSI_CATEGORIES
        assert m.EnergyDocumentCategory.NETWORK_DIAGRAM in f._BCSI_CATEGORIES
        assert m.EnergyDocumentCategory.CYBER_SECURITY_PLAN in f._BCSI_CATEGORIES
        assert m.EnergyDocumentCategory.ACCESS_CONTROL_LIST in f._BCSI_CATEGORIES
        assert m.EnergyDocumentCategory.MAINTENANCE_PROCEDURE not in f._BCSI_CATEGORIES


# ---------------------------------------------------------------------------
# FERCOrder2222Filter
# ---------------------------------------------------------------------------


class TestFERCOrder2222Filter:
    def test_public_ferc_filing_always_permitted(self, m):
        f = m.FERCOrder2222Filter()
        doc = _doc(m, doc_id="FERC-001", category=m.EnergyDocumentCategory.FERC_FILING,
                   is_public=True)
        ctx = _ctx(m, market_participant_certified=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted
        assert not reasons

    def test_public_market_report_always_permitted(self, m):
        f = m.FERCOrder2222Filter()
        doc = _doc(m, doc_id="MKT-RPT-001", category=m.EnergyDocumentCategory.MARKET_REPORT_PUBLIC,
                   is_public=True)
        ctx = _ctx(m, market_participant_certified=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted

    def test_der_dispatch_blocked_without_certification(self, m):
        f = m.FERCOrder2222Filter()
        doc = _doc(m, doc_id="DER-001", category=m.EnergyDocumentCategory.DER_DISPATCH_CURVE,
                   market_sensitive=True)
        ctx = _ctx(m, market_participant_certified=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("FERC" in r and "2222" in r for r in reasons)

    def test_market_bid_data_blocked_without_certification(self, m):
        f = m.FERCOrder2222Filter()
        doc = _doc(m, doc_id="BID-001", category=m.EnergyDocumentCategory.MARKET_BID_DATA,
                   market_sensitive=True)
        ctx = _ctx(m, market_participant_certified=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted

    def test_capacity_position_blocked_without_certification(self, m):
        f = m.FERCOrder2222Filter()
        doc = _doc(m, doc_id="CAP-001", category=m.EnergyDocumentCategory.CAPACITY_POSITION,
                   market_sensitive=True)
        ctx = _ctx(m, market_participant_certified=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted

    def test_market_data_permitted_with_certification(self, m):
        f = m.FERCOrder2222Filter()
        doc = _doc(m, doc_id="DER-002", category=m.EnergyDocumentCategory.DER_DISPATCH_CURVE,
                   market_sensitive=True)
        ctx = _ctx(m, market_participant_certified=True)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted
        assert not reasons

    def test_market_sensitive_flag_blocked_without_certification(self, m):
        f = m.FERCOrder2222Filter()
        doc = _doc(m, doc_id="SENS-001", category=m.EnergyDocumentCategory.OPERATOR_LOG,
                   market_sensitive=True)
        ctx = _ctx(m, market_participant_certified=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("market" in r.lower() for r in reasons)

    def test_non_market_doc_permitted_without_certification(self, m):
        f = m.FERCOrder2222Filter()
        doc = _doc(m, doc_id="LOG-001", category=m.EnergyDocumentCategory.OPERATOR_LOG,
                   market_sensitive=False)
        ctx = _ctx(m, market_participant_certified=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted


# ---------------------------------------------------------------------------
# NRCCybersecurityFilter
# ---------------------------------------------------------------------------


class TestNRCCybersecurityFilter:
    def test_public_doc_always_permitted(self, m):
        f = m.NRCCybersecurityFilter()
        doc = _doc(m, doc_id="PUB-001", category=m.EnergyDocumentCategory.PUBLIC_NOTICE,
                   is_public=True)
        ctx = _ctx(m, nuclear_clearance=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted

    def test_nuclear_safety_system_blocked_without_clearance(self, m):
        f = m.NRCCybersecurityFilter()
        doc = _doc(m, doc_id="NUC-001", category=m.EnergyDocumentCategory.NUCLEAR_SAFETY_SYSTEM,
                   is_nuclear_safety_system=True, requires_q_clearance=True)
        ctx = _ctx(m, nuclear_clearance=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted
        assert any("73.54" in r or "Q-level" in r.lower() or "nuclear" in r.lower() for r in reasons)

    def test_nuclear_safety_system_permitted_with_clearance(self, m):
        f = m.NRCCybersecurityFilter()
        doc = _doc(m, doc_id="NUC-002", category=m.EnergyDocumentCategory.NUCLEAR_SAFETY_SYSTEM,
                   is_nuclear_safety_system=True, requires_q_clearance=True)
        ctx = _ctx(m, nuclear_clearance=True)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted

    def test_q_clearance_required_flag_blocks_without_clearance(self, m):
        f = m.NRCCybersecurityFilter()
        doc = _doc(m, doc_id="NUC-003", category=m.EnergyDocumentCategory.CRITICAL_DIGITAL_ASSET,
                   requires_q_clearance=True, is_nuclear_safety_system=False)
        ctx = _ctx(m, nuclear_clearance=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted

    def test_critical_digital_asset_category_blocked_without_clearance(self, m):
        f = m.NRCCybersecurityFilter()
        doc = _doc(m, doc_id="CDA-001", category=m.EnergyDocumentCategory.CRITICAL_DIGITAL_ASSET)
        ctx = _ctx(m, nuclear_clearance=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted

    def test_emergency_procedure_blocked_without_clearance(self, m):
        f = m.NRCCybersecurityFilter()
        doc = _doc(m, doc_id="EMRG-001", category=m.EnergyDocumentCategory.EMERGENCY_PROCEDURE)
        ctx = _ctx(m, nuclear_clearance=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted

    def test_security_plan_nuclear_blocked_without_clearance(self, m):
        f = m.NRCCybersecurityFilter()
        doc = _doc(m, doc_id="SEC-001", category=m.EnergyDocumentCategory.SECURITY_PLAN_NUCLEAR)
        ctx = _ctx(m, nuclear_clearance=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc not in permitted

    def test_non_nuclear_doc_passes_without_clearance(self, m):
        f = m.NRCCybersecurityFilter()
        doc = _doc(m, doc_id="MAINT-001", category=m.EnergyDocumentCategory.MAINTENANCE_PROCEDURE)
        ctx = _ctx(m, nuclear_clearance=False)
        permitted, reasons = f.filter([doc], ctx)
        assert doc in permitted

    def test_nuclear_restricted_categories_set(self, m):
        f = m.NRCCybersecurityFilter()
        assert m.EnergyDocumentCategory.NUCLEAR_SAFETY_SYSTEM in f._NUCLEAR_RESTRICTED_CATEGORIES
        assert m.EnergyDocumentCategory.CRITICAL_DIGITAL_ASSET in f._NUCLEAR_RESTRICTED_CATEGORIES
        assert m.EnergyDocumentCategory.SECURITY_PLAN_NUCLEAR in f._NUCLEAR_RESTRICTED_CATEGORIES
        assert m.EnergyDocumentCategory.EMERGENCY_PROCEDURE in f._NUCLEAR_RESTRICTED_CATEGORIES


# ---------------------------------------------------------------------------
# EnergyComplianceAuditRecord
# ---------------------------------------------------------------------------


class TestEnergyComplianceAuditRecord:
    def test_to_cip_audit_log_structure(self, m):
        record = m.EnergyComplianceAuditRecord(
            audit_id="AUD-001",
            personnel_id="OPS-001",
            control_area_type=m.ControlAreaType.TRANSMISSION,
            cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
            training_current=True,
            nuclear_clearance=False,
            market_certified=False,
            documents_requested=5,
            documents_permitted=3,
            nerc_blocks=["NERC block 1"],
            ferc_blocks=[],
            nrc_blocks=[],
            permitted_doc_ids=["DOC-A", "DOC-B", "DOC-C"],
        )
        log = record.to_cip_audit_log()
        assert log["audit_id"] == "AUD-001"
        assert log["personnel_id"] == "OPS-001"
        assert log["requested"] == 5
        assert log["permitted"] == 3
        assert log["nerc_blocks"] == 1
        assert log["ferc_blocks"] == 0
        assert log["nrc_blocks"] == 0
        assert len(log["permitted_docs"]) == 3

    def test_to_cip_audit_log_fields(self, m):
        record = m.EnergyComplianceAuditRecord(
            audit_id="AUD-002",
            personnel_id="NUC-001",
            control_area_type=m.ControlAreaType.NUCLEAR,
            cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
            training_current=True,
            nuclear_clearance=True,
            market_certified=False,
            documents_requested=10,
            documents_permitted=8,
            nerc_blocks=[],
            ferc_blocks=[],
            nrc_blocks=["NRC block 1", "NRC block 2"],
            permitted_doc_ids=["A", "B", "C", "D", "E", "F", "G", "H"],
        )
        log = record.to_cip_audit_log()
        assert log["nuclear_clearance"] is True
        assert log["training_current"] is True
        assert log["control_area"] == "NUCLEAR"


# ---------------------------------------------------------------------------
# EnergyRAGPipeline
# ---------------------------------------------------------------------------


class TestEnergyRAGPipeline:
    def _build_kb(self, m):
        return [
            _doc(m, doc_id="SCADA-001", category=m.EnergyDocumentCategory.SCADA_CONFIG,
                 bcsi_classification=True, impact_level=m.BESCyberSystemImpactLevel.HIGH,
                 asset_id="BES-TRANS-044"),
            _doc(m, doc_id="DER-001", category=m.EnergyDocumentCategory.DER_DISPATCH_CURVE,
                 market_sensitive=True),
            _doc(m, doc_id="NUC-001", category=m.EnergyDocumentCategory.NUCLEAR_SAFETY_SYSTEM,
                 is_nuclear_safety_system=True, requires_q_clearance=True),
            _doc(m, doc_id="PUB-001", category=m.EnergyDocumentCategory.PUBLIC_NOTICE,
                 is_public=True),
        ]

    def test_pipeline_layers_execute_in_order(self, m):
        pipeline = m.EnergyRAGPipeline()
        kb = self._build_kb(m)
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
                   nerc_training_current=True, authorized_asset_ids=("BES-TRANS-044",),
                   nuclear_clearance=True, market_participant_certified=True)
        permitted, audit = pipeline.retrieve(kb, ctx)
        # All docs should be permitted for fully authorized user
        assert len(permitted) == 4

    def test_scenario_a_control_room_operator(self, m):
        """Authorized operator gets SCADA docs, not market or nuclear docs."""
        pipeline = m.EnergyRAGPipeline()
        kb = self._build_kb(m)
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
                   nerc_training_current=True, authorized_asset_ids=("BES-TRANS-044",),
                   nuclear_clearance=False, market_participant_certified=False)
        permitted, audit = pipeline.retrieve(kb, ctx)
        ids = {d.doc_id for d in permitted}
        assert "SCADA-001" in ids   # NERC OK
        assert "DER-001" not in ids  # FERC block
        assert "NUC-001" not in ids  # NRC block
        assert "PUB-001" in ids     # Public

    def test_scenario_b_public_vendor_blocked_from_bcsi(self, m):
        """PUBLIC access level gets only public docs."""
        pipeline = m.EnergyRAGPipeline()
        kb = self._build_kb(m)
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.PUBLIC,
                   nerc_training_current=False, nuclear_clearance=False,
                   market_participant_certified=False)
        permitted, audit = pipeline.retrieve(kb, ctx)
        ids = {d.doc_id for d in permitted}
        assert "SCADA-001" not in ids
        assert "PUB-001" in ids
        assert audit.documents_permitted < audit.documents_requested

    def test_scenario_c_market_analyst_no_certification(self, m):
        """Market analyst without certification cannot access DER dispatch curves."""
        pipeline = m.EnergyRAGPipeline()
        kb = self._build_kb(m)
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.INFORMATIONAL,
                   nerc_training_current=True, market_participant_certified=False)
        permitted, audit = pipeline.retrieve(kb, ctx)
        ids = {d.doc_id for d in permitted}
        assert "DER-001" not in ids
        assert len(audit.ferc_blocks) > 0

    def test_scenario_d_nuclear_admin_with_clearance(self, m):
        """Q-cleared nuclear admin gets nuclear docs."""
        pipeline = m.EnergyRAGPipeline()
        kb = self._build_kb(m)
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
                   nerc_training_current=True, authorized_asset_ids=("BES-TRANS-044",),
                   nuclear_clearance=True, market_participant_certified=False)
        permitted, audit = pipeline.retrieve(kb, ctx)
        ids = {d.doc_id for d in permitted}
        assert "NUC-001" in ids
        assert len(audit.nrc_blocks) == 0

    def test_audit_record_counts_correct(self, m):
        pipeline = m.EnergyRAGPipeline()
        kb = self._build_kb(m)
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.PUBLIC,
                   nerc_training_current=False)
        permitted, audit = pipeline.retrieve(kb, ctx)
        assert audit.documents_requested == len(kb)
        assert audit.documents_permitted == len(permitted)
        assert audit.personnel_id == "OPS-001"

    def test_audit_record_has_audit_id(self, m):
        pipeline = m.EnergyRAGPipeline()
        _, audit = pipeline.retrieve([], _ctx(m))
        assert audit.audit_id
        assert len(audit.audit_id) > 0

    def test_empty_document_list(self, m):
        pipeline = m.EnergyRAGPipeline()
        ctx = _ctx(m)
        permitted, audit = pipeline.retrieve([], ctx)
        assert permitted == []
        assert audit.documents_requested == 0
        assert audit.documents_permitted == 0

    def test_pipeline_has_three_layers(self, m):
        pipeline = m.EnergyRAGPipeline()
        assert hasattr(pipeline, "_nerc")
        assert hasattr(pipeline, "_ferc")
        assert hasattr(pipeline, "_nrc")

    def test_nerc_blocks_propagate_to_audit(self, m):
        pipeline = m.EnergyRAGPipeline()
        docs = [
            _doc(m, doc_id="BCSI-001", category=m.EnergyDocumentCategory.SCADA_CONFIG,
                 bcsi_classification=True, impact_level=m.BESCyberSystemImpactLevel.HIGH,
                 asset_id="BES-001"),
        ]
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.PUBLIC)
        _, audit = pipeline.retrieve(docs, ctx)
        assert len(audit.nerc_blocks) > 0

    def test_ferc_blocks_propagate_to_audit(self, m):
        pipeline = m.EnergyRAGPipeline()
        docs = [
            _doc(m, doc_id="DER-001", category=m.EnergyDocumentCategory.DER_DISPATCH_CURVE,
                 market_sensitive=True),
        ]
        ctx = _ctx(m, cip_access_level=m.NERCCIPAccessLevel.OPERATIONAL,
                   nerc_training_current=True, market_participant_certified=False)
        _, audit = pipeline.retrieve(docs, ctx)
        assert len(audit.ferc_blocks) > 0

    def test_nrc_blocks_propagate_to_audit(self, m):
        pipeline = m.EnergyRAGPipeline()
        docs = [
            _doc(m, doc_id="NUC-001", category=m.EnergyDocumentCategory.NUCLEAR_SAFETY_SYSTEM,
                 is_nuclear_safety_system=True, requires_q_clearance=True),
        ]
        ctx = _ctx(m, nuclear_clearance=False)
        _, audit = pipeline.retrieve(docs, ctx)
        assert len(audit.nrc_blocks) > 0
