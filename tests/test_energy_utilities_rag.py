"""
Tests for Energy and Utilities RAG Pipeline (28_energy_utilities_rag.py).

Covers all four filter layers:
  Layer 1 — NERCCIPFilter          (NERC CIP-004, CIP-005, CIP-011, CIP-013)
  Layer 2 — FERCRegulatoryFilter   (18 CFR §388.112 / §388.113 CEII)
  Layer 3 — DOECybersecurityFilter (DOE Orders 470.4B, 475.1B; CESER guidance)
  Layer 4 — NRCNuclearSecurityFilter (NRC 10 CFR Part 73 Safeguards Info)

Plus end-to-end pipeline tests and audit record tests.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------

_MOD_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "28_energy_utilities_rag.py")


def _load():
    spec = importlib.util.spec_from_file_location(
        "energy_utilities_rag_28",
        _MOD_PATH,
    )
    mod = types.ModuleType("energy_utilities_rag_28")
    sys.modules["energy_utilities_rag_28"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def m():
    return _load()


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _ctx(m, **kwargs):
    """Fully authorized grid operator context — all flags at their permissive values."""
    defaults = dict(
        user_id="USER-001",
        user_role=m.EnergyRole.GRID_OPERATOR,
        facility_id="FAC-001",
        user_cleared_for_cip=True,
        has_need_to_know=True,
        is_authorized_electronic_access=True,
        is_on_site_physical_access=True,
        contractor_agreement_active=True,
        ferc_ceii_authorized=True,
        is_ferc_staff=False,
        doe_clearance_level="classified",
        nrc_safeguards_authorized=True,
        is_nrc_inspector=False,
        is_audit_access=False,
    )
    defaults.update(kwargs)
    return m.EnergyUtilitiesContext(**defaults)


def _doc(m, **kwargs):
    """Default NOT_BES, non-restricted, non-public document."""
    defaults = dict(
        document_id="DOC-001",
        bes_cyber_system_impact=m.BESCyberSystemImpact.NOT_BES,
        is_ceii=False,
        is_ferc_restricted=False,
        is_doe_sensitive=False,
        is_classified=False,
        is_safeguards_info=False,
        is_public=False,
    )
    defaults.update(kwargs)
    return m.EnergyDocument(**defaults)


# ---------------------------------------------------------------------------
# TestNERCCIPFilter — 9 tests
# ---------------------------------------------------------------------------


class TestNERCCIPFilter:

    @pytest.fixture
    def nerc(self, m):
        return m.NERCCIPFilter()

    def test_high_bes_cleared_need_to_know_electronic_access_permitted(self, m, nerc):
        """HIGH BES + cleared + need-to-know + electronic access → PERMITTED."""
        ctx = _ctx(
            m,
            user_cleared_for_cip=True,
            has_need_to_know=True,
            is_authorized_electronic_access=True,
        )
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.HIGH)
        result = nerc.evaluate(ctx, doc)
        assert not result.is_denied

    def test_high_bes_not_cleared_denied(self, m, nerc):
        """HIGH BES + NOT cleared → DENIED (CIP-004-6 R3 PRA required)."""
        ctx = _ctx(m, user_cleared_for_cip=False)
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.HIGH)
        result = nerc.evaluate(ctx, doc)
        assert result.is_denied
        assert "CIP-004" in result.reason or "PRA" in result.reason or "personnel" in result.reason.lower()

    def test_high_bes_cleared_no_need_to_know_denied(self, m, nerc):
        """HIGH BES + cleared + no need-to-know → DENIED (CIP-011-2)."""
        ctx = _ctx(
            m,
            user_cleared_for_cip=True,
            has_need_to_know=False,
            is_authorized_electronic_access=True,
        )
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.HIGH)
        result = nerc.evaluate(ctx, doc)
        assert result.is_denied
        assert "CIP-011" in result.reason or "need-to-know" in result.reason.lower()

    def test_medium_bes_cleared_need_to_know_permitted(self, m, nerc):
        """MEDIUM BES + cleared + need-to-know → PERMITTED."""
        ctx = _ctx(
            m,
            user_cleared_for_cip=True,
            has_need_to_know=True,
        )
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.MEDIUM)
        result = nerc.evaluate(ctx, doc)
        assert not result.is_denied

    def test_medium_bes_not_cleared_denied(self, m, nerc):
        """MEDIUM BES + NOT cleared → DENIED (CIP-004-6 R3)."""
        ctx = _ctx(m, user_cleared_for_cip=False)
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.MEDIUM)
        result = nerc.evaluate(ctx, doc)
        assert result.is_denied
        assert "CIP-004" in result.reason or "PRA" in result.reason

    def test_low_bes_contractor_without_active_agreement_denied(self, m, nerc):
        """LOW BES + CONTRACTOR without active agreement → DENIED (CIP-013-2)."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.CONTRACTOR,
            contractor_agreement_active=False,
        )
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.LOW)
        result = nerc.evaluate(ctx, doc)
        assert result.is_denied
        assert "CIP-013" in result.reason or "contractor" in result.reason.lower()

    def test_low_bes_vendor_without_active_agreement_denied(self, m, nerc):
        """LOW BES + VENDOR without active agreement → DENIED (CIP-013-2)."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.VENDOR,
            contractor_agreement_active=False,
        )
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.LOW)
        result = nerc.evaluate(ctx, doc)
        assert result.is_denied
        assert "CIP-013" in result.reason or "vendor" in result.reason.lower()

    def test_low_bes_grid_operator_not_contractor_permitted(self, m, nerc):
        """LOW BES + GRID_OPERATOR (not contractor/vendor) → PERMITTED regardless of agreement flag."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.GRID_OPERATOR,
            contractor_agreement_active=False,
        )
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.LOW)
        result = nerc.evaluate(ctx, doc)
        assert not result.is_denied

    def test_not_bes_document_permitted(self, m, nerc):
        """NOT_BES document → PERMITTED — NERC CIP does not apply."""
        ctx = _ctx(m)
        doc = _doc(m, bes_cyber_system_impact=m.BESCyberSystemImpact.NOT_BES)
        result = nerc.evaluate(ctx, doc)
        assert not result.is_denied
        assert "not" in result.reason.lower() or "does not apply" in result.reason.lower()


# ---------------------------------------------------------------------------
# TestFERCRegulatoryFilter — 6 tests
# ---------------------------------------------------------------------------


class TestFERCRegulatoryFilter:

    @pytest.fixture
    def ferc(self, m):
        return m.FERCRegulatoryFilter()

    def test_ceii_doc_ferc_authorized_user_permitted(self, m, ferc):
        """CEII doc + FERC CEII NDA on file → PERMITTED (18 CFR §388.113(e))."""
        ctx = _ctx(m, ferc_ceii_authorized=True, is_ferc_staff=False)
        doc = _doc(m, is_ceii=True)
        result = ferc.evaluate(ctx, doc)
        assert not result.is_denied
        assert "388.113" in result.reason or "CEII" in result.reason

    def test_ceii_doc_not_authorized_denied(self, m, ferc):
        """CEII doc + not authorized → DENIED (18 CFR §388.113)."""
        ctx = _ctx(
            m,
            ferc_ceii_authorized=False,
            is_ferc_staff=False,
            user_role=m.EnergyRole.FIELD_TECHNICIAN,
        )
        doc = _doc(m, is_ceii=True)
        result = ferc.evaluate(ctx, doc)
        assert result.is_denied
        assert "388.113" in result.reason or "CEII" in result.reason

    def test_ferc_restricted_ferc_staff_permitted(self, m, ferc):
        """FERC restricted filing + FERC staff → PERMITTED (18 CFR §388.113(d))."""
        ctx = _ctx(m, is_ferc_staff=True)
        doc = _doc(m, is_ferc_restricted=True, is_ceii=False)
        result = ferc.evaluate(ctx, doc)
        assert not result.is_denied
        assert "388.113" in result.reason or "FERC Staff" in result.reason

    def test_ferc_restricted_not_ferc_staff_denied(self, m, ferc):
        """FERC restricted (non-CEII) + not FERC staff + wrong role → DENIED."""
        ctx = _ctx(
            m,
            is_ferc_staff=False,
            user_role=m.EnergyRole.FIELD_TECHNICIAN,
            has_need_to_know=True,
        )
        doc = _doc(m, is_ferc_restricted=True, is_ceii=False)
        result = ferc.evaluate(ctx, doc)
        assert result.is_denied

    def test_non_ceii_non_restricted_permitted(self, m, ferc):
        """Non-CEII, non-restricted doc → PERMITTED — FERC layer does not restrict."""
        ctx = _ctx(m)
        doc = _doc(m, is_ceii=False, is_ferc_restricted=False)
        result = ferc.evaluate(ctx, doc)
        assert not result.is_denied

    def test_regulator_ceii_permitted(self, m, ferc):
        """CEII doc + REGULATOR role → PERMITTED (18 CFR §388.113(d) standing access)."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.REGULATOR,
            ferc_ceii_authorized=False,
            is_ferc_staff=False,
        )
        doc = _doc(m, is_ceii=True)
        result = ferc.evaluate(ctx, doc)
        assert not result.is_denied


# ---------------------------------------------------------------------------
# TestDOECybersecurityFilter — 6 tests
# ---------------------------------------------------------------------------


class TestDOECybersecurityFilter:

    @pytest.fixture
    def doe(self, m):
        return m.DOECybersecurityFilter()

    def test_classified_doc_doe_clearance_permitted(self, m, doe):
        """Classified doc + DOE clearance 'classified' → PERMITTED (DOE O 470.4B)."""
        ctx = _ctx(m, doe_clearance_level="classified")
        doc = _doc(m, is_classified=True)
        result = doe.evaluate(ctx, doc)
        assert not result.is_denied
        assert "Classified" in result.reason or "clearance" in result.reason.lower()

    def test_classified_doc_no_clearance_denied(self, m, doe):
        """Classified doc + no clearance (empty string) → DENIED."""
        ctx = _ctx(
            m,
            doe_clearance_level="",
            user_role=m.EnergyRole.FIELD_TECHNICIAN,
        )
        doc = _doc(m, is_classified=True)
        result = doe.evaluate(ctx, doc)
        assert result.is_denied
        assert "classified" in result.reason.lower() or "clearance" in result.reason.lower()

    def test_doe_sensitive_with_sensitive_clearance_permitted(self, m, doe):
        """DOE sensitive + clearance 'sensitive' → PERMITTED."""
        ctx = _ctx(m, doe_clearance_level="sensitive")
        doc = _doc(m, is_doe_sensitive=True, is_classified=False)
        result = doe.evaluate(ctx, doc)
        assert not result.is_denied

    def test_doe_sensitive_authorized_role_need_to_know_permitted(self, m, doe):
        """DOE sensitive + SECURITY_ANALYST + need-to-know + no clearance → PERMITTED."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.SECURITY_ANALYST,
            doe_clearance_level="",
            has_need_to_know=True,
        )
        doc = _doc(m, is_doe_sensitive=True, is_classified=False)
        result = doe.evaluate(ctx, doc)
        assert not result.is_denied

    def test_doe_sensitive_unauthorized_role_denied(self, m, doe):
        """DOE sensitive + FIELD_TECHNICIAN (not in authorized roles) + no clearance → DENIED."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.FIELD_TECHNICIAN,
            doe_clearance_level="",
            has_need_to_know=True,
        )
        doc = _doc(m, is_doe_sensitive=True, is_classified=False)
        result = doe.evaluate(ctx, doc)
        assert result.is_denied

    def test_non_doe_doc_permitted(self, m, doe):
        """Non-DOE (not sensitive, not classified) doc → PERMITTED."""
        ctx = _ctx(m)
        doc = _doc(m, is_doe_sensitive=False, is_classified=False)
        result = doe.evaluate(ctx, doc)
        assert not result.is_denied


# ---------------------------------------------------------------------------
# TestNRCNuclearSecurityFilter — 6 tests
# ---------------------------------------------------------------------------


class TestNRCNuclearSecurityFilter:

    @pytest.fixture
    def nrc(self, m):
        return m.NRCNuclearSecurityFilter()

    def test_safeguards_info_nrc_authorized_compliance_officer_permitted(self, m, nrc):
        """SGI + NRC authorized COMPLIANCE_OFFICER + need-to-know → PERMITTED (10 CFR 73.21)."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.COMPLIANCE_OFFICER,
            nrc_safeguards_authorized=True,
            has_need_to_know=True,
            is_nrc_inspector=False,
        )
        doc = _doc(m, is_safeguards_info=True)
        result = nrc.evaluate(ctx, doc)
        assert not result.is_denied
        assert "73.21" in result.reason or "SGI" in result.reason

    def test_safeguards_info_nrc_inspector_permitted(self, m, nrc):
        """SGI + NRC inspector → PERMITTED (standing regulatory authority)."""
        ctx = _ctx(
            m,
            is_nrc_inspector=True,
            nrc_safeguards_authorized=False,
        )
        doc = _doc(m, is_safeguards_info=True)
        result = nrc.evaluate(ctx, doc)
        assert not result.is_denied
        assert "inspector" in result.reason.lower() or "73" in result.reason

    def test_safeguards_info_not_authorized_not_inspector_denied(self, m, nrc):
        """SGI + not authorized + not inspector → DENIED (10 CFR 73.21)."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.FIELD_TECHNICIAN,
            nrc_safeguards_authorized=False,
            is_nrc_inspector=False,
            has_need_to_know=True,
        )
        doc = _doc(m, is_safeguards_info=True)
        result = nrc.evaluate(ctx, doc)
        assert result.is_denied
        assert "73.21" in result.reason or "Safeguards" in result.reason

    def test_safeguards_info_regulator_permitted(self, m, nrc):
        """SGI + REGULATOR role → PERMITTED (standing regulatory authority)."""
        ctx = _ctx(
            m,
            user_role=m.EnergyRole.REGULATOR,
            nrc_safeguards_authorized=False,
            is_nrc_inspector=False,
        )
        doc = _doc(m, is_safeguards_info=True)
        result = nrc.evaluate(ctx, doc)
        assert not result.is_denied

    def test_non_safeguards_non_public_permitted(self, m, nrc):
        """Non-safeguards doc (is_safeguards_info=False) → PERMITTED — 10 CFR Part 73 does not restrict."""
        ctx = _ctx(m, user_role=m.EnergyRole.FIELD_TECHNICIAN)
        doc = _doc(m, is_safeguards_info=False, is_public=False)
        result = nrc.evaluate(ctx, doc)
        assert not result.is_denied

    def test_public_doc_permitted(self, m, nrc):
        """Public doc → PERMITTED — NRC safeguards restrictions do not apply."""
        ctx = _ctx(m)
        doc = _doc(m, is_public=True, is_safeguards_info=True)
        result = nrc.evaluate(ctx, doc)
        assert not result.is_denied


# ---------------------------------------------------------------------------
# TestEnergyUtilitiesRAGPipeline — 6 tests
# ---------------------------------------------------------------------------


class TestEnergyUtilitiesRAGPipeline:

    @pytest.fixture
    def pipeline(self, m):
        return m.EnergyUtilitiesRAGPipeline()

    def test_fully_authorized_user_passes_all_layers(self, m, pipeline):
        """Fully authorized context allows a plain non-restricted NOT_BES doc through all four layers."""
        ctx = _ctx(m)
        doc = _doc(m, document_id="DOC-PASS")
        result = pipeline.retrieve(ctx, [doc])
        assert len(result) == 1
        assert result[0].document_id == "DOC-PASS"

    def test_unauthorized_on_high_bes_doc_fails(self, m, pipeline):
        """User without CIP clearance is denied a HIGH BES document at Layer 1."""
        ctx = _ctx(m, user_cleared_for_cip=False)
        doc = _doc(m, document_id="DOC-HIGH", bes_cyber_system_impact=m.BESCyberSystemImpact.HIGH)
        result = pipeline.retrieve(ctx, [doc])
        assert result == []

    def test_retrieve_returns_list(self, m, pipeline):
        """retrieve() always returns a list."""
        ctx = _ctx(m)
        docs = [
            _doc(m, document_id="D-001"),
            _doc(m, document_id="D-002"),
        ]
        result = pipeline.retrieve(ctx, docs)
        assert isinstance(result, list)

    def test_retrieve_with_audit_returns_audit_records(self, m, pipeline):
        """retrieve_with_audit() returns a tuple of (permitted_docs, audit_records)."""
        ctx = _ctx(m)
        doc = _doc(m, document_id="AUDIT-DOC")
        permitted, audit_records = pipeline.retrieve_with_audit(ctx, [doc])
        assert isinstance(permitted, list)
        assert isinstance(audit_records, list)
        assert len(audit_records) == 1
        assert isinstance(audit_records[0], m.EnergyAuditRecord)

    def test_pipeline_has_four_layers(self, m, pipeline):
        """Pipeline must contain exactly four filter layers."""
        assert len(pipeline._layers) == 4

    def test_empty_document_list(self, m, pipeline):
        """Retrieving from an empty document list returns an empty list."""
        ctx = _ctx(m)
        result = pipeline.retrieve(ctx, [])
        assert result == []


# ---------------------------------------------------------------------------
# TestEnergyAuditRecord — 3 tests
# ---------------------------------------------------------------------------


class TestEnergyAuditRecord:

    def _make_record(self, m, decision=None):
        """Build a minimal EnergyAuditRecord for audit log testing."""
        if decision is None:
            decision = m.EnergyDecision.PERMITTED
        return m.EnergyAuditRecord(
            user_id="USER-AUDIT",
            facility_id="FAC-AUDIT",
            document_id="DOC-AUDIT",
            decision=decision,
            layer_results=[
                {
                    "layer": "NERC_CIP_BES_CYBER_SYSTEM",
                    "decision": "permitted",
                    "reason": "ok",
                    "conditions": [],
                }
            ],
        )

    def test_to_audit_log_event_field(self, m):
        """to_audit_log() must return a dict with event = 'ENERGY_RAG_RETRIEVAL'."""
        record = self._make_record(m)
        log = record.to_audit_log()
        assert log["event"] == "ENERGY_RAG_RETRIEVAL"

    def test_to_audit_log_contains_user_and_facility(self, m):
        """Audit log dict includes user_id and facility_id from the record."""
        record = self._make_record(m)
        log = record.to_audit_log()
        assert log["user_id"] == "USER-AUDIT"
        assert log["facility_id"] == "FAC-AUDIT"

    def test_denied_count_via_retrieve_with_audit(self, m):
        """retrieve_with_audit() audit records reflect correct denied/permitted split."""
        pipeline = m.EnergyUtilitiesRAGPipeline()
        ctx = _ctx(m, user_cleared_for_cip=False)
        permitted_doc = _doc(m, document_id="PUB-DOC", is_public=True)
        denied_doc = _doc(
            m,
            document_id="HIGH-DOC",
            bes_cyber_system_impact=m.BESCyberSystemImpact.HIGH,
        )
        permitted, audit_records = pipeline.retrieve_with_audit(ctx, [permitted_doc, denied_doc])
        assert len(permitted) == 1
        assert permitted[0].document_id == "PUB-DOC"
        assert len(audit_records) == 2
        decisions = {r.document_id: r.decision for r in audit_records}
        assert decisions["PUB-DOC"] == m.EnergyDecision.PERMITTED
        assert decisions["HIGH-DOC"] == m.EnergyDecision.DENIED
