"""
Tests for Government and Public Sector RAG Pipeline (29_government_public_sector_rag.py).

Covers all four filter layers:
  Layer 1 — FedRAMPAuthorizationFilter  (FedRAMP impact levels + ATO validation)
  Layer 2 — FISMASecurityControlFilter  (NIST SP 800-53 AC-3/AC-4/PS-3)
  Layer 3 — CUIMarkingFilter            (32 CFR Part 2002, Privacy Act, EAR/ITAR)
  Layer 4 — GovernmentAuditFilter       (AU-9 + IG Act + Congressional oversight)

Plus end-to-end pipeline tests and audit record tests.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Module loading (frozen dataclasses — must use spec_from_file_location)
# ---------------------------------------------------------------------------


def _load():
    spec = importlib.util.spec_from_file_location(
        "gov_rag_29",
        os.path.join(os.path.dirname(__file__), "..", "examples", "29_government_public_sector_rag.py"),
    )
    mod = types.ModuleType("gov_rag_29")
    sys.modules["gov_rag_29"] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load()


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _ctx(**overrides):
    """Fully authorized federal employee — all permissive defaults."""
    defaults = dict(
        user_id="u1",
        user_role=mod.GovernmentRole.FEDERAL_EMPLOYEE,
        agency_id="DOJ",
        fedramp_authorization_level=mod.FedRAMPImpactLevel.HIGH,
        has_background_investigation=True,
        has_security_clearance=True,
        is_need_to_know=True,
        is_us_person=True,
        has_privacy_act_training=True,
        is_law_enforcement=False,
        is_on_authorized_system=True,
        contractor_agreement_active=False,
        fisma_system_category="HIGH",
        has_ato=True,
        is_ig_oversight=False,
        is_congressional_oversight=False,
    )
    defaults.update(overrides)
    return mod.GovernmentRAGContext(**defaults)


def _doc(**overrides):
    """Default HIGH FedRAMP, FOUO, non-PII, non-public document."""
    defaults = dict(
        document_id="d1",
        fedramp_required_level=mod.FedRAMPImpactLevel.HIGH,
        cui_category=mod.CUICategory.FOUO,
        contains_pii=False,
        is_law_enforcement_sensitive=False,
        is_export_controlled=False,
        is_classified=False,
        is_public_release_approved=False,
    )
    defaults.update(overrides)
    return mod.GovernmentDocument(**defaults)


# ---------------------------------------------------------------------------
# TestFedRAMPAuthorizationFilter — 9 tests
# ---------------------------------------------------------------------------


class TestFedRAMPAuthorizationFilter:
    @pytest.fixture
    def fedramp(self):
        return mod.FedRAMPAuthorizationFilter()

    def test_classified_doc_denied(self, fedramp):
        """Classified document → DENIED — not handled by this pipeline."""
        ctx = _ctx()
        doc = _doc(is_classified=True)
        result = fedramp.evaluate(ctx, doc)
        assert result.is_denied

    def test_high_doc_moderate_auth_denied(self, fedramp):
        """HIGH doc + MODERATE authorization level → DENIED."""
        ctx = _ctx(fedramp_authorization_level=mod.FedRAMPImpactLevel.MODERATE)
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = fedramp.evaluate(ctx, doc)
        assert result.is_denied

    def test_high_doc_low_auth_denied(self, fedramp):
        """HIGH doc + LOW authorization level → DENIED."""
        ctx = _ctx(fedramp_authorization_level=mod.FedRAMPImpactLevel.LOW)
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = fedramp.evaluate(ctx, doc)
        assert result.is_denied

    def test_moderate_doc_low_auth_denied(self, fedramp):
        """MODERATE doc + LOW authorization level → DENIED."""
        ctx = _ctx(fedramp_authorization_level=mod.FedRAMPImpactLevel.LOW)
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.MODERATE)
        result = fedramp.evaluate(ctx, doc)
        assert result.is_denied

    def test_not_on_authorized_system_fedramp_doc_denied(self, fedramp):
        """FedRAMP-required doc + user not on authorized system → DENIED."""
        ctx = _ctx(is_on_authorized_system=False)
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = fedramp.evaluate(ctx, doc)
        assert result.is_denied

    def test_no_ato_denied(self, fedramp):
        """System without ATO → DENIED regardless of impact level."""
        ctx = _ctx(has_ato=False)
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = fedramp.evaluate(ctx, doc)
        assert result.is_denied

    def test_high_doc_high_auth_on_system_with_ato_permitted(self, fedramp):
        """HIGH doc + HIGH auth + on authorized system + ATO → PERMITTED."""
        ctx = _ctx(
            fedramp_authorization_level=mod.FedRAMPImpactLevel.HIGH,
            is_on_authorized_system=True,
            has_ato=True,
        )
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = fedramp.evaluate(ctx, doc)
        assert not result.is_denied

    def test_not_fedramp_doc_not_on_authorized_system_permitted(self, fedramp):
        """NOT_FEDRAMP doc + not on authorized system → PERMITTED (FedRAMP does not apply)."""
        ctx = _ctx(is_on_authorized_system=False)
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.NOT_FEDRAMP)
        result = fedramp.evaluate(ctx, doc)
        # NOT_FEDRAMP skips the "must be on authorized system" check; ATO still needed
        # if ATO=True (default), it should be PERMITTED
        assert not result.is_denied

    def test_moderate_doc_moderate_auth_permitted(self, fedramp):
        """MODERATE doc + MODERATE authorization → PERMITTED."""
        ctx = _ctx(
            fedramp_authorization_level=mod.FedRAMPImpactLevel.MODERATE,
            is_on_authorized_system=True,
            has_ato=True,
        )
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.MODERATE)
        result = fedramp.evaluate(ctx, doc)
        assert not result.is_denied


# ---------------------------------------------------------------------------
# TestFISMASecurityControlFilter — 8 tests
# ---------------------------------------------------------------------------


class TestFISMASecurityControlFilter:
    @pytest.fixture
    def fisma(self):
        return mod.FISMASecurityControlFilter()

    def test_high_doc_moderate_fisma_category_denied(self, fisma):
        """HIGH doc + MODERATE fisma_system_category → DENIED (AC-4)."""
        ctx = _ctx(fisma_system_category="MODERATE")
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = fisma.evaluate(ctx, doc)
        assert result.is_denied
        assert "AC-4" in result.reason or "AC-4" in result.regulation_citation

    def test_contractor_no_background_investigation_denied(self, fisma):
        """CONTRACTOR without background investigation → DENIED (PS-3)."""
        ctx = _ctx(
            user_role=mod.GovernmentRole.CONTRACTOR,
            has_background_investigation=False,
        )
        doc = _doc()
        result = fisma.evaluate(ctx, doc)
        assert result.is_denied
        assert "PS-3" in result.reason or "PS-3" in result.regulation_citation

    def test_public_user_not_public_release_approved_denied(self, fisma):
        """PUBLIC user + document not approved for public release → DENIED (AC-3)."""
        ctx = _ctx(user_role=mod.GovernmentRole.PUBLIC)
        doc = _doc(is_public_release_approved=False)
        result = fisma.evaluate(ctx, doc)
        assert result.is_denied
        assert "AC-3" in result.reason or "AC-3" in result.regulation_citation

    def test_need_to_know_not_established_cui_doc_denied(self, fisma):
        """Need-to-know not established + CUI (FOUO) doc → DENIED (AC-3(7))."""
        ctx = _ctx(is_need_to_know=False)
        doc = _doc(cui_category=mod.CUICategory.FOUO)
        result = fisma.evaluate(ctx, doc)
        assert result.is_denied
        assert "AC-3(7)" in result.reason or "AC-3(7)" in result.regulation_citation

    def test_federal_employee_need_to_know_high_all_ok_permitted(self, fisma):
        """Federal employee + need_to_know + HIGH fisma_system_category → PERMITTED."""
        ctx = _ctx(
            user_role=mod.GovernmentRole.FEDERAL_EMPLOYEE,
            is_need_to_know=True,
            fisma_system_category="HIGH",
            has_background_investigation=True,
        )
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = fisma.evaluate(ctx, doc)
        assert not result.is_denied

    def test_cleared_contractor_with_background_investigation_permitted(self, fisma):
        """CLEARED_CONTRACTOR + background investigation → PERMITTED."""
        ctx = _ctx(
            user_role=mod.GovernmentRole.CLEARED_CONTRACTOR,
            has_background_investigation=True,
            is_need_to_know=True,
            fisma_system_category="HIGH",
        )
        doc = _doc()
        result = fisma.evaluate(ctx, doc)
        assert not result.is_denied

    def test_public_user_public_release_approved_permitted(self, fisma):
        """PUBLIC user + document approved for public release → PERMITTED."""
        ctx = _ctx(
            user_role=mod.GovernmentRole.PUBLIC,
            is_need_to_know=True,
        )
        doc = _doc(
            is_public_release_approved=True,
            cui_category=mod.CUICategory.UNCONTROLLED_PUBLIC,
        )
        result = fisma.evaluate(ctx, doc)
        assert not result.is_denied

    def test_regulation_citation_mentions_nist_sp_800_53(self, fisma):
        """Any result's regulation_citation or reason mentions 'NIST SP 800-53'."""
        ctx = _ctx(fisma_system_category="MODERATE")
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = fisma.evaluate(ctx, doc)
        assert "NIST SP 800-53" in result.reason or "NIST SP 800-53" in result.regulation_citation


# ---------------------------------------------------------------------------
# TestCUIMarkingFilter — 8 tests
# ---------------------------------------------------------------------------


class TestCUIMarkingFilter:
    @pytest.fixture
    def cui(self):
        return mod.CUIMarkingFilter()

    def test_export_controlled_not_us_person_denied(self, cui):
        """Export-controlled doc + non-US person → DENIED (EAR/ITAR)."""
        ctx = _ctx(is_us_person=False)
        doc = _doc(
            is_export_controlled=True,
            cui_category=mod.CUICategory.EXPORT_CONTROLLED,
        )
        result = cui.evaluate(ctx, doc)
        assert result.is_denied
        assert "EAR" in result.reason or "ITAR" in result.reason or "export" in result.reason.lower()

    def test_les_doc_non_law_enforcement_non_ig_denied(self, cui):
        """LES doc + not law enforcement + not IG oversight → DENIED."""
        ctx = _ctx(is_law_enforcement=False, is_ig_oversight=False)
        doc = _doc(cui_category=mod.CUICategory.LAW_ENFORCEMENT_SENSITIVE)
        result = cui.evaluate(ctx, doc)
        assert result.is_denied

    def test_les_doc_law_enforcement_user_permitted(self, cui):
        """LES doc + is_law_enforcement=True → PERMITTED."""
        ctx = _ctx(is_law_enforcement=True)
        doc = _doc(cui_category=mod.CUICategory.LAW_ENFORCEMENT_SENSITIVE)
        result = cui.evaluate(ctx, doc)
        assert not result.is_denied

    def test_pii_doc_no_privacy_act_training_denied(self, cui):
        """PII-containing doc + no Privacy Act training → DENIED."""
        ctx = _ctx(has_privacy_act_training=False)
        doc = _doc(
            contains_pii=True,
            cui_category=mod.CUICategory.PRIVACY_ACT,
        )
        result = cui.evaluate(ctx, doc)
        assert result.is_denied

    def test_fouo_doc_public_role_denied(self, cui):
        """FOUO doc + PUBLIC role → DENIED (32 CFR Part 2002)."""
        ctx = _ctx(user_role=mod.GovernmentRole.PUBLIC)
        doc = _doc(cui_category=mod.CUICategory.FOUO)
        result = cui.evaluate(ctx, doc)
        assert result.is_denied

    def test_contractor_no_agreement_non_public_cui_denied(self, cui):
        """CONTRACTOR + no contractor_agreement + non-public CUI → DENIED."""
        ctx = _ctx(
            user_role=mod.GovernmentRole.CONTRACTOR,
            contractor_agreement_active=False,
        )
        doc = _doc(cui_category=mod.CUICategory.FOUO)
        result = cui.evaluate(ctx, doc)
        assert result.is_denied

    def test_uncontrolled_public_any_role_permitted(self, cui):
        """UNCONTROLLED_PUBLIC category + any role → PERMITTED (no CUI restrictions)."""
        ctx = _ctx(user_role=mod.GovernmentRole.PUBLIC)
        doc = _doc(
            cui_category=mod.CUICategory.UNCONTROLLED_PUBLIC,
            is_public_release_approved=True,
        )
        result = cui.evaluate(ctx, doc)
        assert not result.is_denied

    def test_privacy_act_cui_with_training_permitted(self, cui):
        """Privacy Act CUI doc + has_privacy_act_training=True → PERMITTED."""
        ctx = _ctx(has_privacy_act_training=True, is_need_to_know=True)
        doc = _doc(
            contains_pii=True,
            cui_category=mod.CUICategory.PRIVACY_ACT,
        )
        result = cui.evaluate(ctx, doc)
        assert not result.is_denied


# ---------------------------------------------------------------------------
# TestGovernmentAuditFilter — 5 tests
# ---------------------------------------------------------------------------


class TestGovernmentAuditFilter:
    @pytest.fixture
    def audit(self):
        return mod.GovernmentAuditFilter()

    def test_ig_auditor_override_permitted(self, audit):
        """IG auditor (is_ig_oversight=True) → PERMITTED override (Inspector General Act)."""
        ctx = _ctx(is_ig_oversight=True)
        doc = _doc()
        result = audit.evaluate(ctx, doc)
        assert not result.is_denied
        assert "Inspector General" in result.reason or "IG" in result.reason or "§6" in result.reason

    def test_congressional_oversight_override_permitted(self, audit):
        """Congressional oversight → PERMITTED override."""
        ctx = _ctx(is_congressional_oversight=True)
        doc = _doc()
        result = audit.evaluate(ctx, doc)
        assert not result.is_denied

    def test_high_doc_no_security_clearance_denied(self, audit):
        """HIGH doc + no security clearance → DENIED (AU-9)."""
        ctx = _ctx(has_security_clearance=False, is_ig_oversight=False, is_congressional_oversight=False)
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = audit.evaluate(ctx, doc)
        assert result.is_denied

    def test_federal_employee_with_clearance_permitted(self, audit):
        """Federal employee + has_security_clearance → PERMITTED."""
        ctx = _ctx(
            user_role=mod.GovernmentRole.FEDERAL_EMPLOYEE,
            has_security_clearance=True,
            is_ig_oversight=False,
            is_congressional_oversight=False,
        )
        doc = _doc(fedramp_required_level=mod.FedRAMPImpactLevel.HIGH)
        result = audit.evaluate(ctx, doc)
        assert not result.is_denied

    def test_regulation_citation_mentions_ig_act_or_au9(self, audit):
        """IG override result mentions IG Act; AU-9 denial result mentions AU-9."""
        # IG override
        ctx_ig = _ctx(is_ig_oversight=True)
        doc = _doc()
        result_ig = audit.evaluate(ctx_ig, doc)
        assert (
            "Inspector General" in result_ig.regulation_citation
            or "IG" in result_ig.regulation_citation
            or "AU-9" in result_ig.regulation_citation
        )
        # AU-9 denial
        ctx_denied = _ctx(
            has_security_clearance=False,
            is_ig_oversight=False,
            is_congressional_oversight=False,
        )
        result_denied = audit.evaluate(ctx_denied, doc)
        assert "AU-9" in result_denied.reason or "AU-9" in result_denied.regulation_citation


# ---------------------------------------------------------------------------
# TestGovernmentRAGPipeline — 4 tests
# ---------------------------------------------------------------------------


class TestGovernmentRAGPipeline:
    @pytest.fixture
    def pipeline(self):
        return mod.GovernmentRAGPipeline()

    def test_fully_authorized_officer_document_permitted(self, pipeline):
        """Fully authorized officer → audit record shows documents_permitted == 1."""
        ctx = _ctx()
        doc = _doc(document_id="d-auth")
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        assert audit.documents_permitted == 1

    def test_no_ato_document_denied(self, pipeline):
        """System without ATO → audit record shows documents_denied == 1."""
        ctx = _ctx(has_ato=False)
        doc = _doc(document_id="d-noato")
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        assert audit.documents_denied == 1

    def test_retrieve_returns_list(self, pipeline):
        """retrieve() returns a list."""
        ctx = _ctx()
        docs = [_doc(document_id="d-001"), _doc(document_id="d-002")]
        result = pipeline.retrieve(ctx, docs)
        assert isinstance(result, list)

    def test_retrieve_with_audit_to_audit_log_event(self, pipeline):
        """to_audit_log() on retrieve_with_audit result has event='GOVERNMENT_RAG_RETRIEVAL'."""
        ctx = _ctx()
        doc = _doc(document_id="d-audit-event")
        audit = pipeline.retrieve_with_audit(ctx, [doc])
        log = audit.to_audit_log()
        assert log["event"] == "GOVERNMENT_RAG_RETRIEVAL"


# ---------------------------------------------------------------------------
# TestGovernmentAuditRecord — 2 tests
# ---------------------------------------------------------------------------


class TestGovernmentAuditRecord:
    def _make_record(self):
        return mod.GovernmentAuditRecord(
            user_id="u-audit",
            agency_id="DHS",
            user_role=mod.GovernmentRole.FEDERAL_EMPLOYEE,
            documents_evaluated=2,
            documents_permitted=1,
            documents_denied=1,
            filter_results=[
                {
                    "document_id": "d1",
                    "final_decision": "PERMITTED",
                    "layer_results": [],
                },
                {
                    "document_id": "d2",
                    "final_decision": "DENIED",
                    "layer_results": [],
                },
            ],
        )

    def test_to_audit_log_contains_user_id_and_agency_id(self):
        """to_audit_log() includes user_id and agency_id."""
        record = self._make_record()
        log = record.to_audit_log()
        assert log["user_id"] == "u-audit"
        assert log["agency_id"] == "DHS"

    def test_documents_evaluated_count_correct(self):
        """documents_evaluated matches the count of docs passed to the record."""
        record = self._make_record()
        assert record.documents_evaluated == 2
        log = record.to_audit_log()
        assert log["documents_evaluated"] == 2
