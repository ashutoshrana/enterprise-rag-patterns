"""
Tests for 26_legal_services_rag.py

Four-layer legal services RAG pipeline:
  Layer 1: AttorneyClientPrivilegeFilter — ABA Model Rule 1.6
  Layer 2: ConflictOfInterestFilter — ABA Model Rules 1.7 / 1.9
  Layer 3: WorkProductDoctrineFilter — FRCP Rule 26(b)(3)
  Layer 4: StateBarEthicsFilter — State bar admission / UPL
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------

_MOD_PATH = Path(__file__).parent.parent / "examples" / "26_legal_services_rag.py"


def _load_module():
    module_name = "legal_services_rag"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, _MOD_PATH)
    mod = types.ModuleType(module_name)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def m():
    return _load_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(m, **kwargs):
    """Fully compliant WA attorney on matter."""
    defaults = dict(
        user_id="ATT-001",
        user_role=m.LegalRole.ATTORNEY,
        matter_id="MAT-001",
        client_id="CLI-001",
        bar_number="WA12345",
        bar_jurisdiction="WA",
        is_admitted_in_matter_jurisdiction=True,
        is_on_matter_team=True,
        has_conflict_cleared=True,
        adverse_to_former_client=False,
        former_client_consented=False,
        privilege_waiver_documented=False,
        substantial_need_shown=False,
        is_audit_access=False,
    )
    defaults.update(kwargs)
    return m.LegalServicesContext(**defaults)


def _doc(m, **kwargs):
    """Default privileged, ordinary work product document."""
    defaults = dict(
        document_id="DOC-001",
        is_privileged=True,
        work_product_type=m.WorkProductType.ORDINARY,
        owning_client_id="CLI-001",
        matter_jurisdiction="WA",
        is_public=False,
    )
    defaults.update(kwargs)
    return m.LegalDocument(**defaults)


# ---------------------------------------------------------------------------
# TestAttorneyClientPrivilegeFilter
# ---------------------------------------------------------------------------


class TestAttorneyClientPrivilegeFilter:
    def test_public_document_permitted(self, m):
        """is_public=True → PERMITTED regardless of privilege status."""
        f = m.AttorneyClientPrivilegeFilter()
        ctx = _ctx(m, user_role=m.LegalRole.OPPOSING_COUNSEL, is_on_matter_team=False)
        doc = _doc(m, is_public=True, is_privileged=True)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_non_privileged_document_permitted(self, m):
        """is_privileged=False → PERMITTED; no Rule 1.6 restriction applies."""
        f = m.AttorneyClientPrivilegeFilter()
        ctx = _ctx(m, user_role=m.LegalRole.OPPOSING_COUNSEL, is_on_matter_team=False)
        doc = _doc(m, is_privileged=False)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_attorney_on_matter_permitted(self, m):
        """ATTORNEY on matter team accessing privileged document → not denied."""
        f = m.AttorneyClientPrivilegeFilter()
        ctx = _ctx(m, user_role=m.LegalRole.ATTORNEY, is_on_matter_team=True)
        doc = _doc(m, is_privileged=True)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_paralegal_on_matter_permitted(self, m):
        """PARALEGAL on matter team accessing privileged document → not denied."""
        f = m.AttorneyClientPrivilegeFilter()
        ctx = _ctx(m, user_role=m.LegalRole.PARALEGAL, is_on_matter_team=True)
        doc = _doc(m, is_privileged=True)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_opposing_counsel_denied(self, m):
        """OPPOSING_COUNSEL on privileged document → DENIED, reason contains 'Rule 1.6'."""
        f = m.AttorneyClientPrivilegeFilter()
        ctx = _ctx(m, user_role=m.LegalRole.OPPOSING_COUNSEL, is_on_matter_team=False)
        doc = _doc(m, is_privileged=True)
        result = f.evaluate(ctx, doc)
        assert result.is_denied
        assert "Rule 1.6" in result.reason or "1.6" in result.reason

    def test_privilege_waiver_permits_access(self, m):
        """privilege_waiver_documented=True → PERMITTED even for opposing counsel."""
        f = m.AttorneyClientPrivilegeFilter()
        ctx = _ctx(
            m,
            user_role=m.LegalRole.OPPOSING_COUNSEL,
            is_on_matter_team=False,
            privilege_waiver_documented=True,
        )
        doc = _doc(m, is_privileged=True)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_client_own_matter_permitted(self, m):
        """CLIENT with is_on_matter_team=True → not denied on privileged doc."""
        f = m.AttorneyClientPrivilegeFilter()
        ctx = _ctx(m, user_role=m.LegalRole.CLIENT, is_on_matter_team=True)
        doc = _doc(m, is_privileged=True)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_admin_non_audit_denied(self, m):
        """ADMIN without audit designation → DENIED on privileged document."""
        f = m.AttorneyClientPrivilegeFilter()
        ctx = _ctx(m, user_role=m.LegalRole.ADMIN, is_on_matter_team=False, is_audit_access=False)
        doc = _doc(m, is_privileged=True)
        result = f.evaluate(ctx, doc)
        assert result.is_denied


# ---------------------------------------------------------------------------
# TestConflictOfInterestFilter
# ---------------------------------------------------------------------------


class TestConflictOfInterestFilter:
    def test_conflict_cleared_no_former_client_approved(self, m):
        """has_conflict_cleared=True, no adverse former client → not denied."""
        f = m.ConflictOfInterestFilter()
        ctx = _ctx(m, has_conflict_cleared=True, adverse_to_former_client=False)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_no_conflict_check_denied(self, m):
        """has_conflict_cleared=False → DENIED; reason contains 'Rule 1.7' or 'conflict'."""
        f = m.ConflictOfInterestFilter()
        ctx = _ctx(m, has_conflict_cleared=False, adverse_to_former_client=False)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert result.is_denied
        assert "1.7" in result.reason or "conflict" in result.reason.lower()

    def test_adverse_former_client_no_consent_denied(self, m):
        """adverse_to_former_client=True, former_client_consented=False → DENIED, Rule 1.9."""
        f = m.ConflictOfInterestFilter()
        ctx = _ctx(
            m,
            has_conflict_cleared=True,
            adverse_to_former_client=True,
            former_client_consented=False,
        )
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert result.is_denied
        assert "Rule 1.9" in result.reason or "1.9" in result.reason

    def test_adverse_former_client_with_consent_permitted(self, m):
        """adverse_to_former_client=True, former_client_consented=True → not denied (Rule 1.9 waiver)."""
        f = m.ConflictOfInterestFilter()
        ctx = _ctx(
            m,
            has_conflict_cleared=True,
            adverse_to_former_client=True,
            former_client_consented=True,
        )
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_public_document_bypasses_conflict(self, m):
        """is_public=True → PERMITTED regardless of conflict state."""
        f = m.ConflictOfInterestFilter()
        ctx = _ctx(m, has_conflict_cleared=False, adverse_to_former_client=True)
        doc = _doc(m, is_public=True)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_conditions_reference_conflict_rules(self, m):
        """Compliant context (cleared, no adversity) → has conditions referencing '1.7' or '1.9'."""
        f = m.ConflictOfInterestFilter()
        ctx = _ctx(m, has_conflict_cleared=True, adverse_to_former_client=False)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert result.conditions
        assert any("1.7" in c or "1.9" in c for c in result.conditions)


# ---------------------------------------------------------------------------
# TestWorkProductDoctrineFilter
# ---------------------------------------------------------------------------


class TestWorkProductDoctrineFilter:
    def test_not_work_product_permitted(self, m):
        """WorkProductType.NOT_WORK_PRODUCT → not denied; Rule 26(b)(3) does not apply."""
        f = m.WorkProductDoctrineFilter()
        ctx = _ctx(m)
        doc = _doc(m, work_product_type=m.WorkProductType.NOT_WORK_PRODUCT)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_public_document_permitted(self, m):
        """is_public=True → not denied at work product layer."""
        f = m.WorkProductDoctrineFilter()
        ctx = _ctx(m, user_role=m.LegalRole.OPPOSING_COUNSEL)
        doc = _doc(m, is_public=True, work_product_type=m.WorkProductType.OPINION)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_attorney_opinion_work_product_permitted(self, m):
        """ATTORNEY on matter team + OPINION work product → not denied."""
        f = m.WorkProductDoctrineFilter()
        ctx = _ctx(m, user_role=m.LegalRole.ATTORNEY, is_on_matter_team=True)
        doc = _doc(m, work_product_type=m.WorkProductType.OPINION)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_opposing_counsel_opinion_denied(self, m):
        """OPPOSING_COUNSEL + OPINION work product → DENIED; reason references '26(b)(3)' or 'opinion'."""
        f = m.WorkProductDoctrineFilter()
        ctx = _ctx(m, user_role=m.LegalRole.OPPOSING_COUNSEL, is_on_matter_team=False)
        doc = _doc(m, work_product_type=m.WorkProductType.OPINION)
        result = f.evaluate(ctx, doc)
        assert result.is_denied
        assert "26(b)(3)" in result.reason or "opinion" in result.reason.lower()

    def test_opposing_counsel_ordinary_no_need_denied(self, m):
        """OPPOSING_COUNSEL + ORDINARY work product + substantial_need_shown=False → DENIED."""
        f = m.WorkProductDoctrineFilter()
        ctx = _ctx(
            m,
            user_role=m.LegalRole.OPPOSING_COUNSEL,
            is_on_matter_team=False,
            substantial_need_shown=False,
        )
        doc = _doc(m, work_product_type=m.WorkProductType.ORDINARY)
        result = f.evaluate(ctx, doc)
        assert result.is_denied

    def test_opposing_counsel_ordinary_substantial_need_permitted(self, m):
        """OPPOSING_COUNSEL + ORDINARY work product + substantial_need_shown=True → not denied; conditions reference 'substantial need'."""  # noqa: E501
        f = m.WorkProductDoctrineFilter()
        ctx = _ctx(
            m,
            user_role=m.LegalRole.OPPOSING_COUNSEL,
            is_on_matter_team=False,
            substantial_need_shown=True,
        )
        doc = _doc(m, work_product_type=m.WorkProductType.ORDINARY)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied
        assert any("substantial need" in c.lower() for c in result.conditions)

    def test_client_ordinary_work_product_permitted(self, m):
        """CLIENT + ORDINARY work product → not denied."""
        f = m.WorkProductDoctrineFilter()
        ctx = _ctx(m, user_role=m.LegalRole.CLIENT, is_on_matter_team=True)
        doc = _doc(m, work_product_type=m.WorkProductType.ORDINARY)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_paralegal_ordinary_work_product_permitted(self, m):
        """PARALEGAL on matter team + ORDINARY work product → not denied."""
        f = m.WorkProductDoctrineFilter()
        ctx = _ctx(m, user_role=m.LegalRole.PARALEGAL, is_on_matter_team=True)
        doc = _doc(m, work_product_type=m.WorkProductType.ORDINARY)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied


# ---------------------------------------------------------------------------
# TestStateBarEthicsFilter
# ---------------------------------------------------------------------------


class TestStateBarEthicsFilter:
    def test_attorney_admitted_in_jurisdiction_permitted(self, m):
        """ATTORNEY with is_admitted_in_matter_jurisdiction=True → not denied."""
        f = m.StateBarEthicsFilter()
        ctx = _ctx(m, user_role=m.LegalRole.ATTORNEY, is_admitted_in_matter_jurisdiction=True)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_attorney_not_admitted_denied(self, m):
        """ATTORNEY not admitted in matter jurisdiction → DENIED; reason contains 'jurisdiction' or 'pro hac'."""
        f = m.StateBarEthicsFilter()
        ctx = _ctx(m, user_role=m.LegalRole.ATTORNEY, is_admitted_in_matter_jurisdiction=False)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert result.is_denied
        assert "jurisdiction" in result.reason.lower() or "pro hac" in result.reason.lower()

    def test_paralegal_on_team_permitted(self, m):
        """PARALEGAL with is_on_matter_team=True → not denied."""
        f = m.StateBarEthicsFilter()
        ctx = _ctx(m, user_role=m.LegalRole.PARALEGAL, is_on_matter_team=True)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_paralegal_not_on_team_denied(self, m):
        """PARALEGAL with is_on_matter_team=False → DENIED."""
        f = m.StateBarEthicsFilter()
        ctx = _ctx(m, user_role=m.LegalRole.PARALEGAL, is_on_matter_team=False)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert result.is_denied

    def test_client_always_permitted(self, m):
        """CLIENT role → not denied at the state bar ethics layer."""
        f = m.StateBarEthicsFilter()
        ctx = _ctx(m, user_role=m.LegalRole.CLIENT, is_on_matter_team=True)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert not result.is_denied

    def test_admin_non_audit_denied(self, m):
        """ADMIN with is_audit_access=False → DENIED at state bar ethics layer."""
        f = m.StateBarEthicsFilter()
        ctx = _ctx(m, user_role=m.LegalRole.ADMIN, is_audit_access=False)
        doc = _doc(m)
        result = f.evaluate(ctx, doc)
        assert result.is_denied


# ---------------------------------------------------------------------------
# TestLegalServicesRAGPipeline
# ---------------------------------------------------------------------------


class TestLegalServicesRAGPipeline:
    def test_compliant_attorney_permitted_docs(self, m):
        """Fully compliant attorney on a WA matter retrieves all 3 docs (privileged+ORDINARY, OPINION, public)."""
        pipeline = m.LegalServicesRAGPipeline()
        ctx = _ctx(m)
        docs = [
            _doc(m, document_id="DOC-PRIV-ORD", is_privileged=True, work_product_type=m.WorkProductType.ORDINARY),
            _doc(m, document_id="DOC-OPINION", is_privileged=True, work_product_type=m.WorkProductType.OPINION),
            _doc(
                m,
                document_id="DOC-PUBLIC",
                is_public=True,
                is_privileged=False,
                work_product_type=m.WorkProductType.NOT_WORK_PRODUCT,
            ),
        ]
        permitted = pipeline.retrieve(ctx, docs)
        permitted_ids = {d.document_id for d in permitted}
        assert "DOC-PRIV-ORD" in permitted_ids
        assert "DOC-OPINION" in permitted_ids
        assert "DOC-PUBLIC" in permitted_ids
        assert len(permitted) == 3

    def test_opposing_counsel_only_gets_public(self, m):
        """OPPOSING_COUNSEL with no privilege waiver and no substantial need gets only public docs."""
        pipeline = m.LegalServicesRAGPipeline()
        ctx = _ctx(
            m,
            user_role=m.LegalRole.OPPOSING_COUNSEL,
            is_on_matter_team=False,
            has_conflict_cleared=True,
            adverse_to_former_client=False,
            substantial_need_shown=False,
            privilege_waiver_documented=False,
        )
        docs = [
            _doc(m, document_id="DOC-PRIV", is_privileged=True, work_product_type=m.WorkProductType.NOT_WORK_PRODUCT),
            _doc(m, document_id="DOC-OPINION", is_privileged=True, work_product_type=m.WorkProductType.OPINION),
            _doc(
                m,
                document_id="DOC-PUBLIC",
                is_public=True,
                is_privileged=False,
                work_product_type=m.WorkProductType.NOT_WORK_PRODUCT,
            ),
        ]
        permitted = pipeline.retrieve(ctx, docs)
        permitted_ids = {d.document_id for d in permitted}
        assert "DOC-PUBLIC" in permitted_ids
        assert "DOC-PRIV" not in permitted_ids
        assert "DOC-OPINION" not in permitted_ids
        assert len(permitted) == 1

    def test_unadmitted_attorney_blocked_on_non_public(self, m):
        """CA attorney on WA matter: public doc passes, non-public blocked at state bar ethics (Layer 4)."""
        pipeline = m.LegalServicesRAGPipeline()
        ctx = _ctx(
            m,
            user_role=m.LegalRole.ATTORNEY,
            bar_jurisdiction="CA",
            is_admitted_in_matter_jurisdiction=False,
            is_on_matter_team=True,
            has_conflict_cleared=True,
            adverse_to_former_client=False,
        )
        docs = [
            _doc(
                m,
                document_id="DOC-NON-PUBLIC",
                is_privileged=True,
                work_product_type=m.WorkProductType.NOT_WORK_PRODUCT,
                matter_jurisdiction="WA",
            ),
            _doc(
                m,
                document_id="DOC-PUBLIC",
                is_public=True,
                is_privileged=False,
                work_product_type=m.WorkProductType.NOT_WORK_PRODUCT,
                matter_jurisdiction="WA",
            ),
        ]
        permitted = pipeline.retrieve(ctx, docs)
        permitted_ids = {d.document_id for d in permitted}
        assert "DOC-PUBLIC" in permitted_ids
        assert "DOC-NON-PUBLIC" not in permitted_ids

    def test_conflict_not_cleared_blocks_all_non_public(self, m):
        """has_conflict_cleared=False: only public docs pass through (blocked at Layer 2)."""
        pipeline = m.LegalServicesRAGPipeline()
        ctx = _ctx(
            m,
            has_conflict_cleared=False,
            adverse_to_former_client=False,
        )
        docs = [
            _doc(m, document_id="DOC-PRIV-1", is_privileged=True, work_product_type=m.WorkProductType.ORDINARY),
            _doc(
                m, document_id="DOC-PRIV-2", is_privileged=False, work_product_type=m.WorkProductType.NOT_WORK_PRODUCT
            ),
            _doc(
                m,
                document_id="DOC-PUBLIC",
                is_public=True,
                is_privileged=False,
                work_product_type=m.WorkProductType.NOT_WORK_PRODUCT,
            ),
        ]
        permitted = pipeline.retrieve(ctx, docs)
        permitted_ids = {d.document_id for d in permitted}
        assert "DOC-PUBLIC" in permitted_ids
        assert "DOC-PRIV-1" not in permitted_ids
        assert "DOC-PRIV-2" not in permitted_ids

    def test_empty_document_list(self, m):
        """retrieve([]) returns empty list."""
        pipeline = m.LegalServicesRAGPipeline()
        ctx = _ctx(m)
        result = pipeline.retrieve(ctx, [])
        assert result == []

    def test_pipeline_has_four_layers(self, m):
        """Pipeline._layers has exactly 4 filter layers."""
        pipeline = m.LegalServicesRAGPipeline()
        assert len(pipeline._layers) == 4

    def test_paralegal_blocked_when_not_on_team(self, m):
        """PARALEGAL with is_on_matter_team=False → all privileged docs denied."""
        pipeline = m.LegalServicesRAGPipeline()
        ctx = _ctx(
            m,
            user_role=m.LegalRole.PARALEGAL,
            is_on_matter_team=False,
            has_conflict_cleared=True,
            adverse_to_former_client=False,
        )
        docs = [
            _doc(m, document_id="DOC-PRIV-1", is_privileged=True, work_product_type=m.WorkProductType.ORDINARY),
            _doc(m, document_id="DOC-PRIV-2", is_privileged=True, work_product_type=m.WorkProductType.NOT_WORK_PRODUCT),
        ]
        permitted = pipeline.retrieve(ctx, docs)
        assert len(permitted) == 0

    def test_client_accesses_own_matter(self, m):
        """CLIENT with is_on_matter_team=True → privileged non-work-product docs permitted."""
        pipeline = m.LegalServicesRAGPipeline()
        ctx = _ctx(
            m,
            user_role=m.LegalRole.CLIENT,
            is_on_matter_team=True,
            has_conflict_cleared=True,
            adverse_to_former_client=False,
            is_admitted_in_matter_jurisdiction=True,
        )
        docs = [
            _doc(
                m, document_id="DOC-CLIENT-1", is_privileged=True, work_product_type=m.WorkProductType.NOT_WORK_PRODUCT
            ),
            _doc(
                m, document_id="DOC-CLIENT-2", is_privileged=True, work_product_type=m.WorkProductType.NOT_WORK_PRODUCT
            ),
        ]
        permitted = pipeline.retrieve(ctx, docs)
        permitted_ids = {d.document_id for d in permitted}
        assert "DOC-CLIENT-1" in permitted_ids
        assert "DOC-CLIENT-2" in permitted_ids
