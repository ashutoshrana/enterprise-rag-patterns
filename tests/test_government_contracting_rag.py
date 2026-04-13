"""
Tests for 22_government_contracting_rag.py

Three-layer defense-in-depth pipeline:
  Layer 1: FAR/DFARS CUI + clearance
  Layer 2: ITAR/EAR export control
  Layer 3: DD Form 254 need-to-know
"""

import importlib.util
import sys
import types
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module loading — importlib pattern (avoids package import issues)
# ---------------------------------------------------------------------------

_MOD_PATH = Path(__file__).parent.parent / "examples" / "22_government_contracting_rag.py"


def _load_module():
    module_name = "gov_contracting_rag"
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
    """Default: US Person, SECRET clearance, CTI + PBI authorized, no contracts."""
    defaults = dict(
        contractor_id="TEST-001",
        is_us_person=True,
        personnel_clearance=m.SecurityClearanceLevel.SECRET,
        facility_clearance=m.SecurityClearanceLevel.SECRET,
        cui_categories_authorized=frozenset({
            m.CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
            m.CUICategory.PROPRIETARY_BUSINESS_INFORMATION,
        }),
        authorized_contract_ids=frozenset(),
        has_deemed_export_license=False,
        is_domestic_recipient=True,
    )
    defaults.update(kwargs)
    return m.ContractorAccessContext(**defaults)


def _doc(m, **kwargs):
    """Default: SECRET/CTI/USML_IV doc, one contract required."""
    defaults = dict(
        document_id=str(uuid.uuid4()),
        title="Test Document",
        minimum_clearance=m.SecurityClearanceLevel.SECRET,
        cui_category=m.CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
        itar_category=m.ITARCategory.USML_IV_AIRCRAFT,
        required_contract_ids=frozenset({"CONTRACT-A"}),
        requires_facility_clearance=m.SecurityClearanceLevel.SECRET,
        is_publicly_releasable=False,
    )
    defaults.update(kwargs)
    return m.GovContractDocument(**defaults)


# ---------------------------------------------------------------------------
# SecurityClearanceLevel tests
# ---------------------------------------------------------------------------

class TestSecurityClearanceLevel:
    def test_rank_ordering(self, m):
        lvl = m.SecurityClearanceLevel
        assert lvl.UNCLASSIFIED.rank < lvl.CUI.rank < lvl.CONFIDENTIAL.rank
        assert lvl.CONFIDENTIAL.rank < lvl.SECRET.rank < lvl.TOP_SECRET.rank
        assert lvl.TOP_SECRET.rank < lvl.TOP_SECRET_SCI.rank

    def test_authorizes_equal(self, m):
        assert m.SecurityClearanceLevel.SECRET.authorizes(m.SecurityClearanceLevel.SECRET)

    def test_authorizes_higher(self, m):
        assert m.SecurityClearanceLevel.TOP_SECRET.authorizes(m.SecurityClearanceLevel.SECRET)

    def test_not_authorizes_lower_clearance(self, m):
        assert not m.SecurityClearanceLevel.CONFIDENTIAL.authorizes(m.SecurityClearanceLevel.SECRET)

    def test_unclassified_authorizes_unclassified(self, m):
        assert m.SecurityClearanceLevel.UNCLASSIFIED.authorizes(
            m.SecurityClearanceLevel.UNCLASSIFIED
        )

    def test_top_secret_sci_authorizes_all(self, m):
        for lvl in m.SecurityClearanceLevel:
            assert m.SecurityClearanceLevel.TOP_SECRET_SCI.authorizes(lvl)


# ---------------------------------------------------------------------------
# Layer 1 — FAR/DFARS filter
# ---------------------------------------------------------------------------

class TestFARDFARSFilter:
    def test_permits_authorized_clearance_and_category(self, m):
        f = m.FARDFARSFilter()
        ctx = _ctx(m, authorized_contract_ids=frozenset({"CONTRACT-A"}))
        doc = _doc(m)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1
        assert audit.far_dfars_permitted == 1
        assert audit.far_dfars_blocked == 0

    def test_blocks_insufficient_personnel_clearance(self, m):
        f = m.FARDFARSFilter()
        ctx = _ctx(
            m,
            personnel_clearance=m.SecurityClearanceLevel.CONFIDENTIAL,
            authorized_contract_ids=frozenset({"CONTRACT-A"}),
        )
        doc = _doc(m, minimum_clearance=m.SecurityClearanceLevel.SECRET)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert audit.far_dfars_blocked == 1
        assert "FAR/DFARS" in audit.block_reasons[0]["reason"]

    def test_blocks_insufficient_facility_clearance(self, m):
        f = m.FARDFARSFilter()
        ctx = _ctx(
            m,
            facility_clearance=m.SecurityClearanceLevel.CONFIDENTIAL,
            authorized_contract_ids=frozenset({"CONTRACT-A"}),
        )
        doc = _doc(m, requires_facility_clearance=m.SecurityClearanceLevel.SECRET)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "Facility clearance" in audit.block_reasons[0]["reason"]

    def test_blocks_unauthorized_cui_category(self, m):
        f = m.FARDFARSFilter()
        ctx = _ctx(
            m,
            cui_categories_authorized=frozenset({m.CUICategory.PRIVACY}),
            authorized_contract_ids=frozenset({"CONTRACT-A"}),
        )
        doc = _doc(m, cui_category=m.CUICategory.CONTROLLED_TECHNICAL_INFORMATION)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "CUI category" in audit.block_reasons[0]["reason"]

    def test_permits_uncontrolled_without_category_authorization(self, m):
        f = m.FARDFARSFilter()
        ctx = _ctx(
            m,
            cui_categories_authorized=frozenset(),
            authorized_contract_ids=frozenset({"CONTRACT-A"}),
        )
        doc = _doc(
            m,
            cui_category=m.CUICategory.UNCONTROLLED,
            minimum_clearance=m.SecurityClearanceLevel.UNCLASSIFIED,
            requires_facility_clearance=m.SecurityClearanceLevel.UNCLASSIFIED,
            itar_category=m.ITARCategory.EAR99,
            required_contract_ids=frozenset(),
        )
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_permits_publicly_releasable_regardless_of_clearance(self, m):
        f = m.FARDFARSFilter()
        ctx = _ctx(m, personnel_clearance=m.SecurityClearanceLevel.UNCLASSIFIED)
        doc = _doc(m, is_publicly_releasable=True)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_blocks_multiple_documents(self, m):
        f = m.FARDFARSFilter()
        ctx = _ctx(m, personnel_clearance=m.SecurityClearanceLevel.CUI)
        docs = [_doc(m) for _ in range(3)]
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter(docs, ctx, audit)
        assert len(result) == 0
        assert audit.far_dfars_blocked == 3


# ---------------------------------------------------------------------------
# Layer 2 — ITAR/EAR filter
# ---------------------------------------------------------------------------

class TestITAREARFilter:
    def test_blocks_usml_foreign_national_no_license(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=False, has_deemed_export_license=False)
        doc = _doc(m, itar_category=m.ITARCategory.USML_IV_AIRCRAFT)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "ITAR" in audit.block_reasons[0]["reason"]

    def test_permits_usml_us_person(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=True)
        doc = _doc(m, itar_category=m.ITARCategory.USML_XV_SPACECRAFT)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1
        assert audit.itar_ear_permitted == 1

    def test_permits_usml_foreign_national_with_license(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=False, has_deemed_export_license=True)
        doc = _doc(m, itar_category=m.ITARCategory.USML_XI_MILITARY_ELECTRONICS)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_blocks_ccl_ns_mt_foreign_recipient(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=True, is_domestic_recipient=False)
        doc = _doc(m, itar_category=m.ITARCategory.CCL_NS_MT)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "EAR" in audit.block_reasons[0]["reason"]

    def test_permits_ccl_ns_mt_domestic_recipient(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=True, is_domestic_recipient=True)
        doc = _doc(m, itar_category=m.ITARCategory.CCL_NS_MT)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_permits_ear99_for_everyone(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=False, is_domestic_recipient=False)
        doc = _doc(m, itar_category=m.ITARCategory.EAR99)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_permits_not_subject_ear(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=False)
        doc = _doc(m, itar_category=m.ITARCategory.NOT_SUBJECT_EAR)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_permits_publicly_releasable(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=False)
        doc = _doc(m, itar_category=m.ITARCategory.USML_IV_AIRCRAFT, is_publicly_releasable=True)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_all_usml_categories_blocked_for_foreign_national(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=False, has_deemed_export_license=False)
        usml_cats = [
            m.ITARCategory.USML_I_FIREARMS,
            m.ITARCategory.USML_II_GUNS,
            m.ITARCategory.USML_III_AMMUNITION,
            m.ITARCategory.USML_IV_AIRCRAFT,
            m.ITARCategory.USML_VIII_AIRCRAFT_TECH,
            m.ITARCategory.USML_XI_MILITARY_ELECTRONICS,
            m.ITARCategory.USML_XII_OPTICS,
            m.ITARCategory.USML_XV_SPACECRAFT,
            m.ITARCategory.USML_XXII_SUBMERSIBLES,
        ]
        for cat in usml_cats:
            doc = _doc(m, itar_category=cat)
            audit = m.GovContractComplianceAuditRecord("Q", "C")
            result = f.filter([doc], ctx, audit)
            assert len(result) == 0, f"Expected {cat} to be blocked for foreign national"

    def test_ccl_dual_use_blocked_for_foreign_recipient(self, m):
        f = m.ITAREARFilter()
        ctx = _ctx(m, is_us_person=True, is_domestic_recipient=False)
        doc = _doc(m, itar_category=m.ITARCategory.CCL_DUAL_USE)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Layer 3 — DD Form 254 need-to-know filter
# ---------------------------------------------------------------------------

class TestDD254Filter:
    def test_permits_matching_contract(self, m):
        f = m.DD254NeedToKnowFilter()
        ctx = _ctx(m, authorized_contract_ids=frozenset({"CONTRACT-A"}))
        doc = _doc(m, required_contract_ids=frozenset({"CONTRACT-A"}))
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1
        assert audit.dd254_permitted == 1

    def test_blocks_non_matching_contract(self, m):
        f = m.DD254NeedToKnowFilter()
        ctx = _ctx(m, authorized_contract_ids=frozenset({"CONTRACT-B"}))
        doc = _doc(m, required_contract_ids=frozenset({"CONTRACT-A"}))
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert audit.dd254_blocked == 1
        assert "DD Form 254" in audit.block_reasons[0]["reason"]

    def test_permits_no_contract_restriction(self, m):
        f = m.DD254NeedToKnowFilter()
        ctx = _ctx(m, authorized_contract_ids=frozenset())
        doc = _doc(m, required_contract_ids=frozenset())
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_permits_one_matching_contract_among_many_required(self, m):
        f = m.DD254NeedToKnowFilter()
        ctx = _ctx(m, authorized_contract_ids=frozenset({"CONTRACT-B"}))
        doc = _doc(m, required_contract_ids=frozenset({"CONTRACT-A", "CONTRACT-B"}))
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_permits_publicly_releasable_without_contract(self, m):
        f = m.DD254NeedToKnowFilter()
        ctx = _ctx(m, authorized_contract_ids=frozenset())
        doc = _doc(m, required_contract_ids=frozenset({"CONTRACT-A"}), is_publicly_releasable=True)
        audit = m.GovContractComplianceAuditRecord("Q", "C")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Full pipeline tests
# ---------------------------------------------------------------------------

class TestGovContractRAGPipeline:
    def _make_corpus(self, m):
        return [
            _doc(
                m,
                document_id="D-001",
                itar_category=m.ITARCategory.USML_IV_AIRCRAFT,
                required_contract_ids=frozenset({"FA8625-24-C-0001"}),
            ),
            _doc(
                m,
                document_id="D-002",
                itar_category=m.ITARCategory.EAR99,
                cui_category=m.CUICategory.PROPRIETARY_BUSINESS_INFORMATION,
                required_contract_ids=frozenset(),
                minimum_clearance=m.SecurityClearanceLevel.CUI,
                requires_facility_clearance=m.SecurityClearanceLevel.CUI,
            ),
            _doc(
                m,
                document_id="D-003",
                itar_category=m.ITARCategory.NOT_SUBJECT_EAR,
                cui_category=m.CUICategory.UNCONTROLLED,
                minimum_clearance=m.SecurityClearanceLevel.UNCLASSIFIED,
                requires_facility_clearance=m.SecurityClearanceLevel.UNCLASSIFIED,
                required_contract_ids=frozenset(),
                is_publicly_releasable=True,
            ),
        ]

    def test_full_pipeline_cleared_us_engineer(self, m):
        pipeline = m.GovContractRAGPipeline()
        corpus = self._make_corpus(m)
        ctx = _ctx(
            m,
            is_us_person=True,
            authorized_contract_ids=frozenset({"FA8625-24-C-0001"}),
        )
        docs, audit = pipeline.retrieve(corpus, ctx)
        assert "D-001" in [d.document_id for d in docs]
        assert "D-002" in [d.document_id for d in docs]
        assert "D-003" in [d.document_id for d in docs]

    def test_full_pipeline_foreign_national_blocked_from_usml(self, m):
        pipeline = m.GovContractRAGPipeline()
        corpus = self._make_corpus(m)
        ctx = _ctx(
            m,
            is_us_person=False,
            authorized_contract_ids=frozenset({"FA8625-24-C-0001"}),
        )
        docs, audit = pipeline.retrieve(corpus, ctx)
        doc_ids = [d.document_id for d in docs]
        assert "D-001" not in doc_ids
        assert audit.itar_ear_blocked >= 1

    def test_full_pipeline_wrong_contract_blocks_classified(self, m):
        pipeline = m.GovContractRAGPipeline()
        corpus = self._make_corpus(m)
        ctx = _ctx(
            m,
            is_us_person=True,
            authorized_contract_ids=frozenset({"UNRELATED-CONTRACT"}),
        )
        docs, audit = pipeline.retrieve(corpus, ctx)
        doc_ids = [d.document_id for d in docs]
        assert "D-001" not in doc_ids
        assert "D-003" in doc_ids

    def test_audit_record_totals(self, m):
        pipeline = m.GovContractRAGPipeline()
        corpus = self._make_corpus(m)
        ctx = _ctx(m, is_us_person=True, authorized_contract_ids=frozenset({"FA8625-24-C-0001"}))
        docs, audit = pipeline.retrieve(corpus, ctx)
        assert audit.total_candidates == 3
        assert audit.final_permitted + audit.final_blocked == 3

    def test_audit_log_structure(self, m):
        pipeline = m.GovContractRAGPipeline()
        corpus = self._make_corpus(m)
        ctx = _ctx(m, is_us_person=False)
        _, audit = pipeline.retrieve(corpus, ctx)
        log = audit.to_audit_log()
        assert "query_id" in log
        assert "layers" in log
        assert "far_dfars" in log["layers"]
        assert "itar_ear" in log["layers"]
        assert "dd254" in log["layers"]
        assert "final" in log

    def test_empty_corpus(self, m):
        pipeline = m.GovContractRAGPipeline()
        ctx = _ctx(m)
        docs, audit = pipeline.retrieve([], ctx)
        assert docs == []
        assert audit.total_candidates == 0
        assert audit.final_permitted == 0
        assert audit.final_blocked == 0

    def test_contractor_id_in_audit(self, m):
        pipeline = m.GovContractRAGPipeline()
        ctx = _ctx(m, contractor_id="ENG-AUDIT-TEST")
        _, audit = pipeline.retrieve([], ctx)
        assert audit.contractor_id == "ENG-AUDIT-TEST"

    def test_block_reasons_list_populated(self, m):
        pipeline = m.GovContractRAGPipeline()
        doc = _doc(m, itar_category=m.ITARCategory.USML_XV_SPACECRAFT)
        ctx = _ctx(m, is_us_person=False)
        _, audit = pipeline.retrieve([doc], ctx)
        assert len(audit.block_reasons) >= 1
        assert all("document_id" in r for r in audit.block_reasons)
        assert all("layer" in r for r in audit.block_reasons)
        assert all("reason" in r for r in audit.block_reasons)


# ---------------------------------------------------------------------------
# Scenario-based integration tests
# ---------------------------------------------------------------------------

class TestScenarios:
    def test_scenario_a_cleared_us_engineer(self, m):
        """Cleared US engineer on F-35 contract can access USML IV + PBI docs."""
        pipeline = m.GovContractRAGPipeline()
        docs_corpus = [
            _doc(m, document_id="USML", itar_category=m.ITARCategory.USML_IV_AIRCRAFT,
                 required_contract_ids=frozenset({"FA8625-24-C-0001"})),
            _doc(m, document_id="PBI", itar_category=m.ITARCategory.EAR99,
                 cui_category=m.CUICategory.PROPRIETARY_BUSINESS_INFORMATION,
                 minimum_clearance=m.SecurityClearanceLevel.CUI,
                 requires_facility_clearance=m.SecurityClearanceLevel.CUI,
                 required_contract_ids=frozenset()),
        ]
        ctx = _ctx(m, is_us_person=True, authorized_contract_ids=frozenset({"FA8625-24-C-0001"}))
        docs, audit = pipeline.retrieve(docs_corpus, ctx)
        assert "USML" in [d.document_id for d in docs]
        assert "PBI" in [d.document_id for d in docs]

    def test_scenario_b_foreign_national_blocked_all_usml(self, m):
        """Foreign national without license cannot access any USML category."""
        pipeline = m.GovContractRAGPipeline()
        ctx = _ctx(m, is_us_person=False, has_deemed_export_license=False,
                   authorized_contract_ids=frozenset({"CONTRACT-A"}))
        for cat in [m.ITARCategory.USML_I_FIREARMS, m.ITARCategory.USML_XV_SPACECRAFT,
                    m.ITARCategory.USML_XXII_SUBMERSIBLES]:
            doc = _doc(m, itar_category=cat, required_contract_ids=frozenset({"CONTRACT-A"}))
            docs, _ = pipeline.retrieve([doc], ctx)
            assert docs == [], f"Expected {cat.value} to be blocked for foreign national"

    def test_scenario_d_foreign_with_license_gets_usml(self, m):
        """Foreign national WITH deemed-export license can access USML data."""
        pipeline = m.GovContractRAGPipeline()
        ctx = _ctx(m, is_us_person=False, has_deemed_export_license=True,
                   authorized_contract_ids=frozenset({"CONTRACT-A"}))
        doc = _doc(m, itar_category=m.ITARCategory.USML_IV_AIRCRAFT,
                   required_contract_ids=frozenset({"CONTRACT-A"}))
        docs, _ = pipeline.retrieve([doc], ctx)
        assert len(docs) == 1

    def test_public_doc_accessible_to_everyone(self, m):
        """Publicly releasable documents bypass all three layers."""
        pipeline = m.GovContractRAGPipeline()
        ctx = _ctx(m, is_us_person=False,
                   personnel_clearance=m.SecurityClearanceLevel.UNCLASSIFIED,
                   facility_clearance=m.SecurityClearanceLevel.UNCLASSIFIED,
                   cui_categories_authorized=frozenset(),
                   authorized_contract_ids=frozenset())
        doc = _doc(m, itar_category=m.ITARCategory.USML_I_FIREARMS,
                   is_publicly_releasable=True)
        docs, _ = pipeline.retrieve([doc], ctx)
        assert len(docs) == 1
