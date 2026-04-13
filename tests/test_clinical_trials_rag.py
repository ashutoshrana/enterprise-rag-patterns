"""
Tests for 24_clinical_trials_rag.py

Four-layer clinical trial RAG pipeline:
  Layer 1: FDA 21 CFR Part 11 — system validation + audit trail + e-signatures
  Layer 2: GxP Document Control — GMP / GLP / GCP / GDP role access
  Layer 3: ICH E6(R3) GCP — blinding enforcement + site-level access control
  Layer 4: HIPAA / HITECH — PHI minimum necessary + IRB waiver + DUA
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------

_MOD_PATH = (
    Path(__file__).parent.parent / "examples" / "24_clinical_trials_rag.py"
)


def _load_module():
    module_name = "clinical_trials_rag"
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
# Helpers — default passing context and document
# ---------------------------------------------------------------------------


def _ctx(m, **kwargs):
    """Fully compliant INVESTIGATOR context at SITE-A."""
    defaults = dict(
        user_id="INVEST-001",
        user_role=m.ClinicalTrialRole.INVESTIGATOR,
        assigned_site_ids=frozenset({"SITE-A"}),
        system_validated=True,
        audit_trail_active=True,
        electronic_signature_bound=True,
        database_locked=False,
        dsmb_authorized_access=False,
        irb_waiver_active=True,
        data_use_agreement_signed=True,
    )
    defaults.update(kwargs)
    return m.ClinicalAccessContext(**defaults)


def _doc(m, doc_type=None, gxp=None, phi=None, **kwargs):
    """Default CRF document at SITE-A with identified PHI."""
    if doc_type is None:
        doc_type = m.ClinicalDocumentType.CASE_REPORT_FORM
    if gxp is None:
        gxp = m.GxPTier.GCP
    if phi is None:
        phi = m.PHIClassification.IDENTIFIED
    defaults = dict(
        document_id="DOC-001",
        document_type=doc_type,
        gxp_tier=gxp,
        phi_classification=phi,
        site_id="SITE-A",
        is_blinded=False,
        is_public=False,
    )
    defaults.update(kwargs)
    return m.ClinicalDocument(**defaults)


# ---------------------------------------------------------------------------
# Layer 1 — FDA 21 CFR Part 11
# ---------------------------------------------------------------------------


class TestFDA21CFR11Filter:

    def test_passes_when_fully_validated(self, m):
        f = m.FDA21CFR11Filter()
        ctx = _ctx(m)
        doc = _doc(m)
        assert f._evaluate(doc, ctx) is None

    def test_blocks_unvalidated_system(self, m):
        f = m.FDA21CFR11Filter()
        ctx = _ctx(m, system_validated=False)
        doc = _doc(m)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "validation" in reason.lower() or "IQ/OQ/PQ" in reason

    def test_blocks_no_audit_trail(self, m):
        f = m.FDA21CFR11Filter()
        ctx = _ctx(m, audit_trail_active=False)
        doc = _doc(m)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "audit trail" in reason.lower()

    def test_blocks_unbound_signatures(self, m):
        f = m.FDA21CFR11Filter()
        ctx = _ctx(m, electronic_signature_bound=False)
        doc = _doc(m)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "signature" in reason.lower()

    def test_public_doc_bypasses_21cfr11(self, m):
        f = m.FDA21CFR11Filter()
        ctx = _ctx(m, system_validated=False, audit_trail_active=False)
        doc = _doc(m, is_public=True)
        assert f._evaluate(doc, ctx) is None

    def test_filter_increments_blocked_count(self, m):
        f = m.FDA21CFR11Filter()
        ctx = _ctx(m, system_validated=False)
        docs = [_doc(m, document_id=f"D-{i}") for i in range(3)]
        audit = m.ClinicalAccessAuditRecord(user_id="U", user_role="INVESTIGATOR")
        permitted = f.filter(docs, ctx, audit)
        assert len(permitted) == 0
        assert audit.blocked_by_21cfr11 == 3


# ---------------------------------------------------------------------------
# Layer 2 — GxP Document Control
# ---------------------------------------------------------------------------


class TestGxPDocumentFilter:

    def test_gmp_batch_record_blocked_for_non_qa(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.INVESTIGATOR)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.BATCH_RECORD,
                   gxp=m.GxPTier.GMP, phi=m.PHIClassification.NO_PHI, site_id=None)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "GMP" in reason

    def test_gmp_batch_record_permitted_for_qa(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.QA)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.BATCH_RECORD,
                   gxp=m.GxPTier.GMP, phi=m.PHIClassification.NO_PHI, site_id=None)
        assert f._evaluate(doc, ctx) is None

    def test_gmp_batch_record_permitted_for_regulatory(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.REGULATORY)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.BATCH_RECORD,
                   gxp=m.GxPTier.GMP, phi=m.PHIClassification.NO_PHI, site_id=None)
        assert f._evaluate(doc, ctx) is None

    def test_glp_raw_data_blocked_for_investigator(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.INVESTIGATOR)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.RAW_STUDY_DATA,
                   gxp=m.GxPTier.GLP, phi=m.PHIClassification.NO_PHI, site_id=None)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "GLP" in reason

    def test_glp_raw_data_permitted_for_regulatory(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.REGULATORY)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.RAW_STUDY_DATA,
                   gxp=m.GxPTier.GLP, phi=m.PHIClassification.NO_PHI, site_id=None)
        assert f._evaluate(doc, ctx) is None

    def test_gdp_distribution_blocked_for_investigator(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.INVESTIGATOR)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.DISTRIBUTION_RECORD,
                   gxp=m.GxPTier.GDP, phi=m.PHIClassification.NO_PHI, site_id=None)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "GDP" in reason or "distribution" in reason.lower()

    def test_gdp_distribution_permitted_for_pharmacist(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.PHARMACIST)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.DISTRIBUTION_RECORD,
                   gxp=m.GxPTier.GDP, phi=m.PHIClassification.NO_PHI, site_id=None)
        assert f._evaluate(doc, ctx) is None

    def test_gcp_document_passes_gxp_layer(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m)
        doc = _doc(m)  # Default is CASE_REPORT_FORM / GCP
        assert f._evaluate(doc, ctx) is None

    def test_public_doc_bypasses_gxp(self, m):
        f = m.GxPDocumentFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.BATCH_RECORD,
                   gxp=m.GxPTier.GMP, phi=m.PHIClassification.NO_PHI,
                   site_id=None, is_public=True)
        assert f._evaluate(doc, ctx) is None


# ---------------------------------------------------------------------------
# Layer 3 — ICH E6(R3) GCP
# ---------------------------------------------------------------------------


class TestICHE6GCPFilter:

    def test_investigator_permitted_own_site(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.INVESTIGATOR,
                   assigned_site_ids=frozenset({"SITE-A"}))
        doc = _doc(m, site_id="SITE-A")
        assert f._evaluate(doc, ctx) is None

    def test_investigator_blocked_other_site(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.INVESTIGATOR,
                   assigned_site_ids=frozenset({"SITE-A"}))
        doc = _doc(m, document_id="CRF-B", site_id="SITE-B")
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "SITE-B" in reason

    def test_monitor_permitted_assigned_site(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.MONITOR,
                   assigned_site_ids=frozenset({"SITE-A", "SITE-C"}))
        doc = _doc(m, site_id="SITE-C")
        assert f._evaluate(doc, ctx) is None

    def test_monitor_blocked_unassigned_site(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.MONITOR,
                   assigned_site_ids=frozenset({"SITE-A"}))
        doc = _doc(m, site_id="SITE-B")
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "SITE-B" in reason

    def test_blinded_interim_blocked_for_sponsor_before_dbl(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR, database_locked=False)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.INTERIM_ANALYSIS,
                   gxp=m.GxPTier.GCP, phi=m.PHIClassification.DE_IDENTIFIED,
                   is_blinded=True, site_id=None)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "blinded" in reason.lower() or "DBL" in reason

    def test_blinded_interim_permitted_for_sponsor_after_dbl(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR, database_locked=True)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.INTERIM_ANALYSIS,
                   gxp=m.GxPTier.GCP, phi=m.PHIClassification.DE_IDENTIFIED,
                   is_blinded=True, site_id=None)
        assert f._evaluate(doc, ctx) is None

    def test_dsmb_with_authorization_accesses_blinded(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.DSMB,
                   dsmb_authorized_access=True, database_locked=False)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.INTERIM_ANALYSIS,
                   gxp=m.GxPTier.GCP, phi=m.PHIClassification.DE_IDENTIFIED,
                   is_blinded=True, site_id=None)
        assert f._evaluate(doc, ctx) is None

    def test_regulatory_has_full_access(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.REGULATORY)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.INTERIM_ANALYSIS,
                   is_blinded=True, site_id="SITE-Z")
        assert f._evaluate(doc, ctx) is None

    def test_biostatistician_can_access_unblinded(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.BIOSTATISTICIAN)
        doc = _doc(m, doc_type=m.ClinicalDocumentType.INTERIM_ANALYSIS,
                   is_blinded=True, site_id=None)
        assert f._evaluate(doc, ctx) is None

    def test_public_doc_bypasses_gcp(self, m):
        f = m.ICHE6GCPFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR, database_locked=False)
        doc = _doc(m, is_blinded=True, is_public=True)
        assert f._evaluate(doc, ctx) is None


# ---------------------------------------------------------------------------
# Layer 4 — HIPAA
# ---------------------------------------------------------------------------


class TestHIPAAFilter:

    def test_identified_phi_permitted_for_investigator_with_irb(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.INVESTIGATOR, irb_waiver_active=True)
        doc = _doc(m, phi=m.PHIClassification.IDENTIFIED)
        assert f._evaluate(doc, ctx) is None

    def test_identified_phi_blocked_without_irb(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.INVESTIGATOR, irb_waiver_active=False)
        doc = _doc(m, phi=m.PHIClassification.IDENTIFIED)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "IRB" in reason or "waiver" in reason.lower()

    def test_identified_phi_blocked_for_sponsor(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR, irb_waiver_active=True)
        doc = _doc(m, phi=m.PHIClassification.IDENTIFIED)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "minimum necessary" in reason.lower() or "SPONSOR" in reason

    def test_monitor_permitted_for_identified_phi_with_irb(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.MONITOR, irb_waiver_active=True)
        doc = _doc(m, phi=m.PHIClassification.IDENTIFIED)
        assert f._evaluate(doc, ctx) is None

    def test_limited_dataset_blocked_without_dua(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, data_use_agreement_signed=False)
        doc = _doc(m, phi=m.PHIClassification.LIMITED_DATASET)
        reason = f._evaluate(doc, ctx)
        assert reason is not None
        assert "DUA" in reason or "Data Use Agreement" in reason

    def test_limited_dataset_permitted_with_dua(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, data_use_agreement_signed=True)
        doc = _doc(m, phi=m.PHIClassification.LIMITED_DATASET)
        assert f._evaluate(doc, ctx) is None

    def test_de_identified_always_permitted(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR, irb_waiver_active=False)
        doc = _doc(m, phi=m.PHIClassification.DE_IDENTIFIED)
        assert f._evaluate(doc, ctx) is None

    def test_no_phi_always_permitted(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR)
        doc = _doc(m, phi=m.PHIClassification.NO_PHI)
        assert f._evaluate(doc, ctx) is None

    def test_public_doc_bypasses_hipaa(self, m):
        f = m.HIPAAFilter()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR, irb_waiver_active=False)
        doc = _doc(m, phi=m.PHIClassification.IDENTIFIED, is_public=True)
        assert f._evaluate(doc, ctx) is None


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------


class TestClinicalTrialRAGPipeline:

    def test_fully_compliant_investigator_own_site(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m)
        docs = [
            _doc(m, document_id="CRF-A", site_id="SITE-A"),
            _doc(m, document_id="IB-001",
                 doc_type=m.ClinicalDocumentType.INVESTIGATOR_BROCHURE,
                 gxp=m.GxPTier.GCP, phi=m.PHIClassification.NO_PHI, site_id=None),
        ]
        result = pipeline.retrieve(docs, ctx)
        assert len(result.permitted_documents) == 2

    def test_monitor_site_restricted(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.MONITOR,
                   assigned_site_ids=frozenset({"SITE-A"}))
        docs = [
            _doc(m, document_id="CRF-A", site_id="SITE-A"),
            _doc(m, document_id="CRF-B", site_id="SITE-B"),
        ]
        result = pipeline.retrieve(docs, ctx)
        permitted_ids = [d.document_id for d in result.permitted_documents]
        assert "CRF-A" in permitted_ids
        assert "CRF-B" not in permitted_ids
        assert result.audit.blocked_by_ich_e6 == 1

    def test_unvalidated_system_blocks_all_non_public(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m, system_validated=False)
        docs = [
            _doc(m, document_id="D1"),
            _doc(m, document_id="D2"),
            _doc(m, document_id="PUB-1", is_public=True),
        ]
        result = pipeline.retrieve(docs, ctx)
        assert result.audit.blocked_by_21cfr11 == 2
        assert len(result.permitted_documents) == 1
        assert result.permitted_documents[0].document_id == "PUB-1"

    def test_sponsor_blocked_from_blinded_interim(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.SPONSOR, database_locked=False)
        docs = [
            _doc(m, document_id="IA-001",
                 doc_type=m.ClinicalDocumentType.INTERIM_ANALYSIS,
                 gxp=m.GxPTier.GCP, phi=m.PHIClassification.DE_IDENTIFIED,
                 is_blinded=True, site_id=None),
            _doc(m, document_id="IB-001",
                 doc_type=m.ClinicalDocumentType.INVESTIGATOR_BROCHURE,
                 gxp=m.GxPTier.GCP, phi=m.PHIClassification.NO_PHI, site_id=None),
        ]
        result = pipeline.retrieve(docs, ctx)
        permitted_ids = [d.document_id for d in result.permitted_documents]
        assert "IB-001" in permitted_ids
        assert "IA-001" not in permitted_ids
        assert result.audit.blocked_by_ich_e6 == 1

    def test_regulatory_full_access(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m, user_role=m.ClinicalTrialRole.REGULATORY)
        docs = [
            _doc(m, document_id="BATCH-1",
                 doc_type=m.ClinicalDocumentType.BATCH_RECORD,
                 gxp=m.GxPTier.GMP, phi=m.PHIClassification.NO_PHI, site_id=None),
            _doc(m, document_id="RAW-1",
                 doc_type=m.ClinicalDocumentType.RAW_STUDY_DATA,
                 gxp=m.GxPTier.GLP, phi=m.PHIClassification.NO_PHI, site_id=None),
            _doc(m, document_id="IA-REG",
                 doc_type=m.ClinicalDocumentType.INTERIM_ANALYSIS,
                 gxp=m.GxPTier.GCP, phi=m.PHIClassification.IDENTIFIED,
                 is_blinded=True, site_id=None),
        ]
        result = pipeline.retrieve(docs, ctx)
        assert len(result.permitted_documents) == 3

    def test_audit_log_totals_consistent(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m)
        docs = [_doc(m, document_id=f"D-{i}") for i in range(5)]
        result = pipeline.retrieve(docs, ctx)
        total = (
            result.audit.permitted_documents
            + result.audit.blocked_by_21cfr11
            + result.audit.blocked_by_gxp
            + result.audit.blocked_by_ich_e6
            + result.audit.blocked_by_hipaa
        )
        assert total == result.audit.total_documents

    def test_audit_log_contains_user_info(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m, user_id="TEST-USER")
        result = pipeline.retrieve([_doc(m)], ctx)
        log = result.audit.to_audit_log()
        assert log["user_id"] == "TEST-USER"
        assert log["event"] == "RAG_RETRIEVAL"

    def test_empty_corpus(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m)
        result = pipeline.retrieve([], ctx)
        assert result.audit.total_documents == 0
        assert result.audit.permitted_documents == 0
        assert len(result.permitted_documents) == 0

    def test_hipaa_identified_phi_blocked_without_irb(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m, irb_waiver_active=False)
        docs = [_doc(m, phi=m.PHIClassification.IDENTIFIED)]
        result = pipeline.retrieve(docs, ctx)
        assert len(result.permitted_documents) == 0
        assert result.audit.blocked_by_hipaa == 1

    def test_block_reasons_reference_document_id(self, m):
        pipeline = m.ClinicalTrialRAGPipeline()
        ctx = _ctx(m, system_validated=False)
        docs = [_doc(m, document_id="DOC-XYZ")]
        result = pipeline.retrieve(docs, ctx)
        assert "DOC-XYZ" in result.block_reasons
