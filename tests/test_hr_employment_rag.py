"""
Tests for 23_hr_employment_rag.py

Three-layer HR/employment RAG pipeline:
  Layer 1: NYC Local Law 144 (AEDT bias audit + notice)
  Layer 2: EEOC AI Guidance + Title VII / ADEA (4/5 rule)
  Layer 3: Illinois AI Video Interview Act (AIVIA consent)
"""

import importlib.util
import sys
import types
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------

_MOD_PATH = Path(__file__).parent.parent / "examples" / "23_hr_employment_rag.py"


def _load_module():
    module_name = "hr_employment_rag"
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
    """Default: NYC employer, all compliant, 0.88 selection rate, consented."""
    defaults = dict(
        user_id="HR-TEST",
        employer_jurisdiction=frozenset({"NYC", "NY"}),
        aedt_bias_audit_completed=True,
        aedt_audit_impact_ratios_acceptable=True,
        aedt_candidate_notice_given=True,
        eeoc_selection_rate_ratio=0.88,
        eeoc_testing_sample_adequate=True,
        aivia_candidate_consented=True,
        aivia_disclosure_provided=True,
        candidate_requested_video_deletion=False,
    )
    defaults.update(kwargs)
    return m.CandidateAccessContext(**defaults)


def _doc(m, category=None, **kwargs):
    """Default: RESUME_SCREENING_CRITERIA, not publicly releasable."""
    defaults = dict(
        document_id=str(uuid.uuid4()),
        title="Test Document",
        category=category or m.HRDocumentCategory.RESUME_SCREENING_CRITERIA,
        candidate_id=None,
        is_publicly_releasable=False,
    )
    defaults.update(kwargs)
    return m.HRDocument(**defaults)


# ---------------------------------------------------------------------------
# Layer 1 — NYC LL 144 filter
# ---------------------------------------------------------------------------


class TestNYCLL144Filter:
    def test_permits_aedt_output_when_fully_compliant(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m)
        doc = _doc(m, category=m.HRDocumentCategory.RESUME_SCREENING_CRITERIA)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1
        assert audit.nyc_ll144_permitted == 1

    def test_blocks_aedt_output_no_audit(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m, aedt_bias_audit_completed=False)
        doc = _doc(m, category=m.HRDocumentCategory.AUTOMATED_RANKING)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "NYC LL 144" in audit.block_reasons[0]["reason"]

    def test_blocks_aedt_output_unacceptable_impact_ratio(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m, aedt_audit_impact_ratios_acceptable=False)
        doc = _doc(m, category=m.HRDocumentCategory.CANDIDATE_SCORING_RUBRIC)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "impact ratio" in audit.block_reasons[0]["reason"].lower()

    def test_blocks_aedt_output_no_candidate_notice(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m, aedt_candidate_notice_given=False)
        doc = _doc(m, category=m.HRDocumentCategory.SKILL_ASSESSMENT_RESULT)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "notice" in audit.block_reasons[0]["reason"].lower()

    def test_nyc_rule_does_not_apply_outside_nyc(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m, employer_jurisdiction=frozenset({"TX"}),
                   aedt_bias_audit_completed=False)
        doc = _doc(m, category=m.HRDocumentCategory.AUTOMATED_RANKING)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1  # Non-NYC employer not subject to LL 144

    def test_permits_publicly_releasable_regardless_of_compliance(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m, aedt_bias_audit_completed=False)
        doc = _doc(m, category=m.HRDocumentCategory.AEDT_BIAS_AUDIT_SUMMARY,
                   is_publicly_releasable=True)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_non_aedt_doc_not_subject_to_nyc_rule(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m, aedt_bias_audit_completed=False)
        doc = _doc(m, category=m.HRDocumentCategory.JOB_DESCRIPTION)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_all_aedt_categories_blocked_when_no_audit(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m, aedt_bias_audit_completed=False)
        aedt_cats = [
            m.HRDocumentCategory.CANDIDATE_SCORING_RUBRIC,
            m.HRDocumentCategory.RESUME_SCREENING_CRITERIA,
            m.HRDocumentCategory.SKILL_ASSESSMENT_RESULT,
            m.HRDocumentCategory.AUTOMATED_RANKING,
        ]
        for cat in aedt_cats:
            doc = _doc(m, category=cat)
            audit = m.HRComplianceAuditRecord("Q", "U")
            result = f.filter([doc], ctx, audit)
            assert result == [], f"Expected {cat} to be blocked without audit"

    def test_block_reason_has_document_id(self, m):
        f = m.NYCLL144Filter()
        ctx = _ctx(m, aedt_bias_audit_completed=False)
        doc = _doc(m, document_id="TEST-DOC-777",
                   category=m.HRDocumentCategory.AUTOMATED_RANKING)
        audit = m.HRComplianceAuditRecord("Q", "U")
        f.filter([doc], ctx, audit)
        assert audit.block_reasons[0]["document_id"] == "TEST-DOC-777"
        assert audit.block_reasons[0]["layer"] == "NYC_LL144"


# ---------------------------------------------------------------------------
# Layer 2 — EEOC filter
# ---------------------------------------------------------------------------


class TestEEOCFilter:
    def test_permits_when_ratio_above_threshold(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.85)
        doc = _doc(m, category=m.HRDocumentCategory.EEO_DEMOGRAPHIC_DATA)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_blocks_protected_class_data_below_threshold(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.68)
        doc = _doc(m, category=m.HRDocumentCategory.EEO_DEMOGRAPHIC_DATA)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "EEOC" in audit.block_reasons[0]["reason"]

    def test_blocks_protected_class_data_insufficient_sample(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_testing_sample_adequate=False)
        doc = _doc(m, category=m.HRDocumentCategory.IMPACT_RATIO_BY_PROTECTED_CLASS)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "inadequate" in audit.block_reasons[0]["reason"].lower()

    def test_blocks_protected_class_data_no_ratio_calculated(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=None)
        doc = _doc(m, category=m.HRDocumentCategory.AGE_CORRELATED_FEATURE_WEIGHTS)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0

    def test_blocks_aedt_output_when_disparate_impact_confirmed(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.71, eeoc_testing_sample_adequate=True)
        doc = _doc(m, category=m.HRDocumentCategory.AUTOMATED_RANKING)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0

    def test_permits_aedt_output_when_ratio_adequate(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.90)
        doc = _doc(m, category=m.HRDocumentCategory.RESUME_SCREENING_CRITERIA)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_permits_job_description_regardless_of_ratio(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.50)
        doc = _doc(m, category=m.HRDocumentCategory.JOB_DESCRIPTION)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_permits_publicly_releasable_regardless_of_ratio(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.50)
        doc = _doc(m, category=m.HRDocumentCategory.EEO_DEMOGRAPHIC_DATA,
                   is_publicly_releasable=True)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_threshold_boundary_at_exactly_080(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.80)
        doc = _doc(m, category=m.HRDocumentCategory.EEO_DEMOGRAPHIC_DATA)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        # 0.80 is not less than threshold → permitted
        assert len(result) == 1

    def test_all_protected_class_categories_blocked(self, m):
        f = m.EEOCFilter()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.65, eeoc_testing_sample_adequate=True)
        protected_cats = [
            m.HRDocumentCategory.EEO_DEMOGRAPHIC_DATA,
            m.HRDocumentCategory.IMPACT_RATIO_BY_PROTECTED_CLASS,
            m.HRDocumentCategory.AGE_CORRELATED_FEATURE_WEIGHTS,
        ]
        for cat in protected_cats:
            doc = _doc(m, category=cat)
            audit = m.HRComplianceAuditRecord("Q", "U")
            result = f.filter([doc], ctx, audit)
            assert result == [], f"Expected {cat} to be blocked with disparate impact"


# ---------------------------------------------------------------------------
# Layer 3 — AIVIA filter
# ---------------------------------------------------------------------------


class TestAIVIAFilter:
    def test_permits_video_when_consented_and_disclosed(self, m):
        f = m.AIVIAFilter()
        ctx = _ctx(m, aivia_candidate_consented=True, aivia_disclosure_provided=True)
        doc = _doc(m, category=m.HRDocumentCategory.VIDEO_AI_ANALYSIS_REPORT)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_blocks_video_no_consent(self, m):
        f = m.AIVIAFilter()
        ctx = _ctx(m, aivia_candidate_consented=False, aivia_disclosure_provided=True)
        doc = _doc(m, category=m.HRDocumentCategory.VIDEO_INTERVIEW_RECORDING)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "AIVIA" in audit.block_reasons[0]["reason"]

    def test_blocks_video_no_disclosure(self, m):
        f = m.AIVIAFilter()
        ctx = _ctx(m, aivia_candidate_consented=True, aivia_disclosure_provided=False)
        doc = _doc(m, category=m.HRDocumentCategory.VIDEO_TRANSCRIPT)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "disclosure" in audit.block_reasons[0]["reason"].lower()

    def test_blocks_video_on_deletion_request(self, m):
        f = m.AIVIAFilter()
        ctx = _ctx(m, aivia_candidate_consented=True, aivia_disclosure_provided=True,
                   candidate_requested_video_deletion=True)
        doc = _doc(m, category=m.HRDocumentCategory.VIDEO_AI_ANALYSIS_REPORT)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 0
        assert "deletion" in audit.block_reasons[0]["reason"].lower()

    def test_deletion_request_blocks_all_video_categories(self, m):
        f = m.AIVIAFilter()
        ctx = _ctx(m, candidate_requested_video_deletion=True)
        video_cats = [
            m.HRDocumentCategory.VIDEO_INTERVIEW_RECORDING,
            m.HRDocumentCategory.VIDEO_AI_ANALYSIS_REPORT,
            m.HRDocumentCategory.VIDEO_TRANSCRIPT,
        ]
        for cat in video_cats:
            doc = _doc(m, category=cat)
            audit = m.HRComplianceAuditRecord("Q", "U")
            result = f.filter([doc], ctx, audit)
            assert result == [], f"Expected {cat} blocked on deletion request"

    def test_non_video_not_subject_to_aivia(self, m):
        f = m.AIVIAFilter()
        ctx = _ctx(m, aivia_candidate_consented=False)
        doc = _doc(m, category=m.HRDocumentCategory.JOB_DESCRIPTION)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1

    def test_publicly_releasable_video_permitted(self, m):
        f = m.AIVIAFilter()
        ctx = _ctx(m, aivia_candidate_consented=False)
        doc = _doc(m, category=m.HRDocumentCategory.VIDEO_AI_ANALYSIS_REPORT,
                   is_publicly_releasable=True)
        audit = m.HRComplianceAuditRecord("Q", "U")
        result = f.filter([doc], ctx, audit)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Full pipeline tests
# ---------------------------------------------------------------------------


class TestHRRAGPipeline:
    def _corpus(self, m):
        return [
            _doc(m, document_id="AEDT-001", category=m.HRDocumentCategory.AUTOMATED_RANKING),
            _doc(m, document_id="VIDEO-001", category=m.HRDocumentCategory.VIDEO_AI_ANALYSIS_REPORT),
            _doc(m, document_id="EEO-001", category=m.HRDocumentCategory.EEO_DEMOGRAPHIC_DATA),
            _doc(m, document_id="JD-001", category=m.HRDocumentCategory.JOB_DESCRIPTION),
            _doc(m, document_id="PUB-001", category=m.HRDocumentCategory.AEDT_BIAS_AUDIT_SUMMARY,
                 is_publicly_releasable=True),
        ]

    def test_fully_compliant_all_permitted(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m)
        docs, audit = pipeline.retrieve(self._corpus(m), ctx)
        assert len(docs) == 5
        assert audit.final_blocked == 0

    def test_no_audit_blocks_aedt_only(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m, aedt_bias_audit_completed=False)
        docs, audit = pipeline.retrieve(self._corpus(m), ctx)
        doc_ids = [d.document_id for d in docs]
        assert "AEDT-001" not in doc_ids
        assert "VIDEO-001" in doc_ids
        assert "PUB-001" in doc_ids

    def test_no_video_consent_blocks_video_only(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m, aivia_candidate_consented=False)
        docs, audit = pipeline.retrieve(self._corpus(m), ctx)
        doc_ids = [d.document_id for d in docs]
        assert "VIDEO-001" not in doc_ids
        assert "AEDT-001" in doc_ids

    def test_disparate_impact_blocks_eeo_and_aedt(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m, eeoc_selection_rate_ratio=0.65, eeoc_testing_sample_adequate=True)
        docs, audit = pipeline.retrieve(self._corpus(m), ctx)
        doc_ids = [d.document_id for d in docs]
        assert "EEO-001" not in doc_ids
        assert "AEDT-001" not in doc_ids

    def test_audit_record_totals_consistent(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m)
        _, audit = pipeline.retrieve(self._corpus(m), ctx)
        assert audit.total_candidates == 5
        assert audit.final_permitted + audit.final_blocked == 5

    def test_audit_log_structure(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m)
        _, audit = pipeline.retrieve(self._corpus(m), ctx)
        log = audit.to_audit_log()
        assert "query_id" in log
        assert "layers" in log
        assert "nyc_ll144" in log["layers"]
        assert "eeoc" in log["layers"]
        assert "aivia" in log["layers"]
        assert "final" in log

    def test_empty_corpus(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m)
        docs, audit = pipeline.retrieve([], ctx)
        assert docs == []
        assert audit.total_candidates == 0
        assert audit.final_permitted == 0
        assert audit.final_blocked == 0

    def test_user_id_in_audit(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m, user_id="HR-AUDIT-USER")
        _, audit = pipeline.retrieve([], ctx)
        assert audit.user_id == "HR-AUDIT-USER"

    def test_non_nyc_employer_aedt_not_blocked_by_ll144(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m, employer_jurisdiction=frozenset({"CA"}),
                   aedt_bias_audit_completed=False)
        corpus = [_doc(m, category=m.HRDocumentCategory.AUTOMATED_RANKING)]
        docs, audit = pipeline.retrieve(corpus, ctx)
        # LLC 144 doesn't apply to non-NYC employers
        assert len(docs) == 1

    def test_block_reasons_reference_correct_layer(self, m):
        pipeline = m.HRRAGPipeline()
        ctx = _ctx(m, aedt_bias_audit_completed=False,
                   aivia_candidate_consented=False,
                   eeoc_selection_rate_ratio=0.60, eeoc_testing_sample_adequate=True)
        corpus = [
            _doc(m, document_id="A", category=m.HRDocumentCategory.AUTOMATED_RANKING),
            _doc(m, document_id="V", category=m.HRDocumentCategory.VIDEO_AI_ANALYSIS_REPORT),
            _doc(m, document_id="E", category=m.HRDocumentCategory.EEO_DEMOGRAPHIC_DATA),
        ]
        _, audit = pipeline.retrieve(corpus, ctx)
        layers = {r["layer"] for r in audit.block_reasons}
        assert "NYC_LL144" in layers
        assert "AIVIA" in layers
