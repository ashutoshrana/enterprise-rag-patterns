"""
Tests for 25_digital_health_rag.py

Four-layer digital health / telehealth RAG pipeline:
  1. FDASaMDFilter — CLASS_I/II/III device clearance requirements
  2. Part2SUDFilter — 42 CFR Part 2 SUD record confidentiality
  3. HIPAASpecialCategoryFilter — psychotherapy notes, HIV, genetic, DV
  4. ONCInteroperabilityFilter — 21st Century Cures information blocking
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
    Path(__file__).parent.parent / "examples" / "25_digital_health_rag.py"
)


def _load_module():
    module_name = "digital_health_rag"
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
    """Fully compliant PRESCRIBER context."""
    defaults = dict(
        user_id="P001",
        user_role=m.DigitalHealthRole.PRESCRIBER,
        device_cleared=True,
        intended_use_documented=True,
        explicit_part2_consent=True,
        is_same_sud_program=False,
        hipaa_authorization_obtained=True,
        information_blocking_exception_applies=False,
        is_patient_self_access=False,
    )
    defaults.update(kwargs)
    return m.DigitalHealthContext(**defaults)


def _doc(m, doc_id="D001", samd_class=None, is_sud=False,
         special_category=None, is_public=False):
    samd_class = samd_class or m.SaMDClass.CLASS_II
    special_category = special_category or m.SpecialCategory.NONE
    return m.DigitalHealthDocument(
        document_id=doc_id,
        samd_class=samd_class,
        is_sud_record=is_sud,
        special_category=special_category,
        is_public=is_public,
    )


# ---------------------------------------------------------------------------
# Layer 1 — FDASaMDFilter
# ---------------------------------------------------------------------------


class TestFDASaMDFilter:

    def test_class_i_always_permitted(self, m):
        f = m.FDASaMDFilter()
        ctx = _ctx(m, device_cleared=False, intended_use_documented=False)
        doc = _doc(m, samd_class=m.SaMDClass.CLASS_I)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_class_ii_without_intended_use_blocked(self, m):
        f = m.FDASaMDFilter()
        ctx = _ctx(m, intended_use_documented=False)
        doc = _doc(m, samd_class=m.SaMDClass.CLASS_II)
        result = f._evaluate(ctx, doc)
        assert not result.permitted
        assert "Class II" in result.reason or "CLASS_II" in result.reason or "SaMD" in result.reason

    def test_class_ii_with_intended_use_permitted(self, m):
        f = m.FDASaMDFilter()
        ctx = _ctx(m, intended_use_documented=True)
        doc = _doc(m, samd_class=m.SaMDClass.CLASS_II)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_class_iii_without_clearance_blocked(self, m):
        f = m.FDASaMDFilter()
        ctx = _ctx(m, device_cleared=False)
        doc = _doc(m, samd_class=m.SaMDClass.CLASS_III)
        result = f._evaluate(ctx, doc)
        assert not result.permitted
        assert "510(k)" in result.reason or "PMA" in result.reason or "Class III" in result.reason

    def test_class_iii_cleared_no_intended_use_blocked(self, m):
        f = m.FDASaMDFilter()
        ctx = _ctx(m, device_cleared=True, intended_use_documented=False)
        doc = _doc(m, samd_class=m.SaMDClass.CLASS_III)
        result = f._evaluate(ctx, doc)
        assert not result.permitted
        assert "intended use" in result.reason.lower() or "intended_use" in result.reason.lower()

    def test_class_iii_cleared_with_intended_use_permitted(self, m):
        f = m.FDASaMDFilter()
        ctx = _ctx(m, device_cleared=True, intended_use_documented=True)
        doc = _doc(m, samd_class=m.SaMDClass.CLASS_III)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_public_doc_bypasses_samd(self, m):
        f = m.FDASaMDFilter()
        ctx = _ctx(m, device_cleared=False, intended_use_documented=False)
        doc = _doc(m, samd_class=m.SaMDClass.CLASS_III, is_public=True)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_filter_documents_returns_only_permitted(self, m):
        f = m.FDASaMDFilter()
        ctx = _ctx(m, device_cleared=False, intended_use_documented=False)
        docs = [
            _doc(m, "D1", samd_class=m.SaMDClass.CLASS_I),
            _doc(m, "D2", samd_class=m.SaMDClass.CLASS_III),
        ]
        permitted = f.filter_documents(ctx, docs)
        assert len(permitted) == 1
        assert permitted[0].document_id == "D1"


# ---------------------------------------------------------------------------
# Layer 2 — Part2SUDFilter
# ---------------------------------------------------------------------------


class TestPart2SUDFilter:

    def test_non_sud_record_passes(self, m):
        f = m.Part2SUDFilter()
        ctx = _ctx(m, explicit_part2_consent=False, is_same_sud_program=False)
        doc = _doc(m, is_sud=False)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_sud_without_consent_or_same_program_blocked(self, m):
        f = m.Part2SUDFilter()
        ctx = _ctx(m, explicit_part2_consent=False, is_same_sud_program=False)
        doc = _doc(m, is_sud=True)
        result = f._evaluate(ctx, doc)
        assert not result.permitted
        assert "42 CFR Part 2" in result.reason or "SUD" in result.reason or "Part 2" in result.reason

    def test_sud_with_explicit_consent_permitted(self, m):
        f = m.Part2SUDFilter()
        ctx = _ctx(m, explicit_part2_consent=True, is_same_sud_program=False)
        doc = _doc(m, is_sud=True)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_sud_same_program_permitted(self, m):
        f = m.Part2SUDFilter()
        ctx = _ctx(m, explicit_part2_consent=False, is_same_sud_program=True)
        doc = _doc(m, is_sud=True)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_sud_blocked_even_for_admin_without_consent(self, m):
        f = m.Part2SUDFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.ADMIN,
                   explicit_part2_consent=False, is_same_sud_program=False)
        doc = _doc(m, is_sud=True)
        result = f._evaluate(ctx, doc)
        assert not result.permitted

    def test_sud_consent_and_same_program_both_set_permitted(self, m):
        f = m.Part2SUDFilter()
        ctx = _ctx(m, explicit_part2_consent=True, is_same_sud_program=True)
        doc = _doc(m, is_sud=True)
        result = f._evaluate(ctx, doc)
        assert result.permitted


# ---------------------------------------------------------------------------
# Layer 3 — HIPAASpecialCategoryFilter
# ---------------------------------------------------------------------------


class TestHIPAASpecialCategoryFilter:

    def test_none_category_permitted_for_all_roles(self, m):
        f = m.HIPAASpecialCategoryFilter()
        for role in m.DigitalHealthRole:
            ctx = _ctx(m, user_role=role)
            doc = _doc(m, special_category=m.SpecialCategory.NONE)
            result = f._evaluate(ctx, doc)
            assert result.permitted, f"NONE should be permitted for {role}"

    def test_psychotherapy_notes_mental_health_provider_permitted(self, m):
        f = m.HIPAASpecialCategoryFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.MENTAL_HEALTH_PROVIDER)
        doc = _doc(m, special_category=m.SpecialCategory.PSYCHOTHERAPY_NOTES)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_psychotherapy_notes_prescriber_blocked(self, m):
        f = m.HIPAASpecialCategoryFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PRESCRIBER)
        doc = _doc(m, special_category=m.SpecialCategory.PSYCHOTHERAPY_NOTES)
        result = f._evaluate(ctx, doc)
        assert not result.permitted
        assert "164.524" in result.reason or "psychotherapy" in result.reason.lower()

    def test_psychotherapy_notes_patient_blocked(self, m):
        """45 CFR 164.524(a)(1)(i): Even patients cannot access psychotherapy notes."""
        f = m.HIPAASpecialCategoryFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PATIENT)
        doc = _doc(m, special_category=m.SpecialCategory.PSYCHOTHERAPY_NOTES)
        result = f._evaluate(ctx, doc)
        assert not result.permitted

    def test_hiv_clinical_role_permitted(self, m):
        f = m.HIPAASpecialCategoryFilter()
        for role in [m.DigitalHealthRole.PRESCRIBER,
                     m.DigitalHealthRole.CARE_MANAGER,
                     m.DigitalHealthRole.MENTAL_HEALTH_PROVIDER]:
            ctx = _ctx(m, user_role=role, hipaa_authorization_obtained=False)
            doc = _doc(m, special_category=m.SpecialCategory.HIV_STATUS)
            result = f._evaluate(ctx, doc)
            assert result.permitted, f"{role} should have HIV access"

    def test_hiv_data_analyst_without_auth_blocked(self, m):
        f = m.HIPAASpecialCategoryFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.DATA_ANALYST,
                   hipaa_authorization_obtained=False)
        doc = _doc(m, special_category=m.SpecialCategory.HIV_STATUS)
        result = f._evaluate(ctx, doc)
        assert not result.permitted

    def test_hiv_data_analyst_with_auth_permitted(self, m):
        f = m.HIPAASpecialCategoryFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.DATA_ANALYST,
                   hipaa_authorization_obtained=True)
        doc = _doc(m, special_category=m.SpecialCategory.HIV_STATUS)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_genetic_info_data_analyst_blocked_without_auth(self, m):
        f = m.HIPAASpecialCategoryFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.DATA_ANALYST,
                   hipaa_authorization_obtained=False)
        doc = _doc(m, special_category=m.SpecialCategory.GENETIC_INFO)
        result = f._evaluate(ctx, doc)
        assert not result.permitted
        assert "GINA" in result.reason or "genetic" in result.reason.lower()

    def test_domestic_violence_care_manager_blocked(self, m):
        f = m.HIPAASpecialCategoryFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.CARE_MANAGER)
        doc = _doc(m, special_category=m.SpecialCategory.DOMESTIC_VIOLENCE)
        result = f._evaluate(ctx, doc)
        assert not result.permitted

    def test_domestic_violence_prescriber_permitted(self, m):
        f = m.HIPAASpecialCategoryFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PRESCRIBER)
        doc = _doc(m, special_category=m.SpecialCategory.DOMESTIC_VIOLENCE)
        result = f._evaluate(ctx, doc)
        assert result.permitted


# ---------------------------------------------------------------------------
# Layer 4 — ONCInteroperabilityFilter
# ---------------------------------------------------------------------------


class TestONCInteroperabilityFilter:

    def test_clinical_role_passes_through(self, m):
        f = m.ONCInteroperabilityFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PRESCRIBER,
                   is_patient_self_access=False)
        doc = _doc(m)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_patient_self_access_permitted_no_exception(self, m):
        f = m.ONCInteroperabilityFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PATIENT,
                   is_patient_self_access=True,
                   information_blocking_exception_applies=False)
        doc = _doc(m)
        result = f._evaluate(ctx, doc)
        assert result.permitted

    def test_patient_self_access_blocked_with_exception(self, m):
        f = m.ONCInteroperabilityFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PATIENT,
                   is_patient_self_access=True,
                   information_blocking_exception_applies=True)
        doc = _doc(m, doc_id="D-RESTRICTED")
        result = f._evaluate(ctx, doc)
        assert not result.permitted
        assert "171" in result.reason or "blocking" in result.reason.lower()

    def test_patient_advocate_permitted_no_exception(self, m):
        f = m.ONCInteroperabilityFilter()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PATIENT_ADVOCATE,
                   is_patient_self_access=False,
                   information_blocking_exception_applies=False)
        doc = _doc(m)
        result = f._evaluate(ctx, doc)
        assert result.permitted


# ---------------------------------------------------------------------------
# DigitalHealthRAGPipeline
# ---------------------------------------------------------------------------


class TestDigitalHealthRAGPipeline:

    def test_fully_compliant_prescriber_permits_standard_docs(self, m):
        pipeline = m.DigitalHealthRAGPipeline()
        ctx = _ctx(m)
        docs = [
            _doc(m, "D1", samd_class=m.SaMDClass.CLASS_II),
            _doc(m, "D2", samd_class=m.SaMDClass.CLASS_I),
        ]
        result = pipeline.retrieve(ctx, docs)
        assert len(result.permitted_documents) == 2
        assert len(result.blocked_documents) == 0

    def test_analyst_sud_records_blocked(self, m):
        pipeline = m.DigitalHealthRAGPipeline()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.DATA_ANALYST,
                   explicit_part2_consent=False, is_same_sud_program=False)
        docs = [
            _doc(m, "SUD1", is_sud=True),
            _doc(m, "REG1", is_sud=False),
        ]
        result = pipeline.retrieve(ctx, docs)
        blocked_ids = {d.document_id for d in result.blocked_documents}
        assert "SUD1" in blocked_ids

    def test_patient_self_access_permitted(self, m):
        pipeline = m.DigitalHealthRAGPipeline()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PATIENT,
                   is_patient_self_access=True,
                   information_blocking_exception_applies=False)
        docs = [
            _doc(m, "REC1", samd_class=m.SaMDClass.CLASS_I),
        ]
        result = pipeline.retrieve(ctx, docs)
        assert "REC1" in {d.document_id for d in result.permitted_documents}

    def test_psychotherapy_notes_blocked_for_prescriber(self, m):
        pipeline = m.DigitalHealthRAGPipeline()
        ctx = _ctx(m, user_role=m.DigitalHealthRole.PRESCRIBER)
        docs = [
            _doc(m, "PSY1",
                 special_category=m.SpecialCategory.PSYCHOTHERAPY_NOTES),
        ]
        result = pipeline.retrieve(ctx, docs)
        assert "PSY1" in {d.document_id for d in result.blocked_documents}

    def test_audit_log_has_correct_structure(self, m):
        pipeline = m.DigitalHealthRAGPipeline()
        ctx = _ctx(m)
        docs = [_doc(m, "D1")]
        result = pipeline.retrieve(ctx, docs)
        audit = m.DigitalHealthAuditRecord(
            user_id=result.user_id,
            user_role=result.user_role,
            total_requested=len(docs),
            total_permitted=len(result.permitted_documents),
            total_blocked=len(result.blocked_documents),
        )
        log = audit.to_audit_log()
        assert log["event"] == "DIGITAL_HEALTH_RAG_RETRIEVAL"
        assert "user_id" in log
        assert "total_requested" in log

    def test_empty_documents_returns_empty_result(self, m):
        pipeline = m.DigitalHealthRAGPipeline()
        ctx = _ctx(m)
        result = pipeline.retrieve(ctx, [])
        assert len(result.permitted_documents) == 0
        assert len(result.blocked_documents) == 0

    def test_all_public_docs_permitted(self, m):
        pipeline = m.DigitalHealthRAGPipeline()
        ctx = _ctx(m, device_cleared=False, intended_use_documented=False)
        docs = [
            _doc(m, f"PUB{i}", samd_class=m.SaMDClass.CLASS_III, is_public=True)
            for i in range(3)
        ]
        result = pipeline.retrieve(ctx, docs)
        assert len(result.permitted_documents) == 3

    def test_block_reasons_keyed_by_document_id(self, m):
        pipeline = m.DigitalHealthRAGPipeline()
        ctx = _ctx(m, explicit_part2_consent=False, is_same_sud_program=False)
        docs = [_doc(m, "SUD-BLOCKED", is_sud=True)]
        result = pipeline.retrieve(ctx, docs)
        assert "SUD-BLOCKED" in result.block_reasons
