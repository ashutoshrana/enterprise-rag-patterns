"""Tests for enterprise_rag_patterns.compliance — FERPA context governance."""

from enterprise_rag_patterns.compliance import (
    AuditRecord,
    DisclosureReason,
    FERPAContextPolicy,
    RecordCategory,
    StudentIdentityScope,
    make_enrollment_advisor_policy,
)

# ---------------------------------------------------------------------------
# StudentIdentityScope
# ---------------------------------------------------------------------------


class TestStudentIdentityScope:
    def test_permits_directory_information_always(self):
        scope = StudentIdentityScope(
            student_id="S-1",
            institution_id="inst-a",
            requesting_user_id="agent",
            authorized_categories=set(),
        )
        assert scope.permits(RecordCategory.DIRECTORY_INFORMATION) is True

    def test_permits_authorized_category(self):
        scope = StudentIdentityScope(
            student_id="S-1",
            institution_id="inst-a",
            requesting_user_id="agent",
            authorized_categories={RecordCategory.ACADEMIC_RECORD},
        )
        assert scope.permits(RecordCategory.ACADEMIC_RECORD) is True

    def test_blocks_unauthorized_category(self):
        scope = StudentIdentityScope(
            student_id="S-1",
            institution_id="inst-a",
            requesting_user_id="agent",
            authorized_categories={RecordCategory.ACADEMIC_RECORD},
        )
        assert scope.permits(RecordCategory.FINANCIAL_RECORD) is False

    def test_blocks_all_protected_when_empty(self):
        scope = StudentIdentityScope(
            student_id="S-1",
            institution_id="inst-a",
            requesting_user_id="agent",
            authorized_categories=set(),
        )
        for cat in [
            RecordCategory.ACADEMIC_RECORD,
            RecordCategory.FINANCIAL_RECORD,
            RecordCategory.DISCIPLINARY_RECORD,
            RecordCategory.HEALTH_RECORD,
        ]:
            assert scope.permits(cat) is False


# ---------------------------------------------------------------------------
# FERPAContextPolicy.filter_retrieved_documents
# ---------------------------------------------------------------------------

DOCS = [
    {"doc_id": "own-academic", "student_id": "S-1", "institution_id": "inst-a", "record_category": "academic_record"},
    {"doc_id": "own-financial", "student_id": "S-1", "institution_id": "inst-a", "record_category": "financial_record"},
    {"doc_id": "other-student", "student_id": "S-2", "institution_id": "inst-a", "record_category": "academic_record"},
    {
        "doc_id": "other-institution",
        "student_id": "S-1",
        "institution_id": "inst-b",
        "record_category": "academic_record",
    },
    {"doc_id": "shared-kb", "institution_id": "inst-a"},  # no student_id — shared knowledge
    {"doc_id": "unknown-category", "student_id": "S-1", "institution_id": "inst-a", "record_category": "unknown_xyz"},
]


def _policy(authorized=None):
    scope = StudentIdentityScope(
        student_id="S-1",
        institution_id="inst-a",
        requesting_user_id="agent",
        authorized_categories=authorized or {RecordCategory.ACADEMIC_RECORD},
    )
    return FERPAContextPolicy(scope=scope)


class TestFERPAContextPolicyFilter:
    def test_allows_own_authorized_academic_record(self):
        safe = _policy().filter_retrieved_documents(DOCS)
        ids = [d["doc_id"] for d in safe]
        assert "own-academic" in ids

    def test_blocks_own_unauthorized_financial_record(self):
        safe = _policy().filter_retrieved_documents(DOCS)
        ids = [d["doc_id"] for d in safe]
        assert "own-financial" not in ids

    def test_blocks_different_student(self):
        safe = _policy().filter_retrieved_documents(DOCS)
        ids = [d["doc_id"] for d in safe]
        assert "other-student" not in ids

    def test_blocks_cross_institution(self):
        safe = _policy().filter_retrieved_documents(DOCS)
        ids = [d["doc_id"] for d in safe]
        assert "other-institution" not in ids

    def test_allows_shared_knowledge_base_doc(self):
        safe = _policy().filter_retrieved_documents(DOCS)
        ids = [d["doc_id"] for d in safe]
        assert "shared-kb" in ids

    def test_blocks_unknown_category(self):
        safe = _policy().filter_retrieved_documents(DOCS)
        ids = [d["doc_id"] for d in safe]
        assert "unknown-category" not in ids

    def test_cross_institution_block_disabled(self):
        scope = StudentIdentityScope(
            student_id="S-1",
            institution_id="inst-a",
            requesting_user_id="agent",
            authorized_categories={RecordCategory.ACADEMIC_RECORD},
        )
        policy = FERPAContextPolicy(scope=scope, block_cross_institution=False)
        safe = policy.filter_retrieved_documents(DOCS)
        ids = [d["doc_id"] for d in safe]
        assert "other-institution" in ids

    def test_financial_allowed_when_authorized(self):
        policy = _policy(authorized={RecordCategory.ACADEMIC_RECORD, RecordCategory.FINANCIAL_RECORD})
        safe = policy.filter_retrieved_documents(DOCS)
        ids = [d["doc_id"] for d in safe]
        assert "own-financial" in ids

    def test_empty_document_list(self):
        assert _policy().filter_retrieved_documents([]) == []

    def test_custom_field_names(self):
        docs = [
            {"id": "d1", "sid": "S-1", "iid": "inst-a", "cat": "academic_record"},
            {"id": "d2", "sid": "S-2", "iid": "inst-a", "cat": "academic_record"},
        ]
        safe = _policy().filter_retrieved_documents(
            docs,
            student_id_field="sid",
            institution_id_field="iid",
            category_field="cat",
        )
        assert len(safe) == 1
        assert safe[0]["id"] == "d1"


# ---------------------------------------------------------------------------
# FERPAContextPolicy.record_access
# ---------------------------------------------------------------------------


class TestFERPAContextPolicyAudit:
    def test_record_access_returns_audit_record(self):
        policy = _policy()
        audit = policy.record_access(
            categories_accessed=[RecordCategory.ACADEMIC_RECORD],
            workflow_context="test",
        )
        assert isinstance(audit, AuditRecord)
        assert audit.student_id == "S-1"
        assert audit.institution_id == "inst-a"

    def test_audit_sink_called(self):
        collected = []
        scope = StudentIdentityScope(
            student_id="S-1",
            institution_id="inst-a",
            requesting_user_id="agent",
            authorized_categories={RecordCategory.ACADEMIC_RECORD},
        )
        policy = FERPAContextPolicy(scope=scope, audit_sink=collected.append)
        policy.record_access(categories_accessed=[RecordCategory.ACADEMIC_RECORD])
        assert len(collected) == 1
        assert collected[0].student_id == "S-1"

    def test_audit_sink_not_called_when_none(self):
        policy = _policy()
        # Should not raise
        audit = policy.record_access(categories_accessed=[RecordCategory.ACADEMIC_RECORD])
        assert audit is not None

    def test_audit_record_log_entry_format(self):
        policy = _policy()
        audit = policy.record_access(
            categories_accessed=[RecordCategory.ACADEMIC_RECORD],
            workflow_context="graduation check",
        )
        log = audit.to_log_entry()
        assert "[FERPA_AUDIT]" in log
        assert "student=S-1" in log
        assert "institution=inst-a" in log
        assert "reason=school_official" in log
        assert "graduation check" in log

    def test_audit_record_id_is_unique(self):
        policy = _policy()
        ids = {policy.record_access(categories_accessed=[RecordCategory.ACADEMIC_RECORD]).record_id for _ in range(10)}
        assert len(ids) == 10


# ---------------------------------------------------------------------------
# make_enrollment_advisor_policy factory
# ---------------------------------------------------------------------------


class TestEnrollmentAdvisorFactory:
    def test_creates_policy_with_correct_scope(self):
        policy = make_enrollment_advisor_policy("S-42", "strayer", "advisor:1")
        assert policy.scope.student_id == "S-42"
        assert policy.scope.institution_id == "strayer"
        assert RecordCategory.ACADEMIC_RECORD in policy.scope.authorized_categories
        assert RecordCategory.DIRECTORY_INFORMATION in policy.scope.authorized_categories

    def test_does_not_authorize_financial_by_default(self):
        policy = make_enrollment_advisor_policy("S-42", "strayer", "advisor:1")
        assert RecordCategory.FINANCIAL_RECORD not in policy.scope.authorized_categories

    def test_disclosure_reason_is_school_official(self):
        policy = make_enrollment_advisor_policy("S-42", "strayer", "advisor:1")
        assert policy.scope.disclosure_reason == DisclosureReason.SCHOOL_OFFICIAL
