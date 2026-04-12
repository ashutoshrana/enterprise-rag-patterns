"""
compliance.py — FERPA-Aware Context Governance for Enterprise RAG Pipelines

FERPA (Family Educational Rights and Privacy Act, 20 U.S.C. § 1232g;
implementing regulations at 34 CFR Part 99) requires institutions to
control access to education records. Standard RAG pipelines do not enforce
these boundaries — they retrieve whatever the retrieval index finds. In
multi-tenant higher education environments, that creates FERPA exposure:
a student record from one enrollment state or one institution can surface
in an AI response scoped to a different user.

This module provides the policy primitives to enforce FERPA boundaries in
retrieval-augmented workflows. It does not replace institutional legal review
but provides the architectural layer that makes FERPA compliance
mechanically enforceable rather than manually audited.

The patterns are cloud-agnostic and platform-agnostic. They work with any
vector store (Pinecone, Weaviate, pgvector, Chroma, OpenSearch, etc.), any
LLM provider, and any cloud environment (AWS, GCP, Azure, OCI). The same
structural pattern applies to other regulated-access frameworks (HIPAA, GLBA)
by substituting the appropriate record categories and disclosure rules.

Key regulations referenced:
  34 CFR § 99.3   — Definitions (education records, legitimate educational interest)
  34 CFR § 99.31  — Conditions for disclosure without consent
  34 CFR § 99.32  — Record of disclosures (audit log requirement)
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class RecordCategory(Enum):
    """
    Categories of education records under FERPA.

    FERPA distinguishes between records that require consent for disclosure
    (protected records) and directory information that institutions may
    disclose without consent if the student has not opted out.
    """

    DIRECTORY_INFORMATION = "directory_information"  # Name, enrollment status, major — disclosable
    ACADEMIC_RECORD = "academic_record"  # Grades, transcripts — protected
    FINANCIAL_RECORD = "financial_record"  # Financial aid, billing — protected
    DISCIPLINARY_RECORD = "disciplinary_record"  # Conduct records — protected
    HEALTH_RECORD = "health_record"  # Campus health, accommodations — protected
    SYSTEM_GENERATED = "system_generated"  # AI-generated context, workflow state


class DisclosureReason(Enum):
    """
    Legitimate educational interest exceptions under 34 CFR § 99.31.

    FERPA allows disclosure without consent under specific conditions.
    Each access to protected records must map to one of these reasons.
    """

    SCHOOL_OFFICIAL = "school_official"  # § 99.31(a)(1) — legitimate educational interest
    AUDIT_EVALUATION = "audit_evaluation"  # § 99.31(a)(3) — authorized audit
    COURT_ORDER = "court_order"  # § 99.31(a)(9) — judicial order
    HEALTH_SAFETY = "health_safety"  # § 99.31(a)(10) — emergency
    SELF_SERVICE = "self_service"  # Student accessing their own records


@dataclass(slots=True)
class StudentIdentityScope:
    """
    Defines the boundary of student identity for one retrieval request.

    A RAG pipeline operating on student records must know exactly which
    student's records it is authorized to retrieve. This scope object
    ensures retrieval filters are applied before records enter the
    LLM context window — not after.

    Attributes:
        student_id: Unique institutional identifier for the student.
        institution_id: Institution whose records are authorized for retrieval.
            In a multi-institution deployment (e.g., Strayer + Capella),
            records from institution A must never appear in a session
            scoped to institution B.
        requesting_user_id: The agent, staff member, or system requesting access.
        authorized_categories: Which record categories may be retrieved.
        disclosure_reason: Legal basis for this access under 34 CFR § 99.31.
        consent_on_file: Whether the student has provided written consent
            for disclosures that go beyond the standard exceptions.
    """

    student_id: str
    institution_id: str
    requesting_user_id: str
    authorized_categories: set[RecordCategory] = field(default_factory=set)
    disclosure_reason: DisclosureReason = DisclosureReason.SCHOOL_OFFICIAL
    consent_on_file: bool = False

    def permits(self, category: RecordCategory) -> bool:
        """Return True if this scope authorizes retrieval of the given record category."""
        if category == RecordCategory.DIRECTORY_INFORMATION:
            return True  # Directory information does not require scope authorization
        return category in self.authorized_categories


@dataclass(slots=True)
class AuditRecord:
    """
    FERPA 34 CFR § 99.32 requires institutions to maintain a record of each
    request for access to a student's education records and the reason for access.

    This dataclass captures the minimum required audit fields. Institutions
    should persist these records for at least one academic year and make
    them available to students on request.

    Reference: 34 CFR § 99.32 — Record of disclosures required
    """

    record_id: str
    student_id: str
    institution_id: str
    requesting_user_id: str
    categories_accessed: list[RecordCategory]
    disclosure_reason: DisclosureReason
    access_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    workflow_context: str = ""  # Brief description of the workflow or use case
    retrieval_query_hash: str = ""  # SHA-256 of the retrieval query (not the result) for audit traceability

    def to_log_entry(self) -> str:
        """Format a structured log entry suitable for institutional audit systems."""
        categories = ", ".join(c.value for c in self.categories_accessed)
        return (
            f"[FERPA_AUDIT] record_id={self.record_id} "
            f"student={self.student_id} "
            f"institution={self.institution_id} "
            f"requester={self.requesting_user_id} "
            f"categories=[{categories}] "
            f"reason={self.disclosure_reason.value} "
            f"timestamp={self.access_timestamp.isoformat()} "
            f"context={self.workflow_context!r}"
        )


@dataclass
class FERPAContextPolicy:
    """
    Governs what records may enter the LLM context window for a given request.

    This is the central enforcement object. It wraps the retrieval step of
    a RAG pipeline and ensures that:
    1. Retrieved documents are filtered to the authorized scope before
       they are assembled into the context envelope.
    2. Every retrieval operation that touches protected records generates
       an audit record (34 CFR § 99.32).
    3. Cross-institution contamination is blocked at the policy layer,
       not at the prompt layer.

    Usage::

        policy = FERPAContextPolicy(
            scope=StudentIdentityScope(
                student_id="S-12345",
                institution_id="strayer",
                requesting_user_id="agent:enrollment_advisor",
                authorized_categories={RecordCategory.ACADEMIC_RECORD},
                disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
            ),
            audit_sink=my_audit_logger,
        )

        # Before passing retrieved docs to the LLM:
        safe_docs = policy.filter_retrieved_documents(raw_docs)
        audit_entry = policy.record_access(
            categories_accessed=[RecordCategory.ACADEMIC_RECORD],
            workflow_context="enrollment status check",
            query_hash=sha256_of_query,
        )

    Attributes:
        scope: The authorized access scope for this request.
        audit_sink: Callable that receives AuditRecord objects for persistence.
            In production, this should write to a durable, tamper-evident store.
        block_cross_institution: If True (default), documents tagged with a
            different institution_id than scope.institution_id are always blocked.
    """

    scope: StudentIdentityScope
    audit_sink: Callable[[AuditRecord], None] | None = None
    block_cross_institution: bool = True

    def filter_retrieved_documents(
        self,
        documents: list[dict[str, object]],
        student_id_field: str = "student_id",
        institution_id_field: str = "institution_id",
        category_field: str = "record_category",
    ) -> list[dict[str, object]]:
        """
        Filter a list of retrieved documents to only those authorized by this policy.

        Documents are excluded if:
        - They are tagged to a different student than scope.student_id
        - They are tagged to a different institution than scope.institution_id
          (when block_cross_institution is True)
        - Their record_category is not authorized by the scope

        Documents without any of these fields are assumed to be non-FERPA
        content (e.g., knowledge base articles, policies) and are passed through.

        Args:
            documents: List of retrieved document dicts, each optionally containing
                student_id, institution_id, and record_category fields.
            student_id_field: Key for the student identity field in each document.
            institution_id_field: Key for the institution identity field.
            category_field: Key for the record category field (should contain
                a RecordCategory value string).

        Returns:
            Filtered list of documents safe to include in LLM context.
        """
        safe_documents = []
        for doc in documents:
            # Cross-institution check
            doc_institution = doc.get(institution_id_field)
            if (
                self.block_cross_institution
                and doc_institution is not None
                and doc_institution != self.scope.institution_id
            ):
                continue

            # Student identity check
            doc_student = doc.get(student_id_field)
            if doc_student is not None and doc_student != self.scope.student_id:
                continue

            # Record category authorization check
            doc_category_str = doc.get(category_field)
            if doc_category_str is not None:
                try:
                    doc_category = RecordCategory(doc_category_str)
                    if not self.scope.permits(doc_category):
                        continue
                except ValueError:
                    # Unknown category — treat as unclassified and block
                    continue

            safe_documents.append(doc)

        return safe_documents

    def record_access(
        self,
        categories_accessed: list[RecordCategory],
        workflow_context: str = "",
        query_hash: str = "",
    ) -> AuditRecord:
        """
        Create and persist a FERPA 34 CFR § 99.32 audit record for this access.

        Call this once per retrieval operation that touches protected records.
        The audit record is created and passed to audit_sink if one is configured.

        Args:
            categories_accessed: Which record categories were actually retrieved.
            workflow_context: Human-readable description of the workflow.
            query_hash: SHA-256 hash of the retrieval query (not the result).

        Returns:
            The created AuditRecord (also passed to audit_sink).
        """
        audit = AuditRecord(
            record_id=str(uuid.uuid4()),
            student_id=self.scope.student_id,
            institution_id=self.scope.institution_id,
            requesting_user_id=self.scope.requesting_user_id,
            categories_accessed=categories_accessed,
            disclosure_reason=self.scope.disclosure_reason,
            workflow_context=workflow_context,
            retrieval_query_hash=query_hash,
        )

        if self.audit_sink is not None:
            self.audit_sink(audit)

        return audit


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def make_enrollment_advisor_policy(
    student_id: str,
    institution_id: str,
    advisor_id: str,
    audit_sink: Callable[[AuditRecord], None] | None = None,
) -> FERPAContextPolicy:
    """
    Factory for the most common higher-education RAG use case:
    an enrollment advisor or AI agent assisting a student with
    enrollment status, course registration, and academic planning.

    Authorizes access to academic records and directory information.
    Does NOT authorize financial or disciplinary records without
    additional explicit scope.
    """
    scope = StudentIdentityScope(
        student_id=student_id,
        institution_id=institution_id,
        requesting_user_id=advisor_id,
        authorized_categories={
            RecordCategory.ACADEMIC_RECORD,
            RecordCategory.DIRECTORY_INFORMATION,
        },
        disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
    )
    return FERPAContextPolicy(scope=scope, audit_sink=audit_sink)
