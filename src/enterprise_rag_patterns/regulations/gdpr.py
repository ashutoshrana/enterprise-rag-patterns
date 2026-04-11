"""
regulations/gdpr.py — GDPR Article 17 RAG-layer compliance patterns.

This module provides the RAG-pipeline-layer primitives for GDPR compliance —
specifically the "right to erasure" (right to be forgotten) as it applies to
retrieval-augmented generation systems.

**Scope of this module**: RAG-layer patterns only.  This is not a general-purpose
GDPR policy engine.  It addresses the specific problem of data subjects whose
personal data has been indexed in a vector store: when an erasure request is
received, the index must be rebuilt without the subject's data, and the operation
must be auditable.

Relevant regulations:
  GDPR Article 17 — Right to erasure ('right to be forgotten')
    Paragraph 1: The data subject shall have the right to obtain from the
    controller the erasure of personal data concerning him or her without
    undue delay.
  GDPR Article 17(3)(a): Erasure obligation does not apply where processing
    is necessary for exercising freedom of expression and information.

Implementation note:
  Vector stores do not natively support selective record deletion by
  subject identity when chunked documents span multiple vectors.  The
  recommended pattern is: (1) identify and delete all vectors tagged with
  the subject's identifier, (2) rebuild affected index segments from the
  filtered source corpus.  This module provides the audit trail for that
  workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class ErasureRequest:
    """
    Represents a GDPR Article 17 right-to-erasure request from a data subject.

    Attributes:
        subject_id: Unique identifier for the data subject (e.g., student ID,
            user ID, or any consistent internal identifier).  This value is
            used to locate and remove the subject's data from RAG indexes.
        request_id: Unique identifier for this erasure request, for audit
            correlation.
        requested_at: UTC timestamp when the request was received.
        regulation: Governing regulation; defaults to ``"GDPR"``.
    """

    subject_id: str
    request_id: str
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    regulation: str = "GDPR"


@dataclass(slots=True)
class ErasureAuditRecord:
    """
    Audit record for a completed GDPR Article 17 erasure operation.

    Captures the minimum fields needed to demonstrate compliance with
    GDPR Article 17 erasure obligations in a RAG system: which subject's
    data was removed, how many documents were affected, and whether the
    index was rebuilt.

    Attributes:
        request_id: Correlates to the originating ``ErasureRequest.request_id``.
        subject_id: Identifier of the data subject whose data was erased.
        documents_removed: Number of source documents removed from the pipeline.
        index_rebuilt: Whether the vector index was rebuilt after removal,
            ensuring no residual vectors for the subject remain.
        completed_at: UTC timestamp when the erasure operation completed.
    """

    request_id: str
    subject_id: str
    documents_removed: int
    index_rebuilt: bool
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_log_entry(self) -> dict[str, object]:
        """
        Serialise this audit record to a structured log dict.

        The returned dict contains all fields required for a GDPR Article 17
        compliance audit trail.  Persist this dict to a tamper-evident log
        store (e.g., Google Cloud Logging, AWS CloudTrail, or an append-only
        database table).

        Returns:
            A ``dict`` with string keys and JSON-serialisable values.
        """
        return {
            "event": "gdpr_erasure_completed",
            "regulation": "GDPR",
            "citation": "GDPR Article 17",
            "request_id": self.request_id,
            "subject_id": self.subject_id,
            "documents_removed": self.documents_removed,
            "index_rebuilt": self.index_rebuilt,
            "completed_at": self.completed_at.isoformat(),
        }


class GDPRRAGPolicy:
    """
    RAG-layer policy primitives for GDPR Article 17 (right to erasure) compliance.

    This class provides two concerns:

    1. **Document filtering**: Remove a data subject's documents from an
       in-memory corpus before indexing or before passing to the LLM.
    2. **Erasure audit recording**: Create a structured ``ErasureAuditRecord``
       after a successful erasure operation.

    Typical workflow::

        policy = GDPRRAGPolicy()

        # 1. Receive an Article 17 request
        request = ErasureRequest(subject_id="U-123", request_id="req-456")

        # 2. Filter the source corpus (run before re-indexing)
        original_docs = load_all_documents()
        filtered_docs = policy.filter_for_subject(original_docs, subject_id_field="subject_id")
        removed = len(original_docs) - len(filtered_docs)

        # 3. Rebuild the vector index from filtered_docs
        rebuild_vector_index(filtered_docs)

        # 4. Record the erasure for compliance audit
        audit_record = policy.record_erasure(request, removed_count=removed, index_rebuilt=True)
        persist_to_audit_log(audit_record.to_log_entry())

    Regulatory reference:
        GDPR Article 17 — Right to erasure ('right to be forgotten').
    """

    def filter_for_subject(
        self,
        documents: list[dict[str, object]],
        subject_id_field: str = "subject_id",
        subject_id: str | None = None,
    ) -> list[dict[str, object]]:
        """
        Remove all documents belonging to a specific data subject.

        Filters a list of document dicts, returning only those that do NOT
        match the given subject identifier.  Call this before re-indexing
        a corpus after receiving a GDPR Article 17 erasure request.

        Documents without the ``subject_id_field`` key are retained (assumed
        to be non-personal general content).

        Args:
            documents: List of document dicts, each optionally containing a
                subject identifier field.
            subject_id_field: Key name for the subject identifier in each
                document dict.  Defaults to ``"subject_id"``.
            subject_id: The identifier of the data subject whose documents
                should be removed.  When ``None``, no documents are removed
                (safe no-op, useful for dry-run testing).

        Returns:
            Filtered list with the subject's documents removed.
        """
        if subject_id is None:
            return list(documents)

        return [doc for doc in documents if doc.get(subject_id_field) != subject_id]

    def record_erasure(
        self,
        request: ErasureRequest,
        removed_count: int,
        index_rebuilt: bool,
    ) -> ErasureAuditRecord:
        """
        Create an ``ErasureAuditRecord`` for a completed Article 17 erasure.

        Call this immediately after the erasure operation completes (documents
        removed and, if applicable, the index rebuilt).

        Args:
            request: The originating ``ErasureRequest``.
            removed_count: Number of documents removed from the corpus/index.
            index_rebuilt: ``True`` if the vector index was rebuilt from the
                filtered corpus; ``False`` if only logical deletion was performed.

        Returns:
            An ``ErasureAuditRecord`` with a UTC ``completed_at`` timestamp.

        Regulatory reference:
            GDPR Article 17(1) — erasure without undue delay; Article 5(1)(f) —
            integrity and confidentiality principle.
        """
        return ErasureAuditRecord(
            request_id=request.request_id,
            subject_id=request.subject_id,
            documents_removed=removed_count,
            index_rebuilt=index_rebuilt,
        )
