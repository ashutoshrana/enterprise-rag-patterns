from __future__ import annotations

"""
Weaviate v4 Compliance RAG Pipeline
====================================

Demonstrates a multi-layer regulatory compliance pipeline that wraps Weaviate
vector store retrieval with FERPA and HIPAA pre/post filters, a disclosure record
builder, and a context assembler for LLM consumption.

Use-Case Table
--------------
| Platform                         | Regulations                         |
|----------------------------------|-------------------------------------|
| University student portals       | FERPA 34 CFR §99.31                 |
| Healthcare patient knowledge     | HIPAA 45 CFR §164                   |
| Hybrid student health clinics    | FERPA + HIPAA                       |
| Financial aid document search    | FERPA §99.31(a)(4)                  |

Regulatory Context (Layer by Layer)
-------------------------------------
Layer 1 - FERPA Identity Scope Filter:
    The Family Educational Rights and Privacy Act (FERPA), codified at 20 U.S.C.
    §1232g and implemented at 34 CFR Part 99, governs access to education records.
    Under 34 CFR §99.31(a)(1), a school may disclose education records to the
    student themselves without prior consent. Before any Weaviate query executes,
    this layer builds a filter that restricts retrieved documents to those owned
    by the requesting student's ID and institution. Documents belonging to other
    students are excluded at the database query level, not after retrieval — this
    is important because it prevents incidental exposure of metadata.

Layer 2 - HIPAA PHI Pre-Filter:
    The Health Insurance Portability and Accountability Act (HIPAA), implemented
    at 45 CFR Part 164 (Privacy Rule), restricts disclosure of protected health
    information (PHI). Under 45 CFR §164.502(a), a covered entity may not disclose
    PHI except as permitted by the rule. In hybrid student-health settings (e.g.,
    a university health clinic), documents retrieved from Weaviate may carry PHI
    indicators (record_type="medical", contains_phi=True). This layer inspects
    retrieved document metadata and removes any PHI-tagged documents unless the
    requester holds a valid Business Associate Agreement (BAA) token, a contractual
    prerequisite for PHI disclosure under 45 CFR §164.504(e).

Layer 3 - Disclosure Record Builder:
    FERPA 34 CFR §99.32 requires that educational institutions maintain a record
    of each disclosure of education records. Each time records are retrieved and
    presented (even to the student), a disclosure record must be created noting:
    the parties who requested or received the information, their legitimate
    interest, and the date. This layer constructs that audit record as a structured
    dict and attaches a unique disclosure_id to the pipeline result.

Layer 4 - LLM Context Assembler:
    After filtering, surviving documents are serialized into a context string
    suitable for inclusion in an LLM prompt. A compliance header is prepended that
    names the regulations applied, the disclosure record ID, and the count of
    documents removed by each filter. This makes the context block self-annotating
    for downstream auditors reviewing LLM prompts.

Architecture
------------
    WeaviateCompliancePipeline
        -> FERPAScopeBuilder          (builds Weaviate filter for student/institution)
        -> Weaviate vector query      (lazy-imported; stub used if unavailable)
        -> HIPAADocumentFilter        (removes PHI docs without BAA)
        -> FERPADisclosureRecordBuilder (builds §99.32 audit record)
        -> LLMContextAssembler        (formats context string with compliance header)

Weaviate v4 Notes
-----------------
The Weaviate Python client v4 uses a strongly-typed Filter API under
`weaviate.classes.query`. This file lazy-imports the client; if it is not
installed, a StubWeaviateClient is used that returns pre-defined synthetic
documents so the compliance layers can still be exercised and tested without
a running Weaviate instance.
"""

import hashlib
import importlib
import logging
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Weaviate lazy import helpers
# ---------------------------------------------------------------------------

def _try_import_weaviate() -> tuple[Any, bool]:
    """Attempt to import the Weaviate v4 client. Return (module, available)."""
    try:
        weaviate = importlib.import_module("weaviate")
        return weaviate, True
    except ModuleNotFoundError:
        return None, False


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class RetrievedDocument:
    """Represents a single document returned from Weaviate."""
    doc_id: str
    student_id: str
    institution_id: str
    content: str
    record_type: str = "academic"      # "academic" | "medical" | "financial"
    contains_phi: bool = False
    score: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DisclosureRecord:
    """FERPA 34 CFR §99.32 disclosure record."""
    disclosure_id: str
    requester_id: str
    student_id: str
    institution_id: str
    disclosed_doc_ids: list[str]
    legitimate_interest: str
    timestamp: str
    regulations_applied: list[str]
    documents_removed_ferpa: int = 0
    documents_removed_hipaa: int = 0


@dataclass
class PipelineResult:
    """Final result returned by WeaviateCompliancePipeline.run()."""
    context: str
    documents: list[RetrievedDocument]
    disclosure_record: DisclosureRecord
    compliance_headers: dict[str, Any]
    query: str
    requester_id: str
    student_id: str


# ---------------------------------------------------------------------------
# Layer 1: FERPA Identity Scope Builder
# ---------------------------------------------------------------------------

class FERPAScopeBuilder:
    """
    Builds a Weaviate query filter that scopes retrieval to documents owned
    by the requesting student at the specified institution.

    Regulatory basis: FERPA 34 CFR §99.31(a)(1) — a school may disclose
    education records to the eligible student without prior written consent.
    Restricting the Weaviate filter at query time (rather than post-filtering)
    ensures no cross-student metadata leakage at the database level.
    """

    def build_filter(
        self,
        student_id: str,
        institution_id: str,
        weaviate_available: bool = False,
        weaviate_module: Any = None,
    ) -> Any:
        """
        Return either a real Weaviate v4 Filter object or a plain dict stub.

        Parameters
        ----------
        student_id:
            The authenticated student's unique identifier.
        institution_id:
            The institution identifier (used to prevent cross-institution leakage
            in multi-tenant deployments).
        weaviate_available:
            True if the weaviate Python package is installed.
        weaviate_module:
            The imported weaviate module, if available.

        Returns
        -------
        A Weaviate Filter object (when client is available) or a dict stub
        describing the intended filter predicates.
        """
        if weaviate_available and weaviate_module is not None:
            try:
                from weaviate.classes.query import Filter  # type: ignore[import]
                ferpa_filter = (
                    Filter.by_property("student_id").equal(student_id)
                    & Filter.by_property("institution_id").equal(institution_id)
                )
                logger.debug(
                    "FERPA scope filter built via Weaviate v4 API for student=%s",
                    student_id,
                )
                return ferpa_filter
            except Exception as exc:  # noqa: BLE001
                logger.warning("Weaviate Filter import failed (%s); using stub.", exc)

        # Stub representation used when real client is unavailable
        stub_filter = {
            "_type": "FERPAFilterStub",
            "_citation": "34 CFR §99.31(a)(1)",
            "predicates": [
                {"property": "student_id", "operator": "Equal", "value": student_id},
                {
                    "property": "institution_id",
                    "operator": "Equal",
                    "value": institution_id,
                },
            ],
            "logical_operator": "AND",
        }
        logger.debug("FERPA scope filter stub built for student=%s", student_id)
        return stub_filter


# ---------------------------------------------------------------------------
# Layer 2: HIPAA PHI Document Filter
# ---------------------------------------------------------------------------

class HIPAADocumentFilter:
    """
    Removes retrieved documents that contain PHI unless the requester holds
    a valid Business Associate Agreement (BAA) token.

    Regulatory basis: HIPAA Privacy Rule, 45 CFR §164.502(a) — covered entities
    and business associates may not use or disclose PHI except as permitted.
    45 CFR §164.504(e) requires a BAA when PHI is disclosed to a business
    associate. In a student health clinic context, academic and medical records
    may co-exist in the same Weaviate collection; this filter enforces separation.

    PHI indicators checked (document metadata):
        - contains_phi == True
        - record_type in {"medical", "health", "clinical"}
    """

    PHI_RECORD_TYPES: frozenset[str] = frozenset({"medical", "health", "clinical"})

    def filter(
        self,
        documents: list[RetrievedDocument],
        has_baa: bool,
    ) -> tuple[list[RetrievedDocument], list[RetrievedDocument]]:
        """
        Partition documents into allowed and removed sets.

        Parameters
        ----------
        documents:
            Documents retrieved from Weaviate after FERPA scoping.
        has_baa:
            True if the requester has a valid Business Associate Agreement token.
            When True, PHI documents are permitted to pass through.

        Returns
        -------
        (allowed_documents, removed_documents) — tuple of two lists.
        """
        if has_baa:
            logger.info(
                "HIPAA filter: BAA present — all %d documents allowed.", len(documents)
            )
            return list(documents), []

        allowed: list[RetrievedDocument] = []
        removed: list[RetrievedDocument] = []

        for doc in documents:
            is_phi = doc.contains_phi or doc.record_type in self.PHI_RECORD_TYPES
            if is_phi:
                logger.info(
                    "HIPAA filter: removing doc %s (record_type=%s, contains_phi=%s) "
                    "— no BAA [45 CFR §164.502(a)]",
                    doc.doc_id,
                    doc.record_type,
                    doc.contains_phi,
                )
                removed.append(doc)
            else:
                allowed.append(doc)

        return allowed, removed


# ---------------------------------------------------------------------------
# Layer 3: FERPA Disclosure Record Builder
# ---------------------------------------------------------------------------

class FERPADisclosureRecordBuilder:
    """
    Constructs the FERPA 34 CFR §99.32 record of disclosures.

    Each disclosure of education records must be documented with:
        - The parties requesting or receiving the records
        - Their legitimate educational interest
        - The date of disclosure

    This builder generates a unique disclosure_id (deterministic SHA-256 hash
    of requester + student + timestamp prefix for reproducibility in tests,
    plus a UUID suffix for uniqueness) and returns a DisclosureRecord dataclass.
    """

    def build(
        self,
        requester_id: str,
        student_id: str,
        institution_id: str,
        allowed_documents: list[RetrievedDocument],
        legitimate_interest: str,
        regulations_applied: list[str],
        documents_removed_ferpa: int = 0,
        documents_removed_hipaa: int = 0,
    ) -> DisclosureRecord:
        """
        Build and return a FERPA §99.32 disclosure record.

        Parameters
        ----------
        requester_id:
            Authenticated identity of the party making the request.
        student_id:
            The student whose records were retrieved.
        institution_id:
            Institution under whose FERPA policy the disclosure occurs.
        allowed_documents:
            The documents that passed all filters and will be disclosed.
        legitimate_interest:
            Human-readable statement of the FERPA-recognized interest
            (e.g., "student self-access", "advisor with legitimate educational
            interest").
        regulations_applied:
            List of regulation codes active during this query.
        documents_removed_ferpa:
            Count of documents excluded by FERPA scope filter.
        documents_removed_hipaa:
            Count of documents excluded by HIPAA PHI filter.

        Returns
        -------
        DisclosureRecord with a unique disclosure_id and ISO-8601 timestamp.
        """
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()

        hash_input = f"{requester_id}:{student_id}:{now.strftime('%Y%m%dT%H%M')}"
        short_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        disclosure_id = f"FERPA-{short_hash}-{uuid.uuid4().hex[:8]}"

        record = DisclosureRecord(
            disclosure_id=disclosure_id,
            requester_id=requester_id,
            student_id=student_id,
            institution_id=institution_id,
            disclosed_doc_ids=[doc.doc_id for doc in allowed_documents],
            legitimate_interest=legitimate_interest,
            timestamp=timestamp_str,
            regulations_applied=regulations_applied,
            documents_removed_ferpa=documents_removed_ferpa,
            documents_removed_hipaa=documents_removed_hipaa,
        )
        logger.info(
            "Disclosure record created: %s — %d docs disclosed to %s",
            disclosure_id,
            len(allowed_documents),
            requester_id,
        )
        return record


# ---------------------------------------------------------------------------
# Layer 4: LLM Context Assembler
# ---------------------------------------------------------------------------

class LLMContextAssembler:
    """
    Assembles filtered documents into a context string for LLM consumption.

    Prepends a compliance header block that names which regulations were active,
    the disclosure record ID, and filter statistics. This makes the context
    block self-documenting for downstream auditors inspecting LLM prompt logs.
    """

    def assemble(
        self,
        query: str,
        documents: list[RetrievedDocument],
        disclosure_record: DisclosureRecord,
    ) -> tuple[str, dict[str, Any]]:
        """
        Build the context string and compliance_headers dict.

        Parameters
        ----------
        query:
            The original retrieval query.
        documents:
            Compliance-filtered documents to include in the context.
        disclosure_record:
            The FERPA §99.32 disclosure record for this retrieval.

        Returns
        -------
        (context_string, compliance_headers) where compliance_headers is a
        dict suitable for logging or inclusion in an audit event.
        """
        regs = ", ".join(disclosure_record.regulations_applied) or "none"
        header_lines = [
            "=== COMPLIANCE CONTEXT BLOCK ===",
            f"Disclosure ID    : {disclosure_record.disclosure_id}",
            f"Regulations      : {regs}",
            f"Requester        : {disclosure_record.requester_id}",
            f"Student          : {disclosure_record.student_id}",
            f"Institution      : {disclosure_record.institution_id}",
            f"Legitimate use   : {disclosure_record.legitimate_interest}",
            f"Docs included    : {len(documents)}",
            f"Removed (FERPA)  : {disclosure_record.documents_removed_ferpa}",
            f"Removed (HIPAA)  : {disclosure_record.documents_removed_hipaa}",
            f"Timestamp        : {disclosure_record.timestamp}",
            "=================================",
            f"Query: {query}",
            "",
        ]

        doc_lines: list[str] = []
        for idx, doc in enumerate(documents, start=1):
            doc_lines.append(f"[Document {idx} | id={doc.doc_id} | type={doc.record_type}]")
            doc_lines.append(doc.content.strip())
            doc_lines.append("")

        context = "\n".join(header_lines + doc_lines)

        compliance_headers = {
            "disclosure_id": disclosure_record.disclosure_id,
            "regulations_applied": disclosure_record.regulations_applied,
            "requester_id": disclosure_record.requester_id,
            "student_id": disclosure_record.student_id,
            "institution_id": disclosure_record.institution_id,
            "documents_disclosed": len(documents),
            "documents_removed_ferpa": disclosure_record.documents_removed_ferpa,
            "documents_removed_hipaa": disclosure_record.documents_removed_hipaa,
            "timestamp": disclosure_record.timestamp,
        }

        return context, compliance_headers


# ---------------------------------------------------------------------------
# Stub Weaviate client (used when package is not installed)
# ---------------------------------------------------------------------------

class _StubWeaviateClient:
    """
    Minimal stub that mimics the subset of Weaviate v4 API used by this pipeline.

    Returns a configurable set of synthetic documents so that compliance layers
    can be exercised in environments without a running Weaviate instance.
    """

    def __init__(self, synthetic_docs: list[RetrievedDocument]) -> None:
        self._docs = synthetic_docs

    def query(
        self,
        collection: str,
        query_text: str,
        filters: Any,
        limit: int,
    ) -> list[RetrievedDocument]:
        """Return the pre-loaded synthetic documents, applying stub FERPA filter."""
        # Extract student_id and institution_id from stub filter if available
        student_id: str | None = None
        institution_id: str | None = None

        if isinstance(filters, dict) and "_type" in filters:
            for pred in filters.get("predicates", []):
                if pred.get("property") == "student_id":
                    student_id = pred.get("value")
                elif pred.get("property") == "institution_id":
                    institution_id = pred.get("value")

        results = []
        for doc in self._docs:
            if student_id and doc.student_id != student_id:
                continue
            if institution_id and doc.institution_id != institution_id:
                continue
            results.append(doc)

        return results[:limit]


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class WeaviateCompliancePipeline:
    """
    Orchestrates a multi-layer compliance RAG pipeline backed by Weaviate.

    The pipeline executes four layers on every call to run():

        1. FERPAScopeBuilder — builds a Weaviate filter scoping to student/institution
        2. Weaviate query     — vector search with the FERPA filter applied
        3. HIPAADocumentFilter — removes PHI documents without BAA
        4. FERPADisclosureRecordBuilder — creates §99.32 disclosure record
        5. LLMContextAssembler — formats context + compliance headers

    Parameters
    ----------
    weaviate_url:
        URL of the Weaviate instance (e.g., "http://localhost:8080"). Ignored
        when the Weaviate package is unavailable (stub is used instead).
    collection_name:
        Name of the Weaviate collection holding education documents.
    top_k:
        Maximum number of documents to retrieve per query.
    synthetic_docs:
        When provided, bypasses real Weaviate and uses these documents instead.
        Useful for unit tests and demonstration.
    """

    def __init__(
        self,
        weaviate_url: str = "http://localhost:8080",
        collection_name: str = "EducationDocuments",
        top_k: int = 5,
        synthetic_docs: list[RetrievedDocument] | None = None,
    ) -> None:
        self.weaviate_url = weaviate_url
        self.collection_name = collection_name
        self.top_k = top_k

        self._weaviate_module, self._weaviate_available = _try_import_weaviate()

        if synthetic_docs is not None or not self._weaviate_available:
            self._client: Any = _StubWeaviateClient(synthetic_docs or [])
            if not self._weaviate_available:
                logger.info(
                    "weaviate-client not installed — using StubWeaviateClient. "
                    "Install with: pip install weaviate-client"
                )
        else:
            self._client = self._weaviate_module.connect_to_local(
                host=weaviate_url.replace("http://", "").split(":")[0],
                port=int(weaviate_url.split(":")[-1]),
            )

        self._ferpa_scope = FERPAScopeBuilder()
        self._hipaa_filter = HIPAADocumentFilter()
        self._disclosure_builder = FERPADisclosureRecordBuilder()
        self._context_assembler = LLMContextAssembler()

    def run(
        self,
        query: str,
        student_id: str,
        institution_id: str,
        requester_id: str,
        has_baa: bool = False,
        legitimate_interest: str = "student self-access per FERPA §99.31(a)(1)",
    ) -> PipelineResult:
        """
        Execute the full compliance RAG pipeline.

        Parameters
        ----------
        query:
            Natural language query to submit to Weaviate.
        student_id:
            Authenticated student identifier (used for FERPA scoping).
        institution_id:
            Institution identifier (used for multi-tenant FERPA scoping).
        requester_id:
            Identity of the party making the request (may differ from student_id
            when an advisor accesses records on behalf of a student).
        has_baa:
            True if the requester has a valid HIPAA Business Associate Agreement,
            which permits retrieval of PHI documents.
        legitimate_interest:
            Human-readable FERPA-recognized purpose for this disclosure.

        Returns
        -------
        PipelineResult with context, documents, disclosure_record, and
        compliance_headers.
        """
        regulations_applied: list[str] = ["FERPA 34 CFR §99.31"]

        # Layer 1: Build FERPA scope filter
        ferpa_filter = self._ferpa_scope.build_filter(
            student_id=student_id,
            institution_id=institution_id,
            weaviate_available=self._weaviate_available,
            weaviate_module=self._weaviate_module,
        )

        # Layer 2: Execute Weaviate vector query with FERPA filter
        raw_documents: list[RetrievedDocument] = self._client.query(
            collection=self.collection_name,
            query_text=query,
            filters=ferpa_filter,
            limit=self.top_k,
        )
        logger.info(
            "Weaviate returned %d documents for student=%s", len(raw_documents), student_id
        )

        # Determine documents_removed_ferpa: stub always returns scoped results,
        # so we cannot easily count filtered-out docs here; set to 0 for stub runs.
        # In production with a real client, this would be total minus returned.
        documents_removed_ferpa = 0

        # Layer 3: HIPAA PHI filter
        phi_indicator_present = any(
            d.contains_phi or d.record_type in HIPAADocumentFilter.PHI_RECORD_TYPES
            for d in raw_documents
        )
        if phi_indicator_present:
            regulations_applied.append("HIPAA 45 CFR §164.502")

        allowed_docs, removed_docs = self._hipaa_filter.filter(
            documents=raw_documents,
            has_baa=has_baa,
        )
        documents_removed_hipaa = len(removed_docs)

        # Layer 4: Build FERPA §99.32 disclosure record
        disclosure_record = self._disclosure_builder.build(
            requester_id=requester_id,
            student_id=student_id,
            institution_id=institution_id,
            allowed_documents=allowed_docs,
            legitimate_interest=legitimate_interest,
            regulations_applied=regulations_applied,
            documents_removed_ferpa=documents_removed_ferpa,
            documents_removed_hipaa=documents_removed_hipaa,
        )

        # Layer 5: Assemble LLM context
        context, compliance_headers = self._context_assembler.assemble(
            query=query,
            documents=allowed_docs,
            disclosure_record=disclosure_record,
        )

        return PipelineResult(
            context=context,
            documents=allowed_docs,
            disclosure_record=disclosure_record,
            compliance_headers=compliance_headers,
            query=query,
            requester_id=requester_id,
            student_id=student_id,
        )

    def close(self) -> None:
        """Close the Weaviate client connection if applicable."""
        if self._weaviate_available and hasattr(self._client, "close"):
            self._client.close()


# ---------------------------------------------------------------------------
# Synthetic document fixtures for demo scenarios
# ---------------------------------------------------------------------------

def _build_demo_documents() -> list[RetrievedDocument]:
    return [
        RetrievedDocument(
            doc_id="doc-acad-001",
            student_id="student-alice",
            institution_id="inst-state-univ",
            content=(
                "Alice Smith — Spring 2025 Academic Transcript. "
                "CSCI 301 (A), MATH 210 (B+), ENGL 102 (A-). "
                "Cumulative GPA: 3.72."
            ),
            record_type="academic",
            contains_phi=False,
        ),
        RetrievedDocument(
            doc_id="doc-fin-002",
            student_id="student-alice",
            institution_id="inst-state-univ",
            content=(
                "Financial Aid Award Letter — 2025/2026. "
                "Pell Grant: $7,395. Subsidized Loan: $3,500. "
                "Unsubsidized Loan: $2,000. Total: $12,895."
            ),
            record_type="financial",
            contains_phi=False,
        ),
        RetrievedDocument(
            doc_id="doc-med-003",
            student_id="student-alice",
            institution_id="inst-state-univ",
            content=(
                "Student Health Center — Visit Note 2025-03-10. "
                "Chief complaint: seasonal allergies. "
                "Prescribed cetirizine 10 mg daily."
            ),
            record_type="medical",
            contains_phi=True,
        ),
        RetrievedDocument(
            doc_id="doc-acad-004",
            student_id="student-bob",
            institution_id="inst-state-univ",
            content=(
                "Bob Jones — Spring 2025 Academic Transcript. "
                "HIST 201 (C+), PSYC 110 (B)."
            ),
            record_type="academic",
            contains_phi=False,
        ),
    ]


# ---------------------------------------------------------------------------
# main() — three demo scenarios
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s — %(message)s",
        stream=sys.stdout,
    )

    synthetic_docs = _build_demo_documents()

    pipeline = WeaviateCompliancePipeline(
        collection_name="EducationDocuments",
        top_k=10,
        synthetic_docs=synthetic_docs,
    )

    separator = "-" * 72

    # ------------------------------------------------------------------
    # Scenario 1: Student accessing their own academic records
    # FERPA §99.31(a)(1): student self-access — no consent required.
    # No PHI in scope (student has no BAA — irrelevant here because
    # the medical doc belongs to alice and will be removed by HIPAA filter).
    # ------------------------------------------------------------------
    print(separator)
    print("SCENARIO 1: Student self-access — academic records only")
    print(separator)

    result1 = pipeline.run(
        query="What are my current grades and GPA?",
        student_id="student-alice",
        institution_id="inst-state-univ",
        requester_id="student-alice",
        has_baa=False,
        legitimate_interest="student self-access per FERPA 34 CFR §99.31(a)(1)",
    )
    print(result1.context)
    print(
        f"Disclosure record ID : {result1.disclosure_record.disclosure_id}"
    )
    print(
        f"Documents disclosed  : {len(result1.documents)}"
    )
    print(
        f"PHI docs removed     : {result1.compliance_headers['documents_removed_hipaa']}"
    )

    # ------------------------------------------------------------------
    # Scenario 2: Student accessing records but PHI docs present — no BAA
    # HIPAA §164.502(a) requires BAA for PHI disclosure.
    # Medical record doc-med-003 must be removed.
    # ------------------------------------------------------------------
    print()
    print(separator)
    print("SCENARIO 2: Student query touches PHI doc — no BAA — PHI removed")
    print(separator)

    result2 = pipeline.run(
        query="Show me all my records including health visits",
        student_id="student-alice",
        institution_id="inst-state-univ",
        requester_id="student-alice",
        has_baa=False,
        legitimate_interest="student self-access per FERPA 34 CFR §99.31(a)(1)",
    )
    print(result2.context)
    print(
        f"Disclosure record ID : {result2.disclosure_record.disclosure_id}"
    )
    removed = result2.compliance_headers["documents_removed_hipaa"]
    print(
        f"PHI docs removed (HIPAA §164.502) : {removed}"
    )
    print(
        f"Docs actually disclosed            : {len(result2.documents)}"
    )

    # ------------------------------------------------------------------
    # Scenario 3: Academic advisor accessing student records
    # FERPA §99.31(a)(1)(ii): school officials with legitimate educational
    # interest may access records. Advisor has a BAA (hypothetical clinic
    # integration), so PHI docs are permitted through.
    # ------------------------------------------------------------------
    print()
    print(separator)
    print("SCENARIO 3: Advisor with BAA — legitimate educational interest — PHI allowed")
    print(separator)

    result3 = pipeline.run(
        query="Full student record review for advising appointment",
        student_id="student-alice",
        institution_id="inst-state-univ",
        requester_id="advisor-dr-chen",
        has_baa=True,
        legitimate_interest=(
            "academic advisor review under FERPA §99.31(a)(1)(ii) — "
            "legitimate educational interest; BAA on file for health records"
        ),
    )
    print(result3.context)
    print(
        f"Disclosure record ID : {result3.disclosure_record.disclosure_id}"
    )
    print(
        f"Docs disclosed to advisor : {len(result3.documents)}"
    )
    print(
        f"Regulations applied       : {result3.compliance_headers['regulations_applied']}"
    )
    print(
        f"Requester                 : {result3.compliance_headers['requester_id']}"
    )

    pipeline.close()


if __name__ == "__main__":
    main()
