# ADR 001 — Apply identity filter before semantic ranking, not after

**Status:** Accepted  
**Date:** 2026-04-11  
**Context:** enterprise-rag-patterns / compliance module

---

## Context

A retrieval-augmented generation pipeline must enforce access control when
documents in the vector store belong to different students or institutions.
There are two points at which this filter can be applied:

1. **Pre-filter (before semantic search):** restrict the candidate set passed
   to the vector store query so the retriever only sees documents the requester
   is authorized to access.
2. **Post-filter (after semantic search):** retrieve the top-k results across
   all documents, then remove unauthorized items from the returned list.

Both approaches produce a list of authorized documents. The question is where
the boundary sits.

---

## Decision

Apply the identity boundary as a **metadata pre-filter on the vector store
query**, not as a post-processing step after retrieval.

`FERPAContextPolicy.filter_retrieved_documents()` implements this as a
first-pass filter that removes any document whose `student_id` or
`institution_id` metadata does not match the `StudentIdentityScope` before the
documents are ranked or passed to the LLM context window.

---

## Rationale

### Pre-filter: eliminates unauthorized documents from the candidate set

- The vector store never returns unauthorized documents — they are excluded
  from the ANN (approximate nearest neighbor) search entirely.
- No unauthorized content enters the ranking pipeline, the reranker, or
  the context assembly step.
- The behavior is deterministic and independent of embedding similarity:
  a document belonging to a different student cannot appear in results
  regardless of how similar its embedding is to the query.

### Post-filter: leaves unauthorized documents in the retrieval path

- Unauthorized documents are scored and ranked before being discarded.
- If the post-filter has a defect (misconfigured field name, missing metadata,
  exception swallowed), unauthorized content can reach the LLM context.
- The effective top-k after filtering is unpredictable: a query asking for
  5 relevant documents may return 0–5 after post-filtering depending on the
  distribution of ownership in the result set.
- Under FERPA, any system design that allows unauthorized records to be
  retrieved (even transiently) and then relies on a downstream step to
  discard them is a weaker control than one that prevents retrieval in the
  first place.

### Defense-in-depth

Pre-filtering does not mean post-filtering is unnecessary. The two-layer
enforcement in `FERPAContextPolicy` applies both:

1. The pre-filter (identity scope metadata constraint)
2. A second category authorization pass (checks `allowed_categories`)

The pre-filter is the primary access control boundary. The category
authorization layer provides defense-in-depth for the content type dimension.

---

## Consequences

### Accepted trade-offs

- The pre-filter requires that all documents in the vector store have
  consistent `student_id` and `institution_id` metadata fields. Documents
  without these fields are treated as unauthorized and excluded.
- Shared knowledge-base documents (e.g., policy documents that apply to all
  students at an institution) require explicit metadata — either a wildcard
  marker or a separate collection — so the pre-filter can include them.
  The `StudentIdentityScope` design accommodates this via `institution_id`
  matching for institution-wide shared content.
- Pre-filtering may reduce the effective candidate pool, which can affect
  recall for queries where few relevant documents belong to the authorized
  student. This is the correct behavior: the system should not compensate for
  a sparse authorized document set by surfacing other students' records.

### Alternatives considered

**Post-filter only:** Rejected. Creates a window where unauthorized content
enters the pipeline. Non-deterministic top-k after filtering. Weaker FERPA
posture.

**Separate collections per student:** Feasible at small scale; operationally
expensive at scale (thousands of students = thousands of collections in most
vector stores). Metadata pre-filtering achieves the same isolation with a
single collection.

---

## Related

- `compliance.py` — `StudentIdentityScope`, `FERPAContextPolicy`
- `docs/implementation-note-02.md` — FERPA boundaries in RAG
- ADR 002 — Two-layer enforcement rationale
