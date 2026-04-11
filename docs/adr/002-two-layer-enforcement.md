# ADR 002 — Two-layer enforcement: identity scope + category authorization

**Status:** Accepted  
**Date:** 2026-04-11  
**Context:** enterprise-rag-patterns / compliance module

---

## Context

In a regulated enterprise RAG system serving higher education, retrieved
documents fall into distinct categories: financial records, academic records,
counseling notes, health information, shared policy documents, and so on.

A student who is authorized to retrieve their own records is not necessarily
authorized to retrieve records in all categories. For example:

- Academic transcript records: accessible to the student for their own records
- Counseling notes: often restricted even from the student themselves depending
  on institution policy and applicable law
- Shared policy documents: accessible to all students at the institution

An identity scope filter (ADR 001) handles the *who-owns-this-document*
dimension. It does not handle the *what-type-is-this-document* dimension.

---

## Decision

`FERPAContextPolicy` implements a **two-layer enforcement model**:

**Layer 1 — Identity pre-filter** (before ranking)  
Documents are excluded if their `student_id` or `institution_id` metadata does
not match the `StudentIdentityScope`. This is a hard ownership boundary.

**Layer 2 — Category authorization** (applied to identity-filtered results)  
Documents are excluded if their category (document type) is not in the
`StudentIdentityScope.allowed_categories` set. This layer checks whether the
authenticated user is permitted to retrieve this *type* of record.

Both layers must pass. A document that passes the identity filter but fails
the category check is excluded from the context window.

---

## Rationale

### Why two separate layers rather than one combined check

Identity and category are orthogonal dimensions of access control. Combining
them into a single predicate creates a complex conjunction that is harder to
audit and harder to extend.

Separate layers mean:
- The identity enforcement logic can be modified independently of the category
  enforcement logic.
- New document categories can be added without touching identity boundary code.
- Audit records (see `AuditRecord`) can log which layer caused an exclusion,
  supporting more granular access review.

### FERPA basis for category-level controls

FERPA permits institutions to restrict access to certain education records
within the student's own file. For example:

- 34 CFR § 99.12 treats counseling records maintained solely by the
  counseling professional as outside the definition of "education records"
  unless shared with others — but this determination is institution-specific.
- Institutions routinely configure their student information systems with
  category-level access tiers beyond simple identity ownership.

The two-layer model mirrors how student information systems already work in
practice, making the RAG access control layer consistent with existing
institutional access control policies.

### Defense-in-depth value

If Layer 1 (identity pre-filter) has a defect in metadata matching, Layer 2
(category authorization) may still block unauthorized content — but only for
categories that are not in the allowed set. The inverse is also true. Neither
layer alone provides full coverage across both dimensions.

---

## Consequences

### Accepted trade-offs

- `StudentIdentityScope` must carry an `allowed_categories` set that accurately
  reflects what the authenticated user is permitted to see. This requires the
  calling system to populate the scope correctly at authentication time.
- Documents in the vector store must have a `category` metadata field. Documents
  without a category field are treated as uncategorized; `FERPAContextPolicy`
  passes them through Layer 2 (no category = cannot enforce category auth).
  Teams building on this pattern should decide whether uncategorized = permit
  or uncategorized = deny for their context.
- Adding a new restricted category requires updating the
  `StudentIdentityScope.allowed_categories` set at the session construction
  point, not in the filter code.

### Alternatives considered

**Single-layer identity-only filter:** Simpler, but does not handle category
restrictions. Insufficient for institutions with tiered access policies.

**Policy engine integration (OPA, Cedar):** More expressive. Higher operational
overhead. This two-layer model is designed to be straightforward to implement
in any Python environment without external dependencies.

---

## Related

- `compliance.py` — `FERPAContextPolicy`, `StudentIdentityScope`
- ADR 001 — Pre-filter before ranking
- ADR 003 — Audit record design
- `docs/implementation-note-02.md` — FERPA boundaries in RAG
