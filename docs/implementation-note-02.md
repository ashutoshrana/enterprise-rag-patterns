# Implementation Note 02: FERPA Boundaries in Retrieval-Augmented Generation

Most RAG tutorials stop at retrieval quality. An education-record workflow has
an earlier question: which records is this requester authorized to use?

This note separates the library's filtering behavior from the institution's
legal and operational responsibilities. Reviewed against main commit `30e2eaf`
on 2026-11-01. The implementation is in
[`compliance.py`](../src/enterprise_rag_patterns/compliance.py); a runnable
reference is [`ferpa_rag_pipeline.py`](../examples/ferpa_rag_pipeline.py).

## What FERPA requires, concisely

FERPA generally requires consent for disclosure of personally identifiable
information from education records unless an exception applies. The
school-official exception requires legitimate educational interests; qualifying
contractors must meet additional conditions, including institutional control
over use and maintenance of the records. Calling software an “agent” does not
establish that exception.

Section 99.32 has recordkeeping requirements and exceptions, including certain
disclosures to school officials. It does not universally require a
tamper-evident log of every retrieval. Where required, the disclosure record
must be retained as long as the education records are maintained. Directory
information also has conditions, including notice and opt-out rights; a
library category label does not establish permission to disclose it.

These points follow the Department of Education's
[FERPA regulations, §§ 99.31, 99.32 and 99.37](https://studentprivacy.ed.gov/ferpa)
and its [school-official recordation clarification](https://studentprivacy.ed.gov/faq/must-school-or-lea-record-non-consensual-disclosure-personally-identifiable-information-pii),
checked 2026-11-01. The institution must determine the applicable legal basis
and retention/access process; the library does not make that determination.

## Where retrieval architectures fail

A shared index can return a relevant record belonging to a different student
or institution. Restrict the store request using trusted identity and category
metadata, then check returned records before prompt assembly. A system prompt
asking the model to ignore another student's information is too late to keep
that information out of model input.

Query-layer constraints and post-retrieval checks protect different boundaries.
`FERPAContextPolicy.filter_retrieved_documents()` checks an already-retrieved
list. It does not construct or execute a vector-store query, authenticate the
requester, or prevent the retrieval service from seeing out-of-scope records.

## Design rules for FERPA-aware RAG

### Rule 1: Establish identity and authority before retrieval

Build `StudentIdentityScope` from authenticated, institution-authorized context.
Do not accept student, institution, category, or disclosure-reason claims
straight from a user prompt. The dataclass stores the supplied scope; it does
not verify consent or legitimate educational interest.

### Rule 2: Apply constraints in the store request

The [vector-store adapters](../src/enterprise_rag_patterns/vector_stores/base.py)
translate `ComplianceFilter` into store-specific filter values. Callers must
pass those values to the actual query. An empty `permitted_categories` set
omits category filtering, so supply categories for protected-record queries.

A filter argument does not prove the engine ranks only authorized records.
For example, [pgvector's filtering documentation](https://github.com/pgvector/pgvector#filtering)
states that approximate-index filtering happens after the index scan
(checked 2026-11-01). Verify the selected store's returned-record behavior and
query plan; do not infer absence of timing or existence side channels.

### Rule 3: Check returned records before context assembly

This standalone example exercises the current policy API. The list represents
results already returned by a retriever; the in-memory sink demonstrates the
callback interface, not durable audit storage.

The executable example below targets the reviewed source checkout, not an
unverified installed release.

```python
from enterprise_rag_patterns.compliance import (
    DisclosureReason, FERPAContextPolicy, RecordCategory, StudentIdentityScope,
)

scope = StudentIdentityScope(
    student_id="S-12345",
    institution_id="acme-univ",
    requesting_user_id="agent:enrollment_advisor",
    authorized_categories={RecordCategory.ACADEMIC_RECORD},
    disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
)
audit_records = []
policy = FERPAContextPolicy(scope=scope, audit_sink=audit_records.append)
raw_results = [
    {"student_id": "S-12345", "institution_id": "acme-univ",
     "record_category": "academic_record", "content": "Authorized record"},
    {"student_id": "S-other", "institution_id": "acme-univ",
     "record_category": "academic_record", "content": "Other student's record"},
    {"content": "Unclassified content"},
]
safe_docs = policy.filter_retrieved_documents(raw_results)
assert safe_docs == [raw_results[0]]
assert audit_records == []  # Filtering alone does not call record_access().
audit = policy.record_access(
    categories_accessed=[RecordCategory.ACADEMIC_RECORD],
    workflow_context="enrollment advisor: graduation audit query",
)
assert audit_records == [audit]
```

Private records require nonempty string identity and recognized category fields.
The default policy rejects other students, other institutions, missing or
malformed metadata, and categories outside the supplied set, with one important
exception: `StudentIdentityScope.permits()` always allows
`RecordCategory.DIRECTORY_INFORMATION`. That category bypasses the category
allowlist, although private-record identity checks still apply. The application
must enforce directory-information eligibility and opt-outs separately. Explicit trusted public content
can pass with `classification="public"` and neither identity key. This marker
must come from a controlled classification process. Missing institution metadata
must not be relabeled as shared or public to bypass the policy.

### Rule 4: Integrate audit persistence deliberately

`record_access()` creates an `AuditRecord` and invokes the optional `audit_sink`.
With no sink it returns the record without persisting it. The base filter does
not call this method automatically; framework integrations may do so on their
own execution paths. Inspect the adapter you actually use.

The application owns durable storage, access restrictions, integrity controls,
retention, and failure handling. `to_log_entry()` is formatted text; it does
not add tamper evidence. Do not infer regulatory completeness from the
`AuditRecord` name or its source docstring. For example, the current record has
no individual retrieved-document IDs; retain those separately if needed.

### Rule 5: Re-authorize changes in scope

A workflow needing additional categories must obtain authority outside the
model, then construct the new scope. A mutable Python scope is not an approval
workflow. Test that caches, conversation history, retries, and human handoffs
respect the current institution and requester.

## Architecture pattern summary

```text
Authenticated request and institution authorization
    → scoped store query (application passes adapter filter)
    → returned-record policy check
    → application audit handling
    → context assembly using only accepted records
    → model generation
```

Validate the complete model input with out-of-scope canary records, including
malformed metadata and duplicate text with different identities. Store filters,
policy tests, and audit callbacks each demonstrate a specific boundary; none
alone establish a FERPA-compliant deployment.
