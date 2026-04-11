# ADR 003 — Audit record as a structured object, not a log string

**Status:** Accepted  
**Date:** 2026-04-11  
**Context:** enterprise-rag-patterns / compliance module

---

## Context

FERPA (34 CFR § 99.32) requires that an institution maintain a record of each
disclosure of education records, including: who made the request, what was
disclosed, the basis for disclosure, and the date. This record must be available
for inspection by the student.

In a RAG system, every time the pipeline retrieves and passes education records
to an LLM context window, that constitutes a disclosure or potential disclosure
that may need to be logged.

The question is what form the compliance audit trail should take:

1. **Log-string approach:** Emit a formatted string to a logging framework
   (Python `logging`, structured log JSON emitter, etc.)
2. **Structured object approach:** Represent each audit event as a typed
   dataclass, then provide a method to emit it as a log entry.

---

## Decision

Represent each audit event as an `AuditRecord` dataclass with typed fields.
Provide a `to_log_entry()` method that serializes the record to a dict suitable
for structured logging, but keep the record itself as a typed Python object.

The `FERPAContextPolicy.record_access()` method accepts an `audit_sink`
callable (type: `Callable[[AuditRecord], None]`) that the caller provides.
The policy does not write to any specific logging destination itself.

---

## Rationale

### Structured object: typed, testable, portable

- Each field is explicitly typed: `student_id: str`, `institution_id: str`,
  `documents_retrieved: int`, `documents_filtered: int`,
  `policy_version: str`, `timestamp: datetime`, `requester_context: dict`.
- Tests can assert on `AuditRecord` field values directly without parsing
  log strings.
- The object can be passed to any sink: a structured log emitter, a database
  write, a message queue, a compliance API — without reformatting.
- The `to_log_entry()` method provides a stable dict schema. Changing the
  internal field structure does not silently break downstream log consumers
  unless `to_log_entry()` is updated deliberately.
- Unique `record_id` (UUID4) on every `AuditRecord` supports deduplication
  and tracing across system components.

### Log-string approach: not suitable for compliance use

- Log strings are not machine-readable without parsing.
- Changing the log format breaks consumers silently.
- No typed field access in tests — assertions require string matching.
- Structured logging frameworks still benefit from receiving structured data
  rather than pre-formatted strings.

### Sink injection: decouples policy from infrastructure

The `audit_sink` parameter keeps the compliance module infrastructure-agnostic.
The same `FERPAContextPolicy` can run in:

- A Lambda function writing audit records to DynamoDB
- A Kubernetes pod writing to Google Cloud Logging via a Fluentd sink
- A test suite passing a `list.append` as the sink to capture records
- A local development environment printing to stdout

No changes to the compliance module are required when the logging destination
changes. The calling system provides the sink.

### 34 CFR § 99.32 field mapping

The `AuditRecord` fields are designed to satisfy the minimum disclosure record
requirements under 34 CFR § 99.32:

| Regulation requirement | AuditRecord field |
|------------------------|-------------------|
| Who requested the records | `requester_context` |
| What records were disclosed | `documents_retrieved`, `documents_filtered` |
| Basis for disclosure | `policy_version` (references the policy in effect) |
| Date of disclosure | `timestamp` |
| Identity scope enforced | `student_id`, `institution_id` |

---

## Consequences

### Accepted trade-offs

- Callers must provide an `audit_sink`. If no sink is provided (the default),
  audit records are not persisted. Teams deploying this in production must
  wire a sink that writes to a durable store.
- The `AuditRecord` structure represents one retrieval event, not a full
  student-viewable disclosure history. The calling system is responsible for
  aggregating records and providing student-facing access as required by
  34 CFR § 99.32(a)(2).
- `requester_context` is a dict rather than a typed structure to accommodate
  varying authentication contexts across deployments (JWT claims,
  session metadata, user service payloads, etc.).

### Alternatives considered

**Emit directly to logging framework inside the policy:** Simpler. Couples
the compliance module to a specific logging infrastructure. Harder to test.
Rejected.

**Write directly to a database inside the policy:** Creates a dependency on
a specific persistence layer. Makes the module non-portable. Rejected.

---

## Related

- `compliance.py` — `AuditRecord`, `FERPAContextPolicy.record_access()`
- ADR 001 — Pre-filter before ranking
- ADR 002 — Two-layer enforcement
- `docs/implementation-note-02.md` — FERPA boundaries in RAG
