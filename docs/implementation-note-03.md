# Implementation Note 03 — Context Assembly for Multi-Source Enterprise RAG

**Series:** enterprise-rag-patterns
**Topic:** When your knowledge lives in five different systems
**Status:** Published 2026-04-11
**Implementation review:** 2026-11-01, main commit `30e2eaf`

---

## The problem

Most RAG tutorials assume a single document corpus. Enterprise environments do
not work that way.

A real enterprise AI workflow might need to assemble context from:

- A CRM or enrollment system (account status, contact history, case records)
- An ERP or financial system (billing, contracts, payment history)
- A knowledge base or policy repository (current policies, procedures, FAQs)
- A compliance or records system (regulated records, access-controlled documents)
- Real-time operational data (queue depth, service status, current availability)

Each of these has different latency characteristics, different freshness
requirements, different trust levels, and different authorization rules. A
single vector store query cannot handle all of them.

The `ContextEnvelope` and `ContextSource` types in this library exist to make
the assembly problem explicit and structured.

---

## Why source provenance matters

When a language model produces a response, the quality of that response depends
not just on whether the relevant information was retrieved, but on which system
it came from and how recent it is.

Consider a query about a student's enrollment status. The answer could come from:

1. A cached record from three days ago (stale — student may have dropped)
2. A real-time query to the SIS (authoritative — reflects current state)
3. A knowledge base article describing the enrollment process (irrelevant — not
   the student's actual status)

All three might be retrieved by a naive RAG pipeline that does not track
source provenance. The model may respond with the wrong answer because the
cached record ranks higher than the real-time query result.

`ContextSource` describes a named source, an optional `freshness_seconds`
budget, and whether it is `required`. It does not hold retrieved content,
retrieval timestamps, content types, or trust levels. The application must keep
that provenance and use it when deciding which facts to pass onward.

---

## The assembly pattern

A `ContextEnvelope` holds `session_id`, `channel`, a list of source descriptors,
and a string-to-string `facts` dictionary. Source-list order is preserved; the
library does not assign authority to that order or resolve conflicts.

The executable example below targets the reviewed source checkout, not an
unverified installed release.

```python
from enterprise_rag_patterns.context import ContextEnvelope, ContextSource

envelope = ContextEnvelope(
    session_id="session-abc",
    channel="web_chat",
    sources=[
        ContextSource(name="sis", freshness_seconds=60, required=True),
        ContextSource(name="knowledge_base", freshness_seconds=3600, required=False),
        ContextSource(name="crm", freshness_seconds=300, required=False),
    ],
)
envelope.add_fact("enrollment_status", "full-time")
envelope.add_fact("enrollment_source", "sis")
assert envelope.source_names() == ["sis", "knowledge_base", "crm"]
assert envelope.facts["enrollment_status"] == "full-time"
```

The values above are illustrative application budgets, not library defaults.
The calling code retrieves and authorizes records, checks their age, resolves
conflicts, and builds the prompt. `add_fact()` overwrites an existing key; it
does not compare source authority. Neither `required` nor `freshness_seconds`
is enforced by these dataclasses.

---

## Five design rules for multi-source context assembly

### 1. Tag every source at retrieval time

Provenance information (which system, when retrieved) must be captured at the
moment of retrieval — not reconstructed afterward. By the time the context
reaches the prompt assembly step, the raw API response is gone.

A retrieval record with no timestamp or source identity is a
provenance gap in the application. Even if the content is correct, you cannot
answer the question
"where did this answer come from?" — which matters for audit, for debugging,
and for explaining model behavior to users.

### 2. Separate retrieval latency tiers

Some sources depend on earlier authorization or lookup results. Set latency and
freshness budgets from measured application needs; the library does not schedule
retrievals or enforce service-level targets.

Structure your assembly pipeline in tiers:

- **Tier 1 (synchronous, real-time):** Sources that must be fresh for the
  query to be meaningful. Query these first; fail fast if unavailable.
- **Tier 2 (parallel retrieval):** Sources that can be fetched in parallel
  while Tier 1 results are being processed.
- **Tier 3 (cached or fallback):** Sources that tolerate staleness. Use cached
  results if the live query fails or exceeds a latency budget.

### 3. Express trust level explicitly, not implicitly through ranking

Retrieval ranking scores (BM25, cosine similarity) measure semantic relevance.
They do not measure authority. A knowledge base article about a policy may
rank higher than a real-time SIS record on a query about enrollment status —
because the article contains more matching terms — while being far less
authoritative for that specific student.

Trust level is a separate dimension from relevance score. Model it explicitly
in application provenance records so the context assembly step can apply
priority rules that override relevance ranking when needed.

### 4. Handle source unavailability gracefully and explicitly

Enterprise systems have scheduled maintenance windows, rate limits, and
occasional failures. The context assembly step must have a defined policy for
each source: what happens if the SIS is unavailable? Does the pipeline proceed
with stale cache, degrade to a partial response, or halt and escalate?

`ContextEnvelope` can be constructed with any subset of source descriptors;
it does not detect source failures or reject a missing required source. The
calling code should record
which sources were unavailable and communicate this to the model (e.g., via a
system prompt flag) rather than silently assembling a degraded context.

### 5. Maintain context boundaries across turns in a session

In a multi-turn conversation, context accumulated in early turns may become
stale by later turns. A student's enrollment status queried at the start of a
session may change (or a cache may expire) mid-session.

`SessionState` does not track retrieved sources or timestamps. Keep that
information in application state. Before assembling context for a new turn,
compare retrieval timestamps to the application freshness policy and re-fetch
when needed.

---

## Common failure modes

**Over-reliance on a single source**
Treating one system (usually the knowledge base) as the only retrieval target
and ignoring CRM or SIS records. The model answers correctly about policy but
incorrectly about the specific case.

**Ignoring retrieval order**
Sorting retrieved documents by relevance score across all sources, treating CRM
records and knowledge base articles as equally authoritative. Produces
inconsistent responses when the highest-ranked document is not the most
authoritative.

**No provenance in prompt context**
Passing raw document text to the model without indicating which system it came
from. The model cannot reason about source reliability, and debugging incorrect
responses requires tracing back through retrieval logs.

**Silent degradation on source failure**
If the SIS query fails and the pipeline proceeds without noting this, the model
responds with knowledge-base content as if it were real-time record data. Users
receive confident-sounding responses based on policy descriptions, not actual
enrollment status.

---

## Relationship to session continuity

The `ContextEnvelope` describes what was retrieved for a single query turn.
`SessionState` holds channel names, checkpoint labels, and an escalation flag
across a session. It does not retain source history, retrieved facts, or a
handoff history.

For multi-turn workflows, both layers are needed. See
[Implementation Note 01](implementation-note-01.md) for the cross-channel continuity pattern that
builds on top of `SessionState`.

---

## See also

- [`context.py`](../src/enterprise_rag_patterns/context.py) — `ContextEnvelope`, `ContextSource`
- [`session.py`](../src/enterprise_rag_patterns/session.py) — `SessionState`
- [Implementation Note 01](implementation-note-01.md) — Cross-channel session continuity
- [Implementation Note 02](implementation-note-02.md) — FERPA boundaries in retrieval-augmented generation
- [ADR 001](adr/001-pre-filter-not-post-filter.md) — Pre-filter design rationale
- [`context-pipeline.yaml`](../examples/context-pipeline.yaml) — Declarative context assembly reference
