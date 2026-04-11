# Implementation Note 03 — Context Assembly for Multi-Source Enterprise RAG

**Series:** enterprise-rag-patterns  
**Topic:** When your knowledge lives in five different systems  
**Status:** Published 2026-04-11

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

`ContextSource` captures the source system, retrieval timestamp, content type,
and a trust level so that the context assembly layer can make priority and
freshness decisions explicitly.

---

## The assembly pattern

A `ContextEnvelope` holds an ordered list of `ContextSource` objects. The
order encodes priority: sources earlier in the list provide more authoritative
context for the same information.

```python
from enterprise_rag_patterns.context import ContextEnvelope, ContextSource

envelope = ContextEnvelope(
    session_id="session-abc",
    sources=[
        ContextSource(
            system="sis",
            content_type="enrollment_record",
            content="Student enrolled full-time, effective 2026-01-15",
            retrieved_at=datetime.utcnow(),
            trust_level="authoritative",
        ),
        ContextSource(
            system="knowledge_base",
            content_type="policy_document",
            content="Full-time enrollment requires 12 or more credit hours...",
            retrieved_at=datetime.utcnow(),
            trust_level="reference",
        ),
        ContextSource(
            system="crm",
            content_type="case_history",
            content="Previous enrollment inquiry closed 2025-09-10",
            retrieved_at=datetime.utcnow(),
            trust_level="contextual",
        ),
    ]
)
```

The calling code — the context assembly step before the LLM call — walks the
sources in priority order and builds the prompt context block. If two sources
contain conflicting information about the same fact, the higher-priority source
wins.

---

## Five design rules for multi-source context assembly

### 1. Tag every source at retrieval time

Provenance information (which system, when retrieved) must be captured at the
moment of retrieval — not reconstructed afterward. By the time the context
reaches the prompt assembly step, the raw API response is gone.

A `ContextSource` with `retrieved_at=None` or `system="unknown"` is a
provenance gap. Even if the content is correct, you cannot answer the question
"where did this answer come from?" — which matters for audit, for debugging,
and for explaining model behavior to users.

### 2. Separate retrieval latency tiers

Not all sources can be queried in parallel. Real-time operational data (queue
depth, service status) may have sub-100ms SLAs. Compliance record retrieval may
require additional authorization checks that add latency. Knowledge base queries
via vector search may take 200–500ms.

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
in `ContextSource` so the context assembly step can apply priority rules that
override relevance ranking when needed.

### 4. Handle source unavailability gracefully and explicitly

Enterprise systems have scheduled maintenance windows, rate limits, and
occasional failures. The context assembly step must have a defined policy for
each source: what happens if the SIS is unavailable? Does the pipeline proceed
with stale cache, degrade to a partial response, or halt and escalate?

`ContextEnvelope` supports partial assembly — it can be constructed with a
subset of sources when some retrievals fail. The calling code should record
which sources were unavailable and communicate this to the model (e.g., via a
system prompt flag) rather than silently assembling a degraded context.

### 5. Maintain context boundaries across turns in a session

In a multi-turn conversation, context accumulated in early turns may become
stale by later turns. A student's enrollment status queried at the start of a
session may change (or a cache may expire) mid-session.

`SessionState` tracks which sources have been retrieved and when. Before
assembling context for a new turn, check whether any authoritative sources are
past their freshness threshold and need to be re-fetched.

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
`SessionState` describes what is known about the user's context across an entire
session — including which sources have been queried, what was found, and what
escalations or handoffs have occurred.

For multi-turn workflows, both layers are needed. See
`docs/implementation-note-01.md` for the cross-channel continuity pattern that
builds on top of `SessionState`.

---

## See also

- `context.py` — `ContextEnvelope`, `ContextSource`
- `session.py` — `SessionState`
- `docs/implementation-note-01.md` — Cross-channel session continuity
- `docs/implementation-note-02.md` — FERPA boundaries in retrieval-augmented generation
- `docs/adr/001-pre-filter-not-post-filter.md` — Pre-filter design rationale
- `examples/context-pipeline.yaml` — Declarative context assembly reference
