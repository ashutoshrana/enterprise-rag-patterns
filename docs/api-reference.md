# API Reference — enterprise-rag-patterns

All public symbols exported from `enterprise_rag_patterns`.

---

## Core compliance module

### `StudentIdentityScope`

Defines the authorized identity context for a FERPA-governed retrieval.

```python
@dataclass
class StudentIdentityScope:
    student_id: str
    institution_id: str
    requesting_user_id: str
    authorized_categories: set[RecordCategory]
    disclosure_reason: DisclosureReason
    cross_institution_allowed: bool = False
```

**Parameters:**
- `student_id` — The student whose records may be retrieved
- `institution_id` — The institution that owns the records
- `requesting_user_id` — The user (or agent) making the request
- `authorized_categories` — Which record categories are authorized (see `RecordCategory`)
- `disclosure_reason` — The FERPA exception under which disclosure is authorized (see `DisclosureReason`)
- `cross_institution_allowed` — If `True`, records from other institutions may pass through (default: `False`)

---

### `RecordCategory`

Enum of FERPA record categories (34 CFR §99.3).

| Value | Description |
|-------|-------------|
| `ACADEMIC_RECORD` | Transcripts, grades, GPA, enrollment status |
| `FINANCIAL_AID` | Financial aid amounts, disbursements, eligibility |
| `DISCIPLINARY` | Disciplinary proceedings and records |
| `HEALTH` | Student health/medical records |
| `DIRECTORY` | Name, enrollment status, major, dates of attendance |
| `GENERAL` | Any other record type — blocked by default |

---

### `DisclosureReason`

Enum of FERPA exception categories under which disclosure is authorized.

| Value | CFR Citation | Description |
|-------|-------------|-------------|
| `SCHOOL_OFFICIAL` | §99.31(a)(1) | Legitimate educational interest |
| `TRANSFER` | §99.31(a)(2) | Transfer to another school |
| `AUDIT_EVALUATION` | §99.31(a)(3) | Authorized audit or evaluation |
| `FINANCIAL_AID` | §99.31(a)(4) | Determining eligibility for financial aid |
| `JUDICIAL_ORDER` | §99.31(a)(9) | Judicial order or subpoena |
| `SAFETY_EMERGENCY` | §99.31(a)(10) | Health or safety emergency |
| `DIRECTORY_INFORMATION` | §99.37 | Published directory information |

---

### `FERPAContextPolicy`

The primary filter class. Applies FERPA identity scoping to a list of retrieved documents.

```python
class FERPAContextPolicy:
    def __init__(self, scope: StudentIdentityScope): ...

    def filter_retrieved_documents(
        self,
        documents: list[dict],
        student_id_field: str = "student_id",
        institution_id_field: str = "institution_id",
        category_field: str = "category",
    ) -> list[dict]: ...

    def record_access(
        self,
        categories_accessed: set[RecordCategory],
    ) -> AuditRecord: ...
```

**`filter_retrieved_documents`** — Returns only documents matching the authorized scope. Documents without identity metadata (no `student_id` field) pass through unchanged.

**`record_access`** — Emits a 34 CFR §99.32 disclosure log entry. Call after filtering to record what was actually disclosed.

---

### `AuditRecord`

Structured disclosure log entry. Returned by `FERPAContextPolicy.record_access()`.

```python
@dataclass
class AuditRecord:
    student_id: str
    institution_id: str
    requesting_user_id: str
    categories_disclosed: list[RecordCategory]
    disclosure_reason: DisclosureReason
    disclosed_at: str        # ISO 8601 timestamp
    regulation_citation: str  # "34 CFR §99.32"

    def to_log_entry(self) -> str: ...
    def to_dict(self) -> dict: ...
```

---

### `make_enrollment_advisor_policy`

Factory: creates a pre-configured policy for enrollment advisor use cases.

```python
def make_enrollment_advisor_policy(
    student_id: str,
    institution_id: str,
    advisor_id: str,
) -> FERPAContextPolicy: ...
```

Authorizes: `ACADEMIC_RECORD`, `DIRECTORY`. Disclosure reason: `SCHOOL_OFFICIAL`.

---

## Context and pipeline

### `ContextEnvelope`

Multi-source context assembly for enterprise RAG. Combines documents from CRM, ERP, knowledge base, and other sources with provenance tracking.

```python
@dataclass
class ContextEnvelope:
    sources: list[ContextSource]
    assembled_at: str

    def add_source(self, name: str, documents: list[dict]) -> None: ...
    def get_by_source(self, name: str) -> list[dict]: ...
    def to_llm_context(self) -> str: ...
```

### `FilterPipeline`

Chains multiple compliance filters. Applies deny-all aggregation: a document is only passed to the LLM if it passes all filters.

```python
class FilterPipeline:
    def add_filter(self, name: str, policy: FERPAContextPolicy | Any) -> None: ...
    def run(self, documents: list[dict]) -> PipelineResult: ...

@dataclass
class PipelineResult:
    approved_docs: list[dict]
    denied_docs: list[dict]
    audit_records: list[AuditRecord]
    denied_by: dict[str, list[str]]  # filter_name → list of denied doc IDs
```

---

## Policy and escalation

### `ActionPolicy`

Defines which actions are permitted.

```python
@dataclass
class ActionPolicy:
    allowed_actions: set[str]
    denied_actions: set[str] = field(default_factory=set)
    escalation_rules: list[EscalationRule] = field(default_factory=list)
    default_deny: bool = True
```

### `EscalationRule`

Adds actions that require human review (not outright deny).

```python
@dataclass
class EscalationRule:
    action_pattern: str      # glob or exact match
    reason: str
    escalation_level: str    # "SUPERVISOR" | "COMPLIANCE" | "LEGAL"
```

---

## Regulation modules

### HIPAA — `enterprise_rag_patterns.regulations.hipaa`

```python
from enterprise_rag_patterns.regulations.hipaa import HIPAAContextPolicy, PHICategory, PatientIdentityScope
```

| Class | Description |
|-------|-------------|
| `PatientIdentityScope` | Patient + covered entity + requesting user + authorized PHI categories |
| `PHICategory` | Enum: `CLINICAL_NOTE`, `LAB_RESULT`, `PRESCRIPTION`, `RADIOLOGY`, `DEMOGRAPHIC`, `BILLING`, `MENTAL_HEALTH`, `SUDs_RECORDS` |
| `HIPAAContextPolicy` | Filters to minimum-necessary PHI; enforces 45 CFR §164.502 |

### GDPR — `enterprise_rag_patterns.regulations.gdpr`

```python
from enterprise_rag_patterns.regulations.gdpr import GDPRContextPolicy, GDPRLegalBasis
```

| Class | Description |
|-------|-------------|
| `GDPRLegalBasis` | Enum: `CONSENT`, `CONTRACT`, `LEGAL_OBLIGATION`, `VITAL_INTEREST`, `PUBLIC_TASK`, `LEGITIMATE_INTEREST` |
| `GDPRContextPolicy` | Enforces Art. 5 data minimisation + Art. 6 lawful basis + Art. 17 right to erasure |

### OWASP LLM — `enterprise_rag_patterns.regulations.owasp_llm`

```python
from enterprise_rag_patterns.regulations.owasp_llm import OWASPLLMScanner
```

Scans retrieved documents for OWASP LLM Top 10 (2025) indicators:
- LLM01: Prompt injection patterns
- LLM02: Insecure output (PII/credential leakage)
- LLM06: Sensitive information disclosure

### NIST AI RMF — `enterprise_rag_patterns.regulations.nist_ai_rmf`

```python
from enterprise_rag_patterns.regulations.nist_ai_rmf import NISTAIRMFPolicy
```

Enforces NIST AI RMF 1.0 + AI 600-1 GenAI Profile risk assessment controls.

---

## Vector store adapters

| Module | Class | Install extra |
|--------|-------|--------------|
| `vector_stores.pinecone_adapter` | `PineconeComplianceFilter` | `[pinecone]` |
| `vector_stores.weaviate_adapter` | `WeaviateComplianceFilter` | `[weaviate]` |
| `vector_stores.qdrant_adapter` | `QdrantComplianceFilter` | `[qdrant]` |
| `vector_stores.chroma_adapter` | `ChromaComplianceFilter` | `[chromadb]` |

All adapters implement a common interface:

```python
class VectorStoreComplianceFilter:
    def filter(self, documents: list[dict], scope: StudentIdentityScope) -> list[dict]: ...
    def filter_namespace(self, namespace: str, scope: StudentIdentityScope) -> list[dict]: ...
```

---

## Framework integrations

### LangChain — `enterprise_rag_patterns.integrations.langchain`

```python
from enterprise_rag_patterns.integrations.langchain import FERPAComplianceCallbackHandler

handler = FERPAComplianceCallbackHandler(
    student_id="stu_001",
    institution_id="univ_abc",
    requesting_user_id="advisor_007",
    authorized_categories={"academic_record"},
    audit_sink=lambda rec: write_to_db(rec),
)
```

Implements `BaseCallbackHandler.on_retriever_end` — fires after retrieval, before LLM.

### Haystack — `enterprise_rag_patterns.integrations.haystack`

```python
from enterprise_rag_patterns.integrations.haystack import FERPAHaystackFilter
```

Or use the standalone package:

```bash
pip install ferpa-haystack
```

```python
from haystack_integrations.components.filters.ferpa_filter import FERPAMetadataFilter
```

### LlamaIndex — `enterprise_rag_patterns.integrations.llama_index`

```python
from enterprise_rag_patterns.integrations.llama_index import FERPANodePostprocessor

postprocessor = FERPANodePostprocessor(
    student_id="stu_001",
    institution_id="univ_abc",
    authorized_categories={"academic_record"},
)
# Add to LlamaIndex query engine as a node postprocessor
```

---

## Async support

```python
from enterprise_rag_patterns.async_compliance import AsyncFERPAContextPolicy

policy = AsyncFERPAContextPolicy(scope=scope)
safe_docs = await policy.afilter_retrieved_documents(documents)
audit = await policy.arecord_access(categories_accessed={RecordCategory.ACADEMIC_RECORD})
```

All async methods are `await`-able. The underlying filtering logic is identical to the sync API.
