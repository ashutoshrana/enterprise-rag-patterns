# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.12.0] — 2026-04-13

### Added — Telecommunications Sector RAG Example (FCC CPNI + TCPA + NPAC)

**`examples/17_telecom_rag.py`** — three-layer defense-in-depth retrieval pipeline
for a telecommunications carrier's customer service and operations knowledge base:

New classes (self-contained in the example):
- `CPNICategory` — CPNI categories under 47 CFR Part 64 (CALL_DETAIL_RECORDS,
  LOCATION_DATA, NETWORK_USAGE, ACCOUNT_INFORMATION, AGGREGATE_ONLY, NON_CPNI, PUBLIC)
- `CPNIAuthorizedPurpose` — 47 CFR Part 64.2005 authorized purposes:
  ACCOUNT_SERVICING (always permitted), MARKETING_WIRELINE_SERVICES (same-type
  existing customers), MARKETING_JOINT_VENTURE / MARKETING_THIRD_PARTY (opt-in
  required), NETWORK_OPERATIONS (internal), LAW_ENFORCEMENT (compelled disclosure)
- `NPACDataType` — NPAC data types under 47 CFR Part 52 (PORTING_STATUS,
  ROUTING_RECORD, SPID_DATA, SUBSCRIPTION_DATA, NON_NPAC)
- `AgentRole` — telecom agent roles: CUSTOMER_SERVICE, MARKETING, NETWORK_OPERATIONS,
  PORTING_TEAM, CARRIER_RELATIONS, COMPLIANCE
- `TelecomAccessContext` — session boundary: authorized purposes, customer CPNI
  opt-out status (47 CFR 64.2008), TCPA consent status, NPAC authorization
- `TelecomComplianceAuditRecord` — per-query record with FCC/TCPA/NPAC citations
- `CPNIFilter` — Layer 1: enforces 47 CFR Part 64; blocks CPNI documents for
  marketing purpose when customer has not opted in; blocks all CPNI when
  customer has opted out (opt-out overrides all purpose claims)
- `TCPAFilter` — Layer 2: blocks customer contact data (phone numbers, contact
  preferences) for marketing agents without documented TCPA prior express written
  consent (PEWC); non-marketing roles are not subject to TCPA restriction
- `NPACFilter` — Layer 3: restricts NPAC routing/porting data to PORTING_TEAM,
  CARRIER_RELATIONS, NETWORK_OPERATIONS, COMPLIANCE roles with npac_authorized=True

Design notes: CPNI opt-out (customer-controlled) overrides all agent purpose claims.
TCPA restricts marketing agents specifically — operational roles accessing contact
data for legitimate non-marketing purposes are not restricted by TCPA.
NPAC data is inter-carrier routing data (not customer data) — exposure to customer-
facing agents creates competitive intelligence risk between carriers.

Scenarios:
- A: CSR with account_servicing purpose — all CPNI account/usage docs returned;
  NPAC blocked (customer service role not authorized)
- B: Marketing agent (no TCPA consent, no CPNI opt-in) — CPNI blocks only for
  marketing purpose; TCPA blocks contact preference docs; public product docs returned
- C: Customer opted out (47 CFR 64.2008) — CPNI filter blocks all CPNI regardless
  of agent purpose; non-CPNI docs returned
- D: Porting team (npac_authorized=True) — full access including NPAC porting/routing
  data; NETWORK_OPERATIONS purpose passes CPNI filter

Closes #38.

---

## [0.11.0] — 2026-04-13

### Added — Energy/Utilities Sector RAG Example (FERC CEII + NERC CIP + NRC SUNSI)

**`examples/16_energy_utilities_rag.py`** — three-layer defense-in-depth retrieval
pipeline for a bulk electric system (BES) operator's grid operations knowledge base:

New classes (self-contained in the example):
- `CEIICategory` — FERC CEII categories (CRITICAL_ASSET_LOCATION, GRID_VULNERABILITY,
  PROTECTION_SYSTEM, CONTROL_SYSTEM, CAPACITY_SENSITIVE, NON_CEII, PUBLIC)
- `NERCCIPTier` — NERC CIP reliability standard tiers (HIGH_IMPACT, MEDIUM_IMPACT,
  LOW_IMPACT, NOT_APPLICABLE); HIGH = transmission ≥ 500kV control centers, MEDIUM =
  substations ≥ 200kV and generation ≥ 1500 MW, LOW = distribution-level systems
- `OperatorRole` — utility roles (SYSTEM_OPERATOR, CIP_COMPLIANCE_ANALYST,
  FIELD_ENGINEER, THIRD_PARTY_CONTRACTOR, NRC_AUTHORIZED, PUBLIC)
- `SUNSIType` — NRC SUNSI types (SAFEGUARDS_INFORMATION, SECURITY_RELATED_INFO,
  EXPORT_CONTROLLED, NON_SUNSI)
- `EnergyAccessContext` — session boundary: authorized CEII categories, NERC CIP
  training completion status, authorized CIP tiers, NRC SUNSI authorization
- `EnergyComplianceAuditRecord` — per-query record: CEII blocked, NERC CIP blocked,
  NRC SUNSI blocked, documents returned, applicable regulations
- `CEIIFilter` — Layer 1: enforces FERC 18 CFR Part 388.113; blocks documents whose
  CEII category is not in the requester's authorized set
- `NERCCIPFilter` — Layer 2: enforces CIP-004-7 (personnel training) and CIP-011-3
  (information protection); blocks BCSI when training is not complete or tier is not
  in the requester's authorized tier set
- `SUNSIFilter` — Layer 3: enforces NRC 10 CFR Part 2.390; blocks safeguards
  information from non-NRC-authorized personnel
- `EnergyRAGPipeline` — three-layer orchestrator

Design note: CEII authorization (FERC-granted), NERC CIP authorization (utility-internal
training + access management), and NRC SUNSI authorization (NRC-granted) are three
independent authorization hierarchies. A CIP compliance analyst with all-tier CIP
training does not automatically have CEII authorization — and vice versa.

Scenarios:
- A: Certified system operator (CEII HIGH+MEDIUM+VULNERABILITY authorized, CIP HIGH+MEDIUM
  trained) — NRC SUNSI blocks nuclear safeguards; NERC CIP LOW-tier blocked (operator
  authorized for HIGH+MEDIUM only); CEII infrastructure docs returned
- B: Third-party contractor (no CEII authorization, CIP training not complete) — CEII
  blocks all critical infrastructure docs; CIP blocks BCSI; only PUBLIC docs returned
- C: CIP Compliance Analyst (all tiers trained, no CEII authorization) — CEII blocks
  critical asset/vulnerability docs; LOW-tier BCSI (distribution automation) returns
- D: Public information request — all three layers pass; pricing and tariff docs returned

Closes #33.

---

## [0.10.0] — 2026-04-13

### Added — Federal/Government RAG Example (CUI + FedRAMP + NIST 800-53 AC-3)

**`examples/15_government_federal_rag.py`** — three-layer defense-in-depth retrieval
pipeline for a federal procurement knowledge-base assistant, covering CUI handling
(32 CFR Part 2002), FedRAMP source authorization, and NIST 800-53 AC-3 role-based
access enforcement.

New classes (self-contained in the example):
- `CUICategory` — enumeration of CUI categories (PROCUREMENT_AND_ACQUISITION, EXPORT_CONTROLLED,
  LAW_ENFORCEMENT_SENSITIVE, CRITICAL_INFRASTRUCTURE, PRIVACY, CONTROLLED_TECHNICAL,
  UNCLASSIFIED, PUBLIC)
- `AgencyRole` — federal role hierarchy (PUBLIC_USER through CUI_AUTHORIZED_OFFICER)
- `CUIAccessContext` — access boundary for a retrieval session: agency role, authorized
  CUI categories, FedRAMP boundary flag; `may_access_cui()` enforces authorized-category
  membership before any retrieval executes
- `FederalComplianceAuditRecord` — per-query audit record capturing documents retrieved,
  documents blocked, CUI categories blocked, FedRAMP sources blocked, AC-3 level violations,
  and applicable regulations (32 CFR 2002, FedRAMP High Baseline, NIST 800-53 AC-3)
- `CUIFilter` — Layer 1: enforces 32 CFR Part 2002 CUI handling; blocks documents whose
  CUI category is not in the requester's `authorized_cui_categories`
- `FedRAMPSourceFilter` — Layer 2: blocks documents sourced from non-FedRAMP-authorized
  cloud providers; default authorized set: aws_govcloud, azure_government, gcp_assured_workloads,
  oracle_cloud_government, ibm_cloud_for_government
- `NIST80053AC3Filter` — Layer 3: role-hierarchy enforcement; `_ROLE_HIERARCHY` maps each
  `AgencyRole` to a numeric level; `_LEVEL_REQUIREMENTS` maps document sensitivity levels
  (PUBLIC/UNCLASSIFIED/SENSITIVE_BUT_UNCLASSIFIED/CONTROLLED/RESTRICTED) to minimum role
  level; documents blocked when `role_level < required_level`

Scenarios:
- A: CMMC-certified contractor (role=CONTRACTOR_CUI_CLEARED, authorized CUI//PROC+CTI) —
  FedRAMP blocks sam.gov/commercial sources; AC-3 blocks CONTROLLED documents (requires
  Contracting Officer level 3, contractor is level 2); FOUO/SBU documents returned
- B: Uncleared vendor (role=CONTRACTOR_UNCLEARED, no CUI authorization) — CUI layer
  blocks all CUI//PROC documents; no documents reach LLM context
- C: Contracting officer with partial CUI scope (authorized CUI//PROC only, not CTI) —
  CUI//CTI documents blocked by Layer 1; CONTROLLED documents pass AC-3 (officer=level 3);
  mixed retrieval result
- D: Non-FedRAMP cloud source — FedRAMP layer blocks all commercial cloud documents
  regardless of CUI category or role level; zero documents returned

Closes #32.

---

## [0.9.0] — 2026-04-13

### Added — Legal Sector RAG Example

**`examples/14_legal_sector_rag.py`** — attorney-client privilege and ABA Model Rules
compliance for a law firm matter research assistant. Three compliance layers:

- **Layer 1 — ABA Rule 1.6 (Confidentiality):** `MatterScopeFilter` restricts retrieval
  to authorized matter personnel. Documents tagged with a `matter_id` are accessible only
  if the requester's `authorized_matter_ids` includes that matter.
- **Layer 2 — ABA Rule 1.7 / 1.9 (Conflicts of Interest):** `ConflictChecker` scans
  retrieved documents for adverse-party entity names. If a conflict is detected, retrieval
  halts and a conflict record is raised before any document reaches the LLM context window.
- **Layer 3 — ABA Rule 1.15 (Safekeeping of Client Property):** `Rule1_15Filter` isolates
  `CLIENT_FINANCIAL` documents to their scoped `matter_id`. A billing partner authorized
  on both matters cannot aggregate financial data across clients in a single query.

New classes:
- `MatterScope` — authorized access boundary for a matter research session (analogous to
  `StudentIdentityScope` for FERPA)
- `MatterScopeFilter` — ABA Rule 1.6 scope enforcement with `LegalAuditRecord` emission
- `ConflictChecker` — ABA Rule 1.7/1.9 adverse-party scanner; halts retrieval on conflict
- `Rule1_15Filter` — cross-matter financial isolation filter
- `LegalAuditRecord` — audit record capturing matter_id, requester, privilege_tags_blocked,
  conflict_parties_detected, ABA rules invoked, outcome

Scenarios:
- A: Authorized associate queries own matter → full retrieval (ALLOW)
- B: Paralegal queries matter they're not on → privileged documents blocked (Rule 1.6)
- C: Query returns document mentioning adverse party → retrieval halted (Rule 1.7)
- D: Billing partner cross-matter financial query → Rule 1.15 isolation applied

Closes #31.

---

## [0.8.5] — 2026-04-13

### Added — Financial Services RAG Example (PCI DSS + GLBA)

**`examples/13_financial_services_rag.py`** — defense-in-depth RAG pipeline for a
wealth management chatbot combining PCI DSS v4.0 and GLBA Safeguards Rule compliance:
- Three-layer defense model: OWASP LLM01 injection scan → GLBA NPI purpose limitation
  → PCI DSS PAN masking + cardholder data category enforcement
- Scenario A: authorized wealth advisor — all 5 docs pass; raw PAN masked to `[PAN-MASKED]`
- Scenario B: PAN masking demonstration — `4532-0151-2345-6789` replaced before LLM context
- Scenario C: unauthenticated user (no authorized purposes) — GLBA blocks 4/5 NPI docs;
  only public market research reaches the LLM
- Scenario D: prompt injection attempt — OWASP LLM01 scanner halts pipeline before retrieval
- Compliance audit summary: GLBA/PCI audit events, OWASP scan events, total PAN masked
- Defense-in-depth layer map with PCI DSS Req and GLBA § references
- Closes #30.

---

## [0.8.4] — 2026-04-13

### Added — Cross-Channel Session Continuity Example

**`examples/12_cross_channel_session.py`** — 6-step `SessionState` lifecycle across
IVR voice → web chat → email → chat:
- `register_channel` tracks the full interaction path (IVR → chat → email)
- `add_checkpoint` records intents and actions; chat replays IVR context without
  re-asking identity or intent
- `escalated` flag set on withdrawal request — monotonically True, all channels
  route to human thereafter
- `ContextEnvelope` packages escalation handoff for human advisor with channel_path,
  escalation_reason, and checkpoint count
- Five session continuity design principles
- Closes #1.

---

## [0.8.3] — 2026-04-13

### Added — Multi-Source Context Assembly Example

**`examples/11_context_assembly.py`** — assembles `ContextEnvelope` from five enterprise
data sources (SIS, financial aid, knowledge base, policy docs, real-time data) with
FERPA pre-filtering and freshness enforcement:
- Scenario 1: enrollment advisor scope (ACADEMIC_RECORD only) — 2 financial docs filtered
- Scenario 2: financial aid advisor scope (academic + financial) — all docs available
- Scenario 3: cross-institution contamination test — `gwu` doc blocked despite correct student_id
- Freshness enforcement: SIS ≤ 1h, real-time ≤ 60s; stale sources excluded and logged
- `ContextEnvelope` metadata tracks source count, pre/post filter counts, FERPA removals
- LLM context string formatting via `to_llm_context()`
- Closes #2.

---

## [0.8.2] — 2026-04-13

### Added — Human Escalation Policy Example

**`examples/10_escalation_policy.py`** — `ActionPolicy` and `EscalationRule` applied to an
enrollment advisor agent with three escalation trigger types:
- **Regulatory triggers**: `submit_withdrawal`, `process_financial_aid_change`, `override_academic_hold`,
  `release_pii_export` — always route to human regardless of confidence
- **Content-based triggers**: `disciplinary`, `financial hardship`, `legal dispute`, `grievance`, `deceased`
  keywords in retrieved context trigger required human handoff
- **Confidence thresholds**: `REQUIRED` < 50% (agent cannot respond), `SOFT` < 75%
  (agent may attempt with human available)
- **Audit trail**: `EscalationEvent` records which rule triggered each escalation
- **FERPA-correct message**: agent never discloses escalation reason to user (34 CFR § 99.12)
- Closes #3.

---

## [0.8.1] — 2026-04-13

### Added — Vector Store Integration Examples

**`examples/09_vector_store_adapters.py`** — end-to-end showcase of all four
compliance filter adapters applied to the same `ComplianceFilter` input:

- **pgvector / psycopg2 (JSONB column):** `metadata->>'student_id' = %s AND ... = ANY(%s)`
- **pgvector / psycopg2 (normalised columns):** `student_id = %s AND ...`
- **pgvector / asyncpg:** `$N`-style placeholders with `::text[]` cast
- **Pinecone v8:** `{"$and": [{"student_id": {"$eq": "..."}}, ...]}`
- **ChromaDB v1.5+:** `{"$and": [{"student_id": {"$eq": "..."}}, ...]}`
- **Weaviate v4:** `Filter.by_property(...).equal(...) & ...` (lazy import)
- **No-category-restriction variant** (HIPAA treatment authorization — no `$in` clause generated)

Shows full usage patterns including FastAPI async (Pinecone `IndexAsyncio`),
defense-in-depth namespace + metadata isolation, and correct query construction
with the compliance filter appended to the embedding parameter tuple.
Closes #5.

---

## [0.8.0] — 2026-04-13

### Added

- `integrations/dspy.py`: `FERPADSPyRetriever` and `HIPAADSPyRetriever` — DSPy
  retriever wrappers that apply FERPA identity-scope filtering and HIPAA
  minimum-necessary filtering respectively (DSPy ≥ 2.5.0, Pydantic v2).

  **`FERPADSPyRetriever`**:
  - Wraps any DSPy ``Retrieve`` module or compatible callable.
  - Intercepts retrieved passages and runs them through
    ``FERPAContextPolicy.filter_retrieved_documents()``.
  - Passages tagged to a different student, institution, or unauthorized category
    are silently removed — consistent with FERPA's prohibition on disclosing which
    records were withheld (34 CFR § 99.12).
  - ``__getattr__`` delegation — DSPy pipeline composition and introspection
    work transparently through the wrapper.
  - Used exactly like the original retriever in a DSPy ``Module.forward()`` method.

  **`HIPAADSPyRetriever`**:
  - Same pattern; applies ``HIPAAContextPolicy.filter_retrieved_documents()``
    (45 CFR § 164.502(b) minimum-necessary) before passages reach the LLM.

  Closes #14, #10. 31 new tests.

- `integrations/__init__.py`: exports `FERPADSPyRetriever`, `HIPAADSPyRetriever`.

---

## [0.7.0] — 2026-04-13

### Added

- `regulations/eu_ai_act.py`: `EUAIActAuditLogger`, `EUAIActRetrievalRecord`,
  `EUAIActRiskTier`, `AnnexIIICategory`, `classify_annex_iii_risk`,
  `SYSTEM_AI_DISCLOSURE` — EU AI Act 2024/1689 Article 12 tamper-evident audit
  log for high-risk RAG systems.

  **Article 12 capabilities:**
  - `EUAIActAuditLogger` captures the full chain-of-custody per retrieval event:
    query hash → retrieved document IDs → context window hash → response hash.
  - Every record is **HMAC-SHA256 signed** (tamper-evidence). `verify_record()`
    re-computes the HMAC; a mismatch means the record was altered after creation.
  - Records are **hash-chained**: each record's `previous_record_hash` is the
    SHA-256 of the preceding record. `verify_chain()` detects insertions,
    deletions, and reordering.
  - `seal_response(record, response_text)` seals the model response into an
    existing record (creates a new immutable record with updated HMAC).
  - `include_query_preview=False` by default — storing cleartext queries requires
    a lawful basis under GDPR Art. 6.
  - `to_log_entry()` serialises to a JSON-safe dict for append-only log stores
    (AWS CloudTrail, Azure Immutable Blob, Google Cloud Audit Logs).

  **Annex III risk classification:**
  - `AnnexIIICategory` enum maps to Annex III §1–§8 use case categories.
  - `classify_annex_iii_risk(category)` returns the risk tier and plain-English
    rationale citing the relevant Annex III section.
  - Education AI (§3), employment AI (§4), law enforcement AI (§6), etc. all
    return `EUAIActRiskTier.HIGH_RISK`.

  **Art. 13 transparency:** `SYSTEM_AI_DISCLOSURE` constant for human-facing
  disclosure that responses were generated by an AI system.

  Penalty context: up to €35M or 7% of global annual revenue for Art. 12
  non-compliance (Art. 99(3)).  Closes #28.  55 new tests.

- `regulations/__init__.py`: exports all 6 EU AI Act symbols; updated
  cross-industry module table with EU AI Act entry.

---

## [0.6.0] — 2026-04-13

### Added

- `vector_stores/pgvector_adapter.py`: `PGVectorComplianceFilter` and
  `PGVectorSQLAlchemyFilter` — compliance-scoped filter adapters for PostgreSQL
  with the `pgvector` extension, the most common enterprise vector store.

  **`PGVectorComplianceFilter`** builds SQL `WHERE` clause fragments + parameterised
  argument tuples for direct database drivers:
  - `build_filter()` — psycopg2 `%s` placeholders; supports both JSONB metadata
    column (`metadata->>'student_id' = %s … AND metadata->>'category' = ANY(%s)`)
    and normalised column (`student_id = %s … AND category = ANY(%s)`) schemas.
  - `build_asyncpg_filter()` — asyncpg `$N` positional placeholders with explicit
    `::text[]` cast for array parameters (`= ANY($3::text[])`).
  - Configurable column / field names (`metadata_column_name`, `student_id_field`,
    `institution_id_field`, `category_field`).
  - Categories sorted deterministically in all output parameter lists.

  **`PGVectorSQLAlchemyFilter`** builds a `sqlalchemy.sql.ColumnElement` boolean
  expression for SQLAlchemy ORM / Core queries (recommended for FastAPI apps):
  - JSONB column mode: `metadata_col["key"].as_string() == value` with `or_()`
    for multi-category matching.
  - Normalised column mode: `col == value` / `col.in_(sorted_categories)`.
  - `sqlalchemy` import is lazy — the module can be imported without SQLAlchemy
    installed; `ImportError` is raised only when `build_filter()` is called.
  - `ValueError` raised at construction time if neither `metadata_column` nor
    the `student_id_column + institution_id_column` pair is provided.

  Satisfies FERPA 34 CFR § 99.3 pre-filter requirement: SQL `WHERE` clauses applied
  before the `<=>` (cosine distance) ranking step guarantee identity scoping at the
  query layer. Closes #16, #9. 31 new tests (29 passing + 2 skipped when SQLAlchemy
  not installed).

- `vector_stores/__init__.py`: exports `PGVectorComplianceFilter`,
  `PGVectorSQLAlchemyFilter`; updated module docstring.

---

## [0.5.3] — 2026-04-12

### Added

- `regulations/glba.py`: `GLBAContextPolicy`, `GLBAAccessContext`, `GLBAAccessScope`,
  `GLBADataCategory`, `GLBAAuditRecord` — GLBA Safeguards Rule (16 CFR § 314) NPI access
  control for RAG pipelines.  Three independent controls applied per document:
  (1) **§ 314.3** institution isolation — documents from other financial institutions are
  blocked unconditionally;
  (2) **§ 314.4(e)** purpose limitation — NPI categories (`NONPUBLIC_PERSONAL`,
  `ACCOUNT_DATA`, `TRANSACTION_HISTORY`, `CREDIT_INFORMATION`) require the actor's declared
  purpose to be in their authorized purposes set;
  (3) **§ 314.4(i)** marketing-role restriction — `CREDIT_INFORMATION` and
  `TRANSACTION_HISTORY` are always blocked for marketing-role actors regardless of purpose.
  `GLBAAccessScope.permits()` helper for pre-validated scope checks.
  SHA-256 tamper-evident `GLBAAuditRecord` with `content_hash()` (§ 314.4(h) monitoring).
  56 new tests.
- `regulations/__init__.py`: exports all five GLBA symbols; updated cross-industry module
  table and docstring with GLBA Safeguards Rule entry.

---

## [0.5.2] — 2026-04-13

### Added

- `regulations/iso27001.py`: `ISMSContextPolicy`, `ISMSAccessContext`, `ISMSClassification`,
  `ISMSAuditRecord` — ISO/IEC 27001:2022 ISMS context-based access control (CBAC) for RAG
  pipelines.  Three independent controls applied per document:
  (1) **A.5.15** organization isolation — tenant boundary enforcement;
  (2) **A.5.12 / A.8.12** classification enforcement — PUBLIC/INTERNAL/CONFIDENTIAL/SECRET
  label hierarchy with fail-safe unknown-label blocking;
  (3) **A.8.2** role-based access — per-document `required_roles` intersection check.
  SHA-256 tamper-evident `ISMSAuditRecord` (A.8.15). 44 new tests.
- `regulations/pci_dss.py`: `PCIContextPolicy`, `PCIAccessScope`, `PCIDataCategory`,
  `PCIAuditRecord` — PCI DSS v4.0 access control and PAN masking for RAG pipelines.
  Three controls:
  (1) **Req 7.2** merchant isolation — per-merchant tenant boundary;
  (2) **Req 7.2.1** category need-to-know — CARDHOLDER_DATA and SENSITIVE_AUTH_DATA require
  explicit authorization; unknown categories default to NON_CHD (permissive, outside PCI scope);
  (3) **Req 3.4** PAN masking — `\\b(?:\\d{{4}}[- ]?){{3}}\\d{{4}}\\b` → `[PAN-MASKED]` in all
  string-valued document fields.  `last_pan_masked_count` property tracks aggregate substitution
  count.  SHA-256 tamper-evident `PCIAuditRecord` (Req 10.3). 37 new tests.
- `regulations/__init__.py`: exports all ISO 27001 and PCI DSS symbols; updated cross-industry
  module table with IT audit / security framework categorisation.

---

## [0.5.1] — 2026-04-13

### Added

- `regulations/soc2.py`: `SOC2ContextPolicy`, `SOC2AccessContext`, `SOC2ConfidentialityTier`,
  `SOC2AuditRecord` — SOC 2 Type II context-based access control (CBAC) for RAG pipelines.
  Three-layer defense-in-depth:
  (1) **CC6.1** tenant isolation — documents outside the authorized tenant boundary are blocked
  unconditionally;
  (2) **C1.1/C1.2** confidentiality tier — PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED label
  enforcement with fail-safe unknown-tier blocking;
  (3) **CC6.6** role-based access — role intersection check on per-document `required_roles`
  fields.  SHA-256 tamper-evident `SOC2AuditRecord` with `content_hash()`. 28 new tests. Closes #27.
- `regulations/__init__.py`: exports all four SOC 2 symbols; updated cross-industry table
  in module docstring.

---

## [0.5.0] — 2026-04-12

### Added — Cross-Industry Compliance Framework

This release expands `enterprise-rag-patterns` from a single-regulation library
(FERPA) into a **cross-industry compliance framework** for RAG pipelines. New
regulation modules apply to healthcare, government, software, and any sector
requiring governed AI.

- `regulations/hipaa.py`: `HIPAAContextPolicy`, `HIPAAAccessScope`, `HIPAAPurpose`,
  `HIPAAAuditRecord` — HIPAA minimum-necessary enforcement (45 CFR § 164.502(b))
  for ePHI retrieval. Three-layer filter: patient identity, HIPAA purpose
  (treatment/payment/operations/research), PHI category. SHA-256 tamper-evident
  audit records per 45 CFR § 164.312(b). Closes #27.

- `regulations/nist_ai_rmf.py`: `AIRMFRAGPolicy`, `AIRMFRetrievalRisk`,
  `AIRMFAuditRecord`, `AIRMFRiskLevel`, `AIRMFFunction` — NIST AI RMF 1.0
  (NIST AI 100-1) + Generative AI Profile (NIST AI 600-1) risk assessment for
  RAG events. MAP/MEASURE/MANAGE function coverage: PII exposure scoring,
  confabulation risk from relevance scores, incident tracking. Closes #28.

- `regulations/owasp_llm.py`: `OWASPSensitiveDisclosureFilter` (LLM02:2025),
  `OWASPPromptInjectionScanner` (LLM01:2025), `OWASPLLMRisk`, `OWASPAuditRecord`
  — OWASP LLM Top 10 (2025 edition) security controls. Redact/block mode for
  PII fields; pattern-based prompt injection detection with quarantine support.
  Closes #29.

- `regulations/__init__.py`: updated to export all 3 new modules alongside
  existing GDPR patterns; compliance table in module docstring.

- `py.typed` marker (PEP 561) — enables mypy/pyright type inference for consumers.

### Fixed
- `pyproject.toml`: `pinecone>=5.0.0` → `>=8.0.0` (IndexAsyncio requires v8).
- `integrations/langchain_lcel.py`: `FERPAFilterRunnable` now exposes `invoke()`
  and `ainvoke()` satisfying the LangChain duck-typed Runnable protocol.
- GitHub Actions: `actions/checkout@v6` → `@v4`, `setup-python@v6` → `@v5`
  (v6 does not exist; jobs silently failed on version resolution).

---

## [0.4.2] — 2026-04-13

### Added
- `vector_stores/pinecone_adapter.py`: `PineconeNamespaceIsolation` — defense-in-depth adapter for Pinecone v8 multi-institution deployments. Layer 1: maps `institution_id` → Pinecone namespace (hardware isolation, cross-institution queries structurally impossible). Layer 2: adds `student_id` metadata filter (software isolation). Supports both sync (`query_sync`) and async (`async_query` via `IndexAsyncio`) Pinecone v8 clients. Custom `namespace_resolver` callable for institution-ID-to-namespace mapping. Closes #26.
- `vector_stores/__init__.py`: exports `PineconeNamespaceIsolation`

---

## [0.4.1] — 2026-04-13

### Added
- `integrations/langchain_lcel.py`: `FERPAFilterRunnable` — LangChain LCEL step that makes FERPA filtering an explicit `Runnable` in the `|` pipe chain. Supports per-request scope injection via `RunnableConfig["metadata"]["ferpa_scope"]`. Closes #25.
- `integrations/langchain_lcel.py`: `make_ferpa_chain()` — factory that wires `retriever | FERPAFilterRunnable | prompt | llm [| output_parser]` in one call.
- `integrations/__init__.py`: exports `FERPAFilterRunnable`, `make_ferpa_chain`

### Fixed
- `integrations/llama_index_workflow.py`: ruff format fix (whitespace normalization)

---

## [0.4.0] — 2026-04-12

### Added
- `integrations/maf.py`: `FERPAAgentMiddleware` — Microsoft Agent Framework (MAF) middleware intercepting agent tool-call messages, applying FERPA identity-scope filtering, emitting 34 CFR § 99.32 audit records. MAF is the enterprise-ready successor to AutoGen and Semantic Kernel (released 2026).
- `integrations/llama_index_workflow.py`: `FERPAWorkflowStep` + `FERPAFilterEvent` — LlamaIndex 0.12+ event-driven Workflow step enforcing FERPA scoping between retrieval and synthesis steps. Compatible with `llama-index-core>=0.12.0` (current: 0.14.20).
- New `[maf]` optional dependency: `microsoft-agent-framework>=1.0.0`

### Changed
- Bumped ecosystem compatibility pins:
  - `llama-index-core`: `>=0.10.0` → `>=0.12.0` (LlamaIndex 0.14.20 current)
  - `haystack-ai`: `>=2.0.0` → `>=2.20.0` (Haystack 2.27.0 current)
  - `pinecone`: `>=3.0.0` → `>=5.0.0` (Pinecone 8.1.2 current; v5 required for async API)
  - `weaviate-client`: `>=4.0.0` → `>=4.10.0` (Weaviate 4.20.5 current)
  - `chromadb`: `>=0.5.0` → `>=1.0.0` (ChromaDB 1.5.7 current; v1.0 is GA)
- `integrations/__init__.py`: exports `FERPAAgentMiddleware`, `FERPAWorkflowStep`, `FERPAFilterEvent`
- `pyproject.toml`: version bumped to 0.4.0; `[all]` extra now includes `[maf]`

---

## [0.3.0] — 2026-04-12

### Added
- Enhanced CI: coverage reporting (Codecov), ruff format check, build-check job, pip cache, concurrency cancellation
- Automation: PR auto-labeler, stale bot, Conventional Commits PR title check, first-contributor welcome bot
- Dependabot; CODEOWNERS; SECURITY.md; pre-commit config; automated release notes
- `integrations/langchain.py`: `FERPAComplianceCallbackHandler` — LangChain callback handler intercepting `on_retriever_end`, applying identity-scope filtering in-place, emitting 34 CFR § 99.32 audit records
- LangChain added as `[langchain]` optional dependency (`langchain-core>=0.3.0`)
- ADRs: `docs/adr/004-pydantic-v2-data-models.md`
- README: badge row, FERPA pipeline ASCII diagram, ecosystem integration table, 60-second quickstart, regulations table, BibTeX citation
- GitHub Discussions enabled; 22 standardized labels (type/*, priority/*, status/*, area/*); milestones v0.3.0 + v1.0.0

---

## [0.2.0] - 2026-04-11

### Added

**Vector store filter adapters** (`src/enterprise_rag_patterns/vector_stores/`):
- `base.py` — `ComplianceFilter` dataclass and `VectorStoreFilterAdapter` ABC; portable filter specification for compliance-scoped vector queries
- `pinecone_adapter.py` — `PineconeComplianceFilter`: builds Pinecone v8 metadata filter dict (`$and` / `$eq` / `$in`) for FERPA/HIPAA scoping
- `weaviate_adapter.py` — `WeaviateComplianceFilter`: builds Weaviate v4 `Filter` object using `Filter.by_property().equal()` and `&` combinator; lazy import
- `qdrant_adapter.py` — `QdrantComplianceFilter`: builds Qdrant `Filter` with `FieldCondition` / `MatchValue` / `MatchAny`; lazy import
- `chroma_adapter.py` — `ChromaComplianceFilter`: builds ChromaDB `where` dict with `$and` / `$eq` / `$in` operators

**Framework integrations** (`src/enterprise_rag_patterns/integrations/`):
- `llama_index.py` — `FERPANodePostprocessor`: LlamaIndex `BaseNodePostprocessor` enforcing student identity scoping; emits 34 CFR § 99.32 audit log entries
- `haystack.py` — `FERPAHaystackFilter`: Haystack 2.x `@component` filtering documents on `meta["student_id"]` and `meta["institution_id"]`; lazy import with `_make_haystack_component()` for pipeline serialisation

**GDPR regulation module** (`src/enterprise_rag_patterns/regulations/`):
- `gdpr.py` — GDPR Article 17 RAG-layer erasure patterns: `ErasureRequest`, `ErasureAuditRecord`, `GDPRRAGPolicy`; supports `filter_for_subject`, `record_erasure`, and `to_log_entry`
- `__init__.py` — exports all GDPR symbols

**Async compliance** (`src/enterprise_rag_patterns/async_compliance.py`):
- `async_filter_retrieved_documents` — async wrapper for `FERPAContextPolicy.filter_retrieved_documents`
- `async_record_access` — async wrapper for `FERPAContextPolicy.record_access`
- Async-wrapper pattern: `await asyncio.sleep(0)` yields to event loop then delegates to synchronous implementation — compatible with all async AI frameworks

**Tests**:
- `tests/test_vector_store_adapters.py` — full coverage of all four adapters; verifies filter structure without real vector store connections
- `tests/test_gdpr.py` — covers `ErasureRequest`, `GDPRRAGPolicy.filter_for_subject`, `record_erasure`, `to_log_entry`
- `tests/test_integrations.py` — covers `FERPAHaystackFilter` and `FERPANodePostprocessor` with duck-typed stubs; no framework import required
- `tests/test_async_compliance.py` — covers `async_filter_retrieved_documents` and `async_record_access` via `asyncio.run`

**Open-source contribution infrastructure**:
- `CONTRIBUTING.md` — comprehensive guide: dev setup, how to add adapters/regulations/integrations, PR checklist with regulatory citation requirement
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1
- `ECOSYSTEM.md` — compatibility matrix for vector stores, frameworks, and regulations
- `.github/ISSUE_TEMPLATE/new-vector-store.md` — issue template for new vector store adapters
- `.github/ISSUE_TEMPLATE/new-regulation.md` — issue template for new regulation modules
- `.github/ISSUE_TEMPLATE/new-framework-integration.md` — issue template for new framework integrations

**Package configuration**:
- `pyproject.toml` — version bumped to `0.2.0`; added optional dependency groups: `llama-index`, `haystack`, `pinecone`, `weaviate`, `qdrant`, `chromadb`, `all`

---

## [0.1.0] — 2026-04-11

### Added

**Core modules:**
- `context.py` — `ContextEnvelope` and `ContextSource` for context assembly across multiple source systems
- `session.py` — `SessionState` for cross-channel continuity (web, voice, messaging, dashboard)
- `policy.py` — `ActionPolicy` and `EscalationRule` for workflow-safe action boundaries and human escalation
- `compliance.py` — FERPA-aware context governance:
  - `StudentIdentityScope` — defines retrieval boundary per student and institution
  - `FERPAContextPolicy` — two-layer enforcement (pre-filter + category authorization)
  - `AuditRecord` — structured 34 CFR § 99.32 disclosure logging
  - `make_enrollment_advisor_policy` — factory for the most common higher-education RAG use case

**Documentation:**
- `docs/architecture.md` — layered architecture overview with design principles
- `docs/implementation-note-01.md` — cross-channel continuity problem and solution
- `docs/implementation-note-02.md` — FERPA boundaries in retrieval-augmented generation
- `docs/articles/production-grade-rag-in-regulated-enterprise-environments.md`
- `docs/case-study-anonymized.md` — anonymized production deployment notes

**Examples:**
- `examples/context-pipeline.yaml` — declarative context assembly reference
- `examples/ferpa_rag_pipeline.py` — complete runnable FERPA-compliant four-layer RAG pipeline

**Project infrastructure:**
- `CITATION.cff` — enables GitHub "Cite this repository" button
- `CONTRIBUTING.md` — contribution guidance
- `GOVERNANCE.md` — project governance model
- `ROADMAP.md` — near-term development direction
- `pyproject.toml` — setuptools build configuration with keywords, classifiers, and optional dependency groups
- GitHub Actions CI: pytest (Python 3.10–3.12), ruff lint, mypy type check
- Issue templates: bug report, feature request
- 85 passing tests covering all public module APIs
