# ADR-004: Use Pydantic v2 for Internal Data Models

**Status:** Accepted  
**Date:** 2026-04-12  
**Deciders:** Ashutosh Rana

## Context

The library needs a consistent strategy for defining and validating internal data models: compliance filter scopes, audit records, and configuration objects. Three options were considered:

1. **Plain Python dataclasses** — zero deps, no runtime validation, but type errors are silent at assignment
2. **attrs** — powerful, but niche; adds a dependency most RAG teams don't already carry
3. **Pydantic v2** — widely adopted in the Python ML/API ecosystem; LangChain, LlamaIndex, FastAPI, and most RAG frameworks already vendor or require it; provides runtime validation plus JSON serialization out of the box

The key tension is between keeping the library dependency-light (important for embedding in enterprise environments with strict dependency governance) and providing validated, serializable data contracts (important for audit records that must survive round-trips through logging pipelines and message queues).

## Decision

Use Pydantic v2 `BaseModel` for all externally-visible data contracts — `StudentIdentityScope`, `FERPAAuditRecord`, `ComplianceFilter`, and their regulation-specific subclasses. Use plain Python `dataclasses` for internal-only intermediate structures that never leave the library boundary.

## Rationale

**Why Pydantic over dataclasses for public models:**
- Audit records are serialized to JSON for compliance logging pipelines (Splunk, CloudWatch, SIEM tools). Pydantic's `.model_dump_json()` handles datetime formatting, UUID serialization, and nested model flattening correctly by default; dataclasses require custom `__init__` or `json.dumps` adapters.
- Regulation-specific scope objects (FERPA vs HIPAA vs GLBA) benefit from Pydantic's discriminated union support — a log consumer can deserialize a union of scope types without a manual type registry.
- `model_config = ConfigDict(frozen=True)` gives immutable value objects at zero extra code, preventing mutation of a scope after enforcement is already in progress.

**Why v2 specifically over v1:**
- Pydantic v2's Rust core (`pydantic-core`) validates ~5–50x faster than v1, which matters when filtering hundreds of retrieved chunks per query.
- v1 is in maintenance mode only; new framework integrations (LangChain v0.2+, LlamaIndex core) target v2 models. Shipping v1 models would force downstream consumers to run two Pydantic versions.

**Why not attrs:**
- attrs has excellent ergonomics but near-zero overlap with the existing dependency graphs of LangChain, LlamaIndex, and FastAPI. Adding it would increase resolution complexity for enterprise environments that audit transitive dependencies.

## Consequences

**Positive:**
- Audit records can be directly serialized to JSON without custom serializers, simplifying integration with SIEM and log aggregation tools.
- Framework integration code (LangChain, DSPy, LlamaIndex adapters) can pass Pydantic models directly without conversion, since those frameworks already speak Pydantic v2.
- Frozen models prevent accidental mutation of a scope mid-enforcement, which could cause a compliance bypass race condition.

**Negative:**
- Pydantic v2 is a non-trivial dependency (~2.5 MB wheel with compiled extension). Environments that explicitly prohibit compiled extensions (some FIPS-compliant deployments, certain air-gapped envs) will need the pure-Python fallback path.
- Adding Pydantic as a hard dependency rather than optional means all consumers install it, even those only using the idempotency utilities that don't touch compliance models.

**Neutral:**
- Pydantic v2 requires Python 3.8+. This aligns with the library's stated minimum Python version and is not an additional constraint.
- Migration from v1 to v2 model syntax (`.dict()` → `.model_dump()`, `class Config` → `model_config`) is a one-time cost already paid.
