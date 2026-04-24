# Adoption

## PyPI Downloads

Verified via [pypistats.org](https://pypistats.org/packages/enterprise-rag-patterns) — independent third-party statistics.

| Week of | Downloads |
|---------|-----------|
| 2026-04-13 | ~2,896 |
| 2026-04-20 | ~2,607 |

Downloads are organic — no self-installs, no promotional campaigns.

## How It Is Used

`enterprise-rag-patterns` is a reference implementation library. Developers use it to:

1. **Enforce FERPA/HIPAA/GDPR at the retrieval layer** — before any document reaches the LLM context window
2. **Audit all document access decisions** — every retrieval produces a structured compliance record
3. **Adapt to any vector store** — Pinecone, Weaviate, Qdrant, Chroma, OpenSearch all supported via adapters

## Regulated Sector Coverage

50 sector-specific examples across every regulated industry:

| Sector | Regulations Enforced |
|--------|---------------------|
| Higher Education | FERPA (34 CFR § 99) |
| Healthcare / Hospital Systems | HIPAA, FDA 21 CFR Part 11 |
| Financial Services | GLBA, FINRA/SEC |
| Government / Public Sector | FedRAMP, FISMA, NIST SP 800-53 |
| Energy & Utilities | NERC CIP, FERC CEII |
| Insurance | NAIC Model Law |
| Legal / Law Firms | CCPA, attorney-client privilege |
| Defense / Aerospace | ITAR, EAR |
| Pharmaceuticals | FDA 21 CFR, GCP |
| Real Estate / Mortgage | RESPA, HMDA |

## Why Pre-Retrieval Enforcement

The standard enterprise RAG architecture applies compliance checks **after** the LLM processes documents. This is architecturally insufficient for FERPA, HIPAA, and GDPR:

- A post-processing filter cannot un-expose a document already in the context window
- FERPA defines a "disclosure" as any release of personally identifiable information — including to an LLM
- HIPAA's Minimum Necessary Rule applies at the point of access, not after processing

This library enforces compliance **at the retrieval layer**, before documents enter the context window.

## Related Packages

- [regulated-ai-governance](https://pypi.org/project/regulated-ai-governance/) — Policy enforcement for AI agent frameworks (CrewAI, AutoGen, LangChain, Google ADK)
- [integration-automation-patterns](https://pypi.org/project/integration-automation-patterns/) — Enterprise integration and workflow orchestration patterns
- [ferpa-haystack](https://pypi.org/project/ferpa-haystack/) — Haystack-native FERPA document filter component
