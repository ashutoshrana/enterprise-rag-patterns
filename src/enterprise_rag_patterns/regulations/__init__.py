"""
regulations — Cross-industry RAG compliance patterns.

Each sub-module provides the RAG-layer primitives for a specific regulation
or compliance framework.  These modules address the retrieval and
context-assembly layer — they are not general-purpose compliance engines.

Available modules
-----------------
- ``ferpa``    — FERPA 34 CFR § 99 patterns (in parent: ``enterprise_rag_patterns.compliance``).
- ``gdpr``     — GDPR Article 17 right-to-erasure patterns.
- ``hipaa``    — HIPAA 45 CFR §§ 164.312(b), 164.502(b) ePHI access control + audit.
- ``nist_ai_rmf`` — NIST AI RMF 1.0 + AI 600-1 GenAI Profile risk assessment.
- ``owasp_llm``   — OWASP LLM Top 10 (2025): LLM01 prompt injection, LLM02 sensitive
  disclosure prevention.

Cross-industry applicability
-----------------------------

| Regulation      | Primary Sector       | RAG-Specific Control                      |
|-----------------|----------------------|-------------------------------------------|
| FERPA           | Education            | Student identity scoping, audit logging   |
| GDPR            | EU / Global          | Erasure, data subject rights, lineage     |
| HIPAA           | Healthcare           | ePHI minimum-necessary, audit controls    |
| NIST AI RMF     | All sectors          | Risk assessment, confabulation scoring    |
| OWASP LLM Top 10| Software / AI        | PII redaction, prompt injection scanning  |
"""

from .gdpr import ErasureAuditRecord, ErasureRequest, GDPRRAGPolicy
from .hipaa import HIPAAAccessScope, HIPAAAuditRecord, HIPAAContextPolicy, HIPAAPurpose
from .nist_ai_rmf import (
    AIRMFAuditRecord,
    AIRMFFunction,
    AIRMFRAGPolicy,
    AIRMFRetrievalRisk,
    AIRMFRiskLevel,
)
from .owasp_llm import (
    OWASPAuditRecord,
    OWASPLLMRisk,
    OWASPPromptInjectionScanner,
    OWASPSensitiveDisclosureFilter,
)

__all__ = [
    # GDPR
    "ErasureRequest",
    "ErasureAuditRecord",
    "GDPRRAGPolicy",
    # HIPAA
    "HIPAAAccessScope",
    "HIPAAAuditRecord",
    "HIPAAContextPolicy",
    "HIPAAPurpose",
    # NIST AI RMF
    "AIRMFRiskLevel",
    "AIRMFFunction",
    "AIRMFRetrievalRisk",
    "AIRMFAuditRecord",
    "AIRMFRAGPolicy",
    # OWASP LLM Top 10
    "OWASPLLMRisk",
    "OWASPAuditRecord",
    "OWASPSensitiveDisclosureFilter",
    "OWASPPromptInjectionScanner",
]
