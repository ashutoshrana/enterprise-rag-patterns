"""
regulations — Cross-industry RAG compliance patterns.

Each sub-module provides the RAG-layer primitives for a specific regulation or
compliance framework.  These modules address the retrieval and context-assembly
layer — they are not general-purpose compliance engines.

Available modules
-----------------
Regulatory / statutory:
- ``ferpa``       — FERPA 34 CFR § 99 (in parent: ``enterprise_rag_patterns.compliance``).
- ``gdpr``        — GDPR Articles 17, 32: right-to-erasure, data subject rights.
- ``hipaa``       — HIPAA 45 CFR §§ 164.312(b), 164.502(b): ePHI minimum-necessary + audit.

IT audit / security frameworks:
- ``iso27001``    — ISO/IEC 27001:2022 ISMS Annex A CBAC: organization isolation,
  classification tier enforcement, role-based access (A.5.12, A.5.15, A.8.2, A.8.15).
- ``pci_dss``     — PCI DSS v4.0: merchant isolation, CHD category access control,
  PAN masking (Req 3.4, Req 7.2, Req 7.2.1, Req 10.2.1).
- ``soc2``        — SOC 2 Type II CBAC: tenant isolation, confidentiality tier enforcement,
  role-based access (TSC CC6.1, CC6.6, C1.1, CC7.2).

AI / technology governance:
- ``nist_ai_rmf`` — NIST AI RMF 1.0 + AI 600-1 GenAI Profile risk assessment.
- ``owasp_llm``   — OWASP LLM Top 10 (2025): LLM01 prompt injection, LLM02 PII disclosure.

Cross-industry applicability
-----------------------------

| Regulation / Framework | Category         | Primary Sector       | RAG-Specific Control                       |
|------------------------|------------------|----------------------|--------------------------------------------|
| FERPA                  | Regulatory       | Education            | Student identity scoping, audit logging    |
| GDPR                   | Regulatory       | EU / Global          | Erasure, data subject rights, lineage      |
| HIPAA                  | Regulatory       | Healthcare           | ePHI minimum-necessary, audit controls     |
| ISO/IEC 27001:2022     | IT Audit         | All sectors          | ISMS classification, org isolation, CBAC   |
| NIST AI RMF 1.0        | AI Governance    | All sectors          | Risk assessment, confabulation scoring     |
| OWASP LLM Top 10       | AI Security      | Software / AI        | PII redaction, prompt injection scanning   |
| PCI DSS v4.0           | IT Audit         | Payments / Finance   | Merchant isolation, CHD CBAC, PAN masking  |
| SOC 2 Type II          | IT Audit         | SaaS / Enterprise    | Tenant isolation, CBAC, CC7.2 audit log    |
"""

from .gdpr import ErasureAuditRecord, ErasureRequest, GDPRRAGPolicy
from .hipaa import HIPAAAccessScope, HIPAAAuditRecord, HIPAAContextPolicy, HIPAAPurpose
from .iso27001 import ISMSAccessContext, ISMSAuditRecord, ISMSClassification, ISMSContextPolicy
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
from .pci_dss import PCIAccessScope, PCIAuditRecord, PCIContextPolicy, PCIDataCategory
from .soc2 import (
    SOC2AccessContext,
    SOC2AuditRecord,
    SOC2ConfidentialityTier,
    SOC2ContextPolicy,
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
    # ISO/IEC 27001:2022
    "ISMSClassification",
    "ISMSAccessContext",
    "ISMSAuditRecord",
    "ISMSContextPolicy",
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
    # PCI DSS v4.0
    "PCIDataCategory",
    "PCIAccessScope",
    "PCIAuditRecord",
    "PCIContextPolicy",
    # SOC 2 Type II
    "SOC2ConfidentialityTier",
    "SOC2AccessContext",
    "SOC2AuditRecord",
    "SOC2ContextPolicy",
]
