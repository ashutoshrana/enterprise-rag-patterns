"""
examples/08_nist_ai_rmf_assessment.py — NIST AI RMF 1.0 risk assessment for RAG.

Demonstrates how to use AIRMFRAGPolicy to perform MAP, MEASURE, and MANAGE
function assessments on retrieved documents, following NIST AI 100-1 (2023)
and the NIST AI 600-1 Generative AI Profile (2024).

Run this file directly — no external dependencies required:

    python examples/08_nist_ai_rmf_assessment.py

Architecture
------------
Layer 3 of the four-layer compliance model:

    authorized_docs (from Layer 1/2)
         │
         ▼
    AIRMFRAGPolicy.assess_retrieval()
         │  ← MAP: risk identification (PII exposure, confabulation)
         │  ← MEASURE: risk quantification (score 0.0–1.0 per risk)
         ▼
    AIRMFRetrievalRisk  ──→  risk-aware context
         │
         ├──→  AIRMFAuditRecord (MANAGE 1.3)  ──→  incident log
         ├──→  audit_sink  ──→  SIEM / governance dashboard
         └──→  (if CRITICAL) human escalation / circuit breaker

NIST AI 600-1 GenAI Profile risks addressed
--------------------------------------------
  GV-AI-001 — Data Privacy: PII leakage from retrieved context
  GV-AI-002 — Confabulation: Retrieval-grounded hallucination
  GV-AI-003 — Information Integrity: Retrieved document authenticity
  GV-AI-007 — Data Poisoning: Adversarial manipulation of knowledge base
"""

from __future__ import annotations

import json

from enterprise_rag_patterns.regulations.nist_ai_rmf import (
    AIRMFRAGPolicy,
    AIRMFRetrievalRisk,
    AIRMFRiskLevel,
)

# ---------------------------------------------------------------------------
# Build the AI RMF policy for this system
# ---------------------------------------------------------------------------

risk_log: list[AIRMFRetrievalRisk] = []

policy = AIRMFRAGPolicy(
    system_id="enrollment-advisor-v3",
    risk_level=AIRMFRiskLevel.HIGH,  # Categorise as HIGH because it handles student PII
    data_sources=["student_information_system", "financial_aid_database", "course_catalog"],
    audit_sink=risk_log.append,
)

print("=" * 65)
print("NIST AI RMF 1.0 RISK ASSESSMENT FOR RAG PIPELINES")
print("NIST AI 100-1 (2023) · AI 600-1 GenAI Profile (2024)")
print("=" * 65)
print(f"\nSystem: {policy.system_id}")
print(f"System risk level: {policy.risk_level}")
print(f"Data sources: {policy.data_sources}")

# ---------------------------------------------------------------------------
# Scenario 1: Low-risk query — general course info, high relevance scores
# ---------------------------------------------------------------------------

low_risk_docs = [
    {"doc_id": "course_001", "content": "CHEM 101: Introduction to Chemistry. 3 credits. Fall/Spring."},
    {"doc_id": "course_002", "content": "CHEM 201: Organic Chemistry. Prerequisites: CHEM 101."},
    {"doc_id": "catalog_faq", "content": "Course catalog is updated annually in June."},
]

risk1 = policy.assess_retrieval(
    query="What chemistry courses are available?",
    retrieved_docs=low_risk_docs,
    relevance_scores=[0.95, 0.92, 0.78],  # High relevance → low confabulation risk
)

print("\n--- Scenario 1: Low-risk query (general course catalog) ---")
print(f"  Risk level:          {risk1.risk_level.value}")
print(f"  Documents retrieved: {risk1.documents_retrieved}")
print(f"  Confabulation risk:  {risk1.confabulation_risk:.2f}")
print(f"  PII exposure risk:   {risk1.pii_exposure_risk:.2f}")
print(f"  RMF controls:        {len(risk1.relevant_rmf_controls)} controls applied")

# ---------------------------------------------------------------------------
# Scenario 2: Medium-risk query — contains PII-adjacent data
# ---------------------------------------------------------------------------

medium_risk_docs = [
    {"doc_id": "aid_pkg_001", "student_id": "stu_001", "content": "Financial aid package for student."},
    {"doc_id": "tuition_001", "content": "2026 tuition rates: $18,450/semester."},
    {"doc_id": "aid_faq_001", "content": "FAFSA deadline is March 1 each year."},
]

risk2 = policy.assess_retrieval(
    query="What financial aid is this student eligible for?",
    retrieved_docs=medium_risk_docs,
    relevance_scores=[0.88, 0.72, 0.65],
)

print("\n--- Scenario 2: Medium-risk query (financial aid + student PII) ---")
print(f"  Risk level:          {risk2.risk_level.value}")
print(f"  Documents retrieved: {risk2.documents_retrieved}")
print(f"  Confabulation risk:  {risk2.confabulation_risk:.2f}")
print(f"  PII exposure risk:   {risk2.pii_exposure_risk:.2f}")
print(f"  RMF controls:        {len(risk2.relevant_rmf_controls)} controls applied")

# ---------------------------------------------------------------------------
# Scenario 3: High-risk scenario — low relevance scores (confabulation risk)
# ---------------------------------------------------------------------------

low_relevance_docs = [
    {"doc_id": "unrelated_001", "content": "Parking permit renewal process."},
    {"doc_id": "unrelated_002", "content": "Campus shuttle schedule changes."},
]

risk3 = policy.assess_retrieval(
    query="Has this student completed all graduation requirements?",
    retrieved_docs=low_relevance_docs,
    relevance_scores=[0.45, 0.38],  # Low relevance → high confabulation risk
)

print("\n--- Scenario 3: High confabulation risk (low relevance scores) ---")
print(f"  Risk level:          {risk3.risk_level.value}")
print(f"  Documents retrieved: {risk3.documents_retrieved}")
print(f"  Confabulation risk:  {risk3.confabulation_risk:.2f}  ← GV-AI-002 flag")
print(f"  PII exposure risk:   {risk3.pii_exposure_risk:.2f}")
print(f"  RMF controls:        {len(risk3.relevant_rmf_controls)} controls applied")

# ---------------------------------------------------------------------------
# MANAGE 1.3: Record an incident triggered by the high-confabulation scenario
# ---------------------------------------------------------------------------

if float(risk3.confabulation_risk) > 0.6:
    incident = policy.record_incident(
        incident_type="retrieval_failure",
        severity="high",
        description=(
            f"Query returned low-relevance documents (scores: {[0.45, 0.38]}). "
            f"Confabulation risk: {risk3.confabulation_risk:.2f}. "
            "LLM context may produce unsupported graduation status claims."
        ),
        affected_users=1,
        remediation_applied=True,
    )
    print("\n--- MANAGE 1.3: Incident Record ---")
    parsed_incident = json.loads(incident.to_log_entry())
    for key, value in parsed_incident.items():
        print(f"  {key}: {value}")

# ---------------------------------------------------------------------------
# Risk trend summary across all scenarios
# ---------------------------------------------------------------------------

print("\n--- RISK ASSESSMENT SUMMARY (MAP + MEASURE) ---")
print(f"{'Query':<45} {'Risk':<10} {'Confab':<10} {'PII'}")
print("-" * 73)
scenarios = [
    ("Chemistry courses available?", risk1),
    ("Financial aid eligibility?", risk2),
    ("Graduation requirements met?", risk3),
]
for label, risk in scenarios:
    print(f"  {label:<43} {risk.risk_level.value:<10} {risk.confabulation_risk:<10.2f} {risk.pii_exposure_risk:.2f}")

print("\n--- MANAGE: Recommended Actions ---")
for label, risk in scenarios:
    if risk.risk_level in (AIRMFRiskLevel.HIGH, AIRMFRiskLevel.CRITICAL):
        print(f"  ⚠️  {label!r}: {risk.risk_level.value} — add retrieval fallback or human review gate")
    elif risk.risk_level == AIRMFRiskLevel.MEDIUM:
        print(f"  ℹ️  {label!r}: {risk.risk_level.value} — log for monitoring, no immediate action")
    else:
        print(f"  ✅  {label!r}: {risk.risk_level.value} — proceed normally")

print(f"\nAudit records emitted: {len(risk_log)}")
print("(In production: wire audit_sink to SIEM / governance dashboard)")
