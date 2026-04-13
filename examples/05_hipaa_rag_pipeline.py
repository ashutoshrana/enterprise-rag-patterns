"""
examples/05_hipaa_rag_pipeline.py — HIPAA-compliant RAG pipeline.

Demonstrates how to use HIPAAContextPolicy to enforce the minimum-necessary
standard (45 CFR § 164.502(b)) when retrieving ePHI from a clinical knowledge
base, and how to emit structured 45 CFR § 164.312(b) audit records.

Run this file directly — no external dependencies required:

    python examples/05_hipaa_rag_pipeline.py

Architecture
------------
This example illustrates Layer 1 (HIPAA identity scoping) and Layer 3 (audit)
of the four-layer defense-in-depth model.

    Retrieved docs (raw)
         │
         ▼
    HIPAAContextPolicy.filter_retrieved_documents()
         │  ← patient identity check (Layer 1)
         │  ← HIPAA purpose check     (Layer 1)
         │  ← PHI category check      (Layer 1)
         ▼
    safe_docs  ──→  LLM context
         │
         ├──→  HIPAAAuditRecord  ──→  SIEM / append-only log (Layer 3)
"""

from __future__ import annotations

import json

from enterprise_rag_patterns.regulations.hipaa import (
    HIPAAAccessScope,
    HIPAAAuditRecord,
    HIPAAContextPolicy,
    HIPAAPurpose,
)

# ---------------------------------------------------------------------------
# Simulated knowledge base — mix of authorized and unauthorized ePHI
# ---------------------------------------------------------------------------

RETRIEVED_DOCS = [
    # ✅ Authorized: correct patient, treatment purpose, authorized PHI category
    {
        "doc_id": "note_001",
        "patient_id": "PAT-0042",
        "data_purpose": "treatment",
        "phi_category": "clinical_notes",
        "content": "Patient reports persistent cough for 3 days. Prescribed amoxicillin.",
    },
    # ✅ Authorized: correct patient, treatment purpose, lab results authorized
    {
        "doc_id": "lab_007",
        "patient_id": "PAT-0042",
        "data_purpose": "treatment",
        "phi_category": "lab_results",
        "content": "CBC: WBC 11.2 (H), RBC 4.8, HGB 13.5. Mild leukocytosis.",
    },
    # ❌ Blocked: wrong patient (cross-patient data leak)
    {
        "doc_id": "note_099",
        "patient_id": "PAT-0099",
        "data_purpose": "treatment",
        "phi_category": "clinical_notes",
        "content": "Different patient's clinical note — must not reach LLM context.",
    },
    # ❌ Blocked: unauthorized HIPAA purpose (billing, not treatment)
    {
        "doc_id": "billing_003",
        "patient_id": "PAT-0042",
        "data_purpose": "payment",
        "phi_category": "billing_codes",
        "content": "ICD-10: J06.9. Claim submitted for office visit.",
    },
    # ❌ Blocked: unauthorized PHI category (mental_health not authorized for this scope)
    {
        "doc_id": "psych_002",
        "patient_id": "PAT-0042",
        "data_purpose": "treatment",
        "phi_category": "mental_health",
        "content": "Psychiatric evaluation notes — not authorized for this request scope.",
    },
    # ✅ Authorized: no patient_id field (non-patient reference doc — passes by default)
    {
        "doc_id": "protocol_001",
        "content": "Standard antibiotic dosing protocol for upper respiratory infections.",
    },
]

# ---------------------------------------------------------------------------
# Build the HIPAA access scope
# ---------------------------------------------------------------------------

# In production: derive from a verified session token / OIDC claims —
# NEVER from user-supplied input.
scope = HIPAAAccessScope(
    patient_id="PAT-0042",
    covered_entity_id="ACO-NORTHWEST",
    permitted_purposes=frozenset({HIPAAPurpose.TREATMENT}),
    role="attending_physician",
    # Only clinical notes and lab results are needed for this treatment request
    authorized_phi_categories=frozenset({"clinical_notes", "lab_results"}),
)

# ---------------------------------------------------------------------------
# Collect audit records (wire to SIEM / append-only log in production)
# ---------------------------------------------------------------------------

audit_log: list[HIPAAAuditRecord] = []


def audit_sink(record: HIPAAAuditRecord) -> None:
    audit_log.append(record)
    print(f"\n[HIPAA AUDIT] {record.regulation_citation}")
    parsed = json.loads(record.to_log_entry())
    for key, value in parsed.items():
        print(f"  {key}: {value}")
    print(f"  tamper_hash (SHA-256): {record.content_hash()[:16]}...")


# ---------------------------------------------------------------------------
# Apply the policy
# ---------------------------------------------------------------------------

policy = HIPAAContextPolicy(
    scope=scope,
    audit_sink=audit_sink,
    session_id="sess_tx_20260413_001",
)

print("=" * 60)
print("HIPAA-COMPLIANT RAG PIPELINE EXAMPLE")
print("Regulation: 45 CFR § 164.502(b) minimum-necessary standard")
print("=" * 60)
print(f"\nAccess scope: patient={scope.patient_id}, role={scope.role}")
print(f"Permitted purposes: {[p.value for p in scope.permitted_purposes]}")
print(f"Authorized PHI categories: {sorted(scope.authorized_phi_categories)}")
print(f"\nRetrieved docs (pre-filter): {len(RETRIEVED_DOCS)}")

safe_docs = policy.filter_retrieved_documents(RETRIEVED_DOCS)

print(f"\n--- FILTER RESULTS ---")
print(f"Docs passed minimum-necessary filter: {len(safe_docs)}")
print(f"Docs blocked: {len(RETRIEVED_DOCS) - len(safe_docs)}")

print(f"\n--- SAFE DOCS (LLM CONTEXT) ---")
for doc in safe_docs:
    print(f"  ✅  {doc['doc_id']}: {doc['content'][:60]}...")

print(f"\n--- BLOCKED DOCS (NEVER REACHED LLM) ---")
safe_ids = {d["doc_id"] for d in safe_docs}
for doc in RETRIEVED_DOCS:
    if doc["doc_id"] not in safe_ids:
        reason = "wrong patient" if doc.get("patient_id") != "PAT-0042" else (
            "unauthorized purpose" if doc.get("data_purpose") == "payment" else "unauthorized PHI category"
        )
        print(f"  ❌  {doc['doc_id']}: blocked ({reason})")

print(f"\n--- AUDIT TRAIL ---")
print(f"Audit records emitted: {len(audit_log)}")
print("(In production: write to SIEM / append-only log per § 164.312(b))")

# ---------------------------------------------------------------------------
# Demonstrate tamper-evidence
# ---------------------------------------------------------------------------
if audit_log:
    record = audit_log[0]
    h1 = record.content_hash()
    record.documents_retrieved = 99  # simulate tampering
    h2 = record.content_hash()
    print(f"\n--- TAMPER-EVIDENCE DEMONSTRATION ---")
    print(f"Original hash: {h1[:32]}...")
    print(f"After tampering: {h2[:32]}...")
    print(f"Hashes differ: {h1 != h2}  ← tampering detected")
