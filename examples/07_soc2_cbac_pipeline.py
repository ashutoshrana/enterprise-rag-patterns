"""
examples/07_soc2_cbac_pipeline.py — SOC 2 Type II CBAC for multi-tenant RAG.

Demonstrates how to use SOC2ContextPolicy to enforce:
  - CC6.1: tenant isolation (cross-tenant data never reaches LLM context)
  - C1.1/C1.2: confidentiality tier enforcement (RESTRICTED blocked for lower tiers)
  - CC6.6: role-based document access
  - CC7.2: structured access audit record for SIEM

Run this file directly — no external dependencies required:

    python examples/07_soc2_cbac_pipeline.py

Typical use case: SaaS platform where multiple customer organizations share
a vector store, and each support/analytics query must be scoped to the
requesting user's organization and role.

Architecture
------------
Layer 2 of the four-layer compliance model:

    Layer 1 output (identity-scoped docs)
         │
         ▼
    SOC2ContextPolicy.filter_retrieved_documents()
         │  ← CC6.1: tenant isolation
         │  ← C1.1:  confidentiality tier check
         │  ← CC6.6: role intersection check
         ▼
    authorized_docs  ──→  LLM context
         │
         ├──→  SOC2AuditRecord  ──→  SIEM (CC7.2)
"""

from __future__ import annotations

import json

from enterprise_rag_patterns.regulations.soc2 import (
    SOC2AccessContext,
    SOC2AuditRecord,
    SOC2ConfidentialityTier,
    SOC2ContextPolicy,
)

# ---------------------------------------------------------------------------
# Simulated multi-tenant knowledge base
# ---------------------------------------------------------------------------

# Imagine this is the result of a vector similarity search across a shared
# knowledge base. Without SOC 2 CBAC, all of these would reach the LLM.
RETRIEVED_DOCS = [
    # ✅ Authorized: correct tenant, confidential tier, analyst role present
    {
        "doc_id": "contract_001",
        "tenant_id": "org_acme",
        "confidentiality_tier": "confidential",
        "required_roles": ["analyst", "legal"],
        "content": "ACME Corp Q1 2026 vendor contract — renewal terms and pricing.",
    },
    # ✅ Authorized: internal tier, no role restriction
    {
        "doc_id": "runbook_003",
        "tenant_id": "org_acme",
        "confidentiality_tier": "internal",
        "content": "Standard operating procedure: incident escalation runbook v3.",
    },
    # ❌ Blocked (CC6.1): wrong tenant — cross-tenant data leak attempt
    {
        "doc_id": "contract_042",
        "tenant_id": "org_rival",
        "confidentiality_tier": "confidential",
        "content": "RIVAL Corp proprietary pricing model — must never reach ACME context.",
    },
    # ❌ Blocked (C1.1): confidentiality tier exceeds user's authorization
    {
        "doc_id": "security_cfg_007",
        "tenant_id": "org_acme",
        "confidentiality_tier": "restricted",
        "content": "Production TLS private key rotation schedule — restricted access only.",
    },
    # ❌ Blocked (CC6.6): user role (analyst) not in required_roles (admin only)
    {
        "doc_id": "admin_audit_001",
        "tenant_id": "org_acme",
        "confidentiality_tier": "confidential",
        "required_roles": ["admin", "security_officer"],
        "content": "User access audit log — admin-only document.",
    },
    # ✅ Authorized: public tier, no tenant restriction
    {
        "doc_id": "faq_001",
        "content": "General product FAQ — publicly available information.",
    },
]

# ---------------------------------------------------------------------------
# Build access context from verified session token
# ---------------------------------------------------------------------------

# In production: derive from OIDC token claims — NEVER from user input.
ctx = SOC2AccessContext(
    subject_id="user_alice_007",
    tenant_id="org_acme",
    roles=frozenset({"analyst", "viewer"}),
    max_confidentiality_tier=SOC2ConfidentialityTier.CONFIDENTIAL,
    purpose="customer_support_query",
)

# ---------------------------------------------------------------------------
# Apply policy with audit sink
# ---------------------------------------------------------------------------

audit_log: list[SOC2AuditRecord] = []

policy = SOC2ContextPolicy(
    access_context=ctx,
    audit_sink=audit_log.append,
    session_id="sess_soc2_20260413_001",
)

print("=" * 60)
print("SOC 2 TYPE II CBAC RAG PIPELINE EXAMPLE")
print("TSC Controls: CC6.1 · CC6.6 · C1.1 · CC7.2")
print("=" * 60)
print(f"\nSubject: {ctx.subject_id}")
print(f"Tenant:  {ctx.tenant_id}")
print(f"Roles:   {sorted(ctx.roles)}")
print(f"Max tier: {ctx.max_confidentiality_tier.name}")
print(f"\nRetrieved docs (pre-filter): {len(RETRIEVED_DOCS)}")

authorized_docs = policy.filter_retrieved_documents(RETRIEVED_DOCS)

print(f"\n--- FILTER RESULTS ---")
print(f"Authorized docs:  {len(authorized_docs)}")
print(f"Blocked docs:     {len(RETRIEVED_DOCS) - len(authorized_docs)}")

print(f"\n--- AUTHORIZED DOCS (LLM CONTEXT) ---")
for doc in authorized_docs:
    tier = doc.get("confidentiality_tier", "unclassified")
    print(f"  ✅  {doc['doc_id']} [{tier}]: {doc['content'][:55]}...")

print(f"\n--- BLOCKED DOCS ---")
auth_ids = {d["doc_id"] for d in authorized_docs}
for doc in RETRIEVED_DOCS:
    if doc["doc_id"] not in auth_ids:
        if doc.get("tenant_id") and doc.get("tenant_id") != ctx.tenant_id:
            reason = "CC6.1: tenant mismatch"
        elif doc.get("confidentiality_tier") == "restricted":
            reason = "C1.1: tier_exceeded"
        else:
            reason = "CC6.6: role_required"
        print(f"  ❌  {doc['doc_id']}: blocked ({reason})")

# ---------------------------------------------------------------------------
# CC7.2 Audit record
# ---------------------------------------------------------------------------

if audit_log:
    record = audit_log[0]
    parsed = json.loads(record.to_log_entry())
    print(f"\n--- CC7.2 AUDIT RECORD ---")
    for key, value in parsed.items():
        print(f"  {key}: {value}")
    print(f"  tamper_hash: {record.content_hash()[:32]}...")

# ---------------------------------------------------------------------------
# Demonstrate SOC2ContextPolicy.last_audit_record shortcut
# ---------------------------------------------------------------------------

last = policy.last_audit_record
if last:
    print(f"\n--- BLOCK REASON BREAKDOWN ---")
    for reason, count in sorted(last.block_reasons.items()):
        print(f"  {reason}: {count} document(s)")
    print(f"\nTSC controls applied: {sorted(last.tsc_controls_applied)}")
