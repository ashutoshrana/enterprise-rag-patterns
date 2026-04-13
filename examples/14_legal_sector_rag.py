"""
14_legal_sector_rag.py — Attorney-client privilege + ABA Model Rules compliance
for law firm matter research RAG.

Demonstrates a defense-in-depth RAG pipeline for a law firm matter research
assistant that must enforce the professional responsibility rules that govern
attorney-client privilege and confidentiality.

Three compliance layers applied in retrieval order:

    Layer 1  — ABA Model Rule 1.6 (Confidentiality): Documents tagged
               with a matter_id are accessible only to personnel on that
               matter's authorized team. MatterScopeFilter enforces this
               boundary before any document reaches the LLM context window.

    Layer 2  — ABA Model Rule 1.7 / 1.9 (Conflicts of Interest): When
               retrieved documents contain names or entities that are
               adverse parties to any of the requester's active matters,
               the retrieval is halted and a conflict flag is raised.
               ConflictChecker implements this boundary.

    Layer 3  — ABA Model Rule 1.15 (Safekeeping of Client Funds):
               Client financial records tagged to a specific matter_id
               are isolated from cross-matter financial queries. A billing
               partner may not use a single RAG query to retrieve financial
               summaries across multiple clients simultaneously.

Scenarios
---------

  A. Authorized associate on matter M-2024-0047 queries case strategy:
     MatterScopeFilter verifies team membership, ConflictChecker finds no
     adverse parties in results → full retrieval, ALLOW.

  B. Paralegal queries matter M-2024-0052 — not assigned to that matter:
     MatterScopeFilter blocks all privileged documents from the query
     response → zero privileged documents returned, DENY.

  C. Associate's query returns a document that mentions "Nexus Dynamics LLC"
     — an adverse party in a different active matter (M-2024-0081):
     ConflictChecker halts retrieval and raises a conflict flag →
     zero documents returned, CONFLICT.

  D. Billing partner queries cross-matter client funds summary:
     Rule 1.15 isolation blocks financial records from matter M-2024-0052
     (different client) from appearing in a query scoped to M-2024-0047 →
     only the requesting matter's financial records returned.

No external dependencies required.

Run:
    python examples/14_legal_sector_rag.py
"""

from __future__ import annotations

import hashlib
import sys
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PrivilegeTag(str, Enum):
    """
    Document-level privilege classification for legal matter documents.

    Mirrors the standard privilege taxonomy used in e-discovery and
    privilege log preparation (FRCP Rule 26(b)(5)).
    """

    ATTORNEY_CLIENT = "attorney_client"          # ABA Rule 1.6 — core confidentiality
    WORK_PRODUCT = "work_product"                # FRCP 26(b)(3) — prepared in anticipation
    COMMON_INTEREST = "common_interest"          # Co-defendant / joint privilege
    PUBLIC = "public"                            # Filed, published, or otherwise public
    CLIENT_FINANCIAL = "client_financial"        # ABA Rule 1.15 — trust account records


class ABARule(str, Enum):
    """ABA Model Rules of Professional Conduct invoked in compliance decisions."""

    RULE_1_6 = "ABA_Rule_1.6"    # Confidentiality of Information
    RULE_1_7 = "ABA_Rule_1.7"    # Conflict of Interest: Current Clients
    RULE_1_9 = "ABA_Rule_1.9"    # Duties to Former Clients
    RULE_1_15 = "ABA_Rule_1.15"  # Safekeeping Property


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class MatterScope:
    """
    Defines the authorized access boundary for a single matter research query.

    Analogous to ``StudentIdentityScope`` in FERPA-compliant RAG — the scope
    is established when the query session begins and gates all subsequent
    retrieval operations.

    Attributes:
        matter_id: The primary matter identifier (e.g. "M-2024-0047").
        requesting_user_id: The attorney, paralegal, or system making the request.
        authorized_matter_ids: The complete set of matter IDs the requester is
            authorized to access. Typically populated from the firm's DMS (document
            management system) role assignment.
        authorized_privilege_tags: Document privilege levels this user may retrieve.
        adverse_parties: Entity names that are adverse to the requesting matter.
            Populated from the firm's conflict-checking database.
    """

    matter_id: str
    requesting_user_id: str
    authorized_matter_ids: frozenset[str]
    authorized_privilege_tags: frozenset[PrivilegeTag] = field(
        default_factory=lambda: frozenset(
            {PrivilegeTag.PUBLIC, PrivilegeTag.ATTORNEY_CLIENT, PrivilegeTag.WORK_PRODUCT}
        )
    )
    adverse_parties: frozenset[str] = field(default_factory=frozenset)

    def is_authorized_for_matter(self, matter_id: str) -> bool:
        """Return True if the requester is on the authorized team for this matter."""
        return matter_id in self.authorized_matter_ids

    def may_access_privilege(self, tag: PrivilegeTag) -> bool:
        """Return True if this scope authorizes access to documents with this privilege tag."""
        return tag in self.authorized_privilege_tags


@dataclass
class LegalAuditRecord:
    """
    ABA Rule 1.6 compliance audit record for a matter retrieval operation.

    Law firms should maintain retrieval audit records for the duration of the
    client-attorney relationship and a reasonable period thereafter (typically
    7 years, mirroring document retention requirements in most jurisdictions).
    """

    record_id: str = field(default_factory=lambda: str(uuid4()))
    matter_id: str = ""
    requesting_user_id: str = ""
    query_hash: str = ""
    documents_retrieved: int = 0
    documents_blocked: int = 0
    documents_conflict_flagged: int = 0
    privilege_tags_blocked: list[str] = field(default_factory=list)
    conflict_parties_detected: list[str] = field(default_factory=list)
    aba_rules_invoked: list[str] = field(default_factory=list)
    outcome: str = "ALLOW"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_log_entry(self) -> str:
        return (
            f"[LEGAL_AUDIT] record_id={self.record_id} "
            f"matter={self.matter_id} "
            f"requester={self.requesting_user_id} "
            f"outcome={self.outcome} "
            f"retrieved={self.documents_retrieved} "
            f"blocked={self.documents_blocked} "
            f"conflict_flagged={self.documents_conflict_flagged} "
            f"rules={self.aba_rules_invoked} "
            f"timestamp={self.timestamp.isoformat()}"
        )


# ---------------------------------------------------------------------------
# Filter classes
# ---------------------------------------------------------------------------


class MatterScopeFilter:
    """
    ABA Rule 1.6 scope filter: restricts retrieval to authorized matter personnel.

    Documents tagged with a ``matter_id`` are accessible only if the requesting
    user's ``MatterScope.authorized_matter_ids`` includes that matter_id. Documents
    without a ``matter_id`` tag (e.g., public case law, regulatory guidance) are
    passed through unconditionally.

    Args:
        scope: The ``MatterScope`` establishing authorized access for this session.
        audit_sink: Optional callable receiving ``LegalAuditRecord`` on each filter call.
    """

    def __init__(
        self,
        scope: MatterScope,
        audit_sink: Callable[[LegalAuditRecord], None] | None = None,
    ) -> None:
        self._scope = scope
        self._audit_sink = audit_sink

    def filter(
        self,
        documents: list[dict],
        matter_id_field: str = "matter_id",
        privilege_field: str = "privilege_tag",
    ) -> tuple[list[dict], LegalAuditRecord]:
        """
        Filter documents by matter scope and privilege tag.

        Returns:
            Tuple of (authorized_docs, audit_record).
            ``authorized_docs`` is safe to pass to the LLM context window.
        """
        authorized: list[dict] = []
        blocked_tags: list[str] = []
        blocked_count = 0

        for doc in documents:
            doc_matter = doc.get(matter_id_field)
            raw_tag = doc.get(privilege_field, PrivilegeTag.PUBLIC.value)
            try:
                tag = PrivilegeTag(raw_tag)
            except ValueError:
                tag = PrivilegeTag.PUBLIC

            # Untagged or public documents pass through
            if doc_matter is None or tag == PrivilegeTag.PUBLIC:
                authorized.append(doc)
                continue

            # Check matter team membership (ABA Rule 1.6)
            if not self._scope.is_authorized_for_matter(doc_matter):
                blocked_count += 1
                blocked_tags.append(tag.value)
                continue

            # Check privilege level authorization
            if not self._scope.may_access_privilege(tag):
                blocked_count += 1
                blocked_tags.append(tag.value)
                continue

            authorized.append(doc)

        record = LegalAuditRecord(
            matter_id=self._scope.matter_id,
            requesting_user_id=self._scope.requesting_user_id,
            documents_retrieved=len(authorized),
            documents_blocked=blocked_count,
            privilege_tags_blocked=blocked_tags,
            aba_rules_invoked=[ABARule.RULE_1_6.value] if blocked_count > 0 else [],
            outcome="ALLOW" if len(authorized) > 0 else "DENY",
        )
        if self._audit_sink:
            self._audit_sink(record)
        return authorized, record


class ConflictChecker:
    """
    ABA Rule 1.7 / 1.9 conflict-of-interest scanner.

    Scans retrieved documents for entity names that are adverse parties to the
    requesting matter. If a conflict is detected, retrieval is halted — zero
    documents are returned and a conflict record is raised.

    In production, ``adverse_parties`` is populated from the firm's conflict-
    checking database (e.g., Intapp Conflicts, Aderant Handshake).

    Args:
        adverse_parties: Entity names that are adverse to the requesting matter.
        content_field: Document field to scan for adverse party mentions.
    """

    def __init__(
        self,
        adverse_parties: frozenset[str],
        content_field: str = "content",
    ) -> None:
        self._adverse_parties = {p.lower() for p in adverse_parties}
        self._content_field = content_field

    def check(
        self, documents: list[dict]
    ) -> tuple[list[dict], list[str]]:
        """
        Scan documents for adverse party mentions.

        Returns:
            (safe_docs, conflict_parties_found)
            If conflict_parties_found is non-empty, the caller should halt
            retrieval and raise a ConflictOfInterestError.
        """
        conflicts: list[str] = []
        for doc in documents:
            content = doc.get(self._content_field, "").lower()
            for party in self._adverse_parties:
                if party in content:
                    conflicts.append(party)
        if conflicts:
            return [], list(set(conflicts))
        return documents, []


class Rule1_15Filter:
    """
    ABA Rule 1.15 (Safekeeping of Client Property) cross-matter isolation filter.

    Ensures that financial records tagged ``PrivilegeTag.CLIENT_FINANCIAL`` are
    only returned for documents belonging to the same matter_id as the scope.
    Prevents a single RAG query from aggregating financial data across multiple
    clients — a confidentiality and fiduciary obligation under Rule 1.15.

    Args:
        scope: The ``MatterScope`` for the current session.
    """

    def __init__(self, scope: MatterScope) -> None:
        self._scope = scope

    def filter(
        self,
        documents: list[dict],
        matter_id_field: str = "matter_id",
        privilege_field: str = "privilege_tag",
    ) -> tuple[list[dict], int]:
        """
        Filter out CLIENT_FINANCIAL documents not belonging to the scope matter.

        Returns:
            (filtered_docs, cross_matter_blocked_count)
        """
        safe: list[dict] = []
        blocked = 0
        for doc in documents:
            raw_tag = doc.get(privilege_field, PrivilegeTag.PUBLIC.value)
            doc_matter = doc.get(matter_id_field)
            if (
                raw_tag == PrivilegeTag.CLIENT_FINANCIAL.value
                and doc_matter is not None
                and doc_matter != self._scope.matter_id
            ):
                blocked += 1
                continue
            safe.append(doc)
        return safe, blocked


# ---------------------------------------------------------------------------
# Mock document store
# ---------------------------------------------------------------------------

MOCK_DOCUMENTS: list[dict] = [
    # Matter M-2024-0047 — Northfield Technologies (patent litigation)
    {
        "id": "doc_strategy_001",
        "matter_id": "M-2024-0047",
        "privilege_tag": PrivilegeTag.ATTORNEY_CLIENT.value,
        "content": (
            "Northfield Technologies v. Precision Systems Corp — Case Strategy\n"
            "Infringement theory: Claim 12 of US10,234,567 reads on PSC Model X500.\n"
            "Key witness: Dr. Sarah Kim (PSC Chief Engineer).\n"
            "Estimated trial date: Q3 2026. Recommend Markman hearing by May 2026."
        ),
        "source": "matter_management_system",
        "client": "Northfield Technologies",
    },
    {
        "id": "doc_memo_001",
        "matter_id": "M-2024-0047",
        "privilege_tag": PrivilegeTag.WORK_PRODUCT.value,
        "content": (
            "WORK PRODUCT — Attorney Memorandum\n"
            "Invalidity analysis: US10,234,567 vs Smithson 2019 prior art.\n"
            "Conclusion: claims 1-11 likely invalid; claims 12-15 defensible.\n"
            "Prepared by: J. Chen, Esq."
        ),
        "source": "matter_management_system",
        "client": "Northfield Technologies",
    },
    {
        "id": "doc_financial_047",
        "matter_id": "M-2024-0047",
        "privilege_tag": PrivilegeTag.CLIENT_FINANCIAL.value,
        "content": (
            "Client Trust Account — Matter M-2024-0047\n"
            "Retainer received: $150,000 (2024-09-01)\n"
            "Fees billed to date: $87,430\n"
            "Trust balance: $62,570\n"
            "Next billing cycle: 2026-05-01"
        ),
        "source": "billing_system",
        "client": "Northfield Technologies",
    },
    # Matter M-2024-0052 — Westlake Manufacturing (regulatory compliance)
    {
        "id": "doc_memo_052",
        "matter_id": "M-2024-0052",
        "privilege_tag": PrivilegeTag.ATTORNEY_CLIENT.value,
        "content": (
            "Westlake Manufacturing — EPA Consent Decree\n"
            "Negotiated settlement for Clean Air Act violations.\n"
            "Compliance timeline: 18 months from execution.\n"
            "Penalty: $2.4M to be paid in quarterly installments."
        ),
        "source": "matter_management_system",
        "client": "Westlake Manufacturing",
    },
    {
        "id": "doc_financial_052",
        "matter_id": "M-2024-0052",
        "privilege_tag": PrivilegeTag.CLIENT_FINANCIAL.value,
        "content": (
            "Client Trust Account — Matter M-2024-0052\n"
            "Retainer received: $75,000 (2025-01-15)\n"
            "Fees billed: $43,200\n"
            "Trust balance: $31,800"
        ),
        "source": "billing_system",
        "client": "Westlake Manufacturing",
    },
    # Matter M-2024-0081 — Sovereign Capital (securities litigation)
    # Adverse party: Nexus Dynamics LLC
    {
        "id": "doc_adverse_001",
        "matter_id": "M-2024-0081",
        "privilege_tag": PrivilegeTag.ATTORNEY_CLIENT.value,
        "content": (
            "Sovereign Capital v. Nexus Dynamics LLC\n"
            "Securities fraud claim: misrepresentation in Series B offering docs.\n"
            "Adverse party: Nexus Dynamics LLC (CEO: Marcus Holloway)\n"
            "Relief sought: rescission + $18M damages"
        ),
        "source": "matter_management_system",
        "client": "Sovereign Capital",
    },
    # Public document — no matter scope restriction
    {
        "id": "doc_public_001",
        "matter_id": None,
        "privilege_tag": PrivilegeTag.PUBLIC.value,
        "content": (
            "35 U.S.C. § 112 — Specification\n"
            "The specification shall contain a written description of the invention "
            "and of the manner and process of making and using it, in such full, clear, "
            "concise, and exact terms as to enable any person skilled in the art..."
        ),
        "source": "usco_public_database",
    },
]

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

audit_log: list[LegalAuditRecord] = []


def record_audit(record: LegalAuditRecord) -> None:
    audit_log.append(record)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run_query(
    label: str,
    description: str,
    scope: MatterScope,
    query: str,
    all_docs: list[dict] | None = None,
) -> None:
    """Run a full compliance-gated retrieval and print results."""
    docs = all_docs if all_docs is not None else MOCK_DOCUMENTS
    query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]

    print(f"\n  Label:       {label}")
    print(f"  Requester:   {scope.requesting_user_id}")
    print(f"  Matter:      {scope.matter_id}")
    print(f"  Query:       {query}")
    print(f"  Scenario:    {description}")

    # Layer 1 — Matter scope filter (ABA Rule 1.6)
    scope_filter = MatterScopeFilter(scope=scope, audit_sink=record_audit)
    scoped_docs, scope_record = scope_filter.filter(docs)

    # Layer 2 — Conflict checker (ABA Rule 1.7 / 1.9)
    conflict_checker = ConflictChecker(adverse_parties=scope.adverse_parties)
    clean_docs, conflict_parties = conflict_checker.check(scoped_docs)

    if conflict_parties:
        print(f"  Decision:    CONFLICT — retrieval halted")
        print(f"  Conflicts:   {conflict_parties}")
        print(f"  Rule:        {ABARule.RULE_1_7.value} / {ABARule.RULE_1_9.value}")
        return

    # Layer 3 — Rule 1.15 cross-matter financial isolation
    rule_1_15 = Rule1_15Filter(scope=scope)
    final_docs, cross_matter_blocked = rule_1_15.filter(clean_docs)

    # Print results
    if not final_docs:
        print(f"  Decision:    DENY — no authorized documents")
        print(f"  Blocked by MatterScopeFilter: {scope_record.documents_blocked}")
    else:
        print(f"  Decision:    ALLOW")
        print(f"  Docs returned: {len(final_docs)}")
        if scope_record.documents_blocked > 0:
            print(f"  Privilege-blocked: {scope_record.documents_blocked} (Rule 1.6)")
        if cross_matter_blocked > 0:
            print(
                f"  Cross-matter financial blocked: {cross_matter_blocked} (Rule 1.15)"
            )
        for doc in final_docs:
            tag = doc.get("privilege_tag", "public")
            matter = doc.get("matter_id", "—")
            preview = doc["content"][:60].replace("\n", " ")
            print(f"    [{tag:20s}] matter={matter} | {preview}...")


def main() -> None:
    print("=" * 68)
    print("Legal Sector RAG — Attorney-Client Privilege + ABA Model Rules")
    print("  Firm       : Morrison & Chen LLP")
    print("  Rules      : ABA Rule 1.6 (Confidentiality)")
    print("               ABA Rule 1.7 / 1.9 (Conflicts of Interest)")
    print("               ABA Rule 1.15 (Safekeeping of Client Property)")
    print("=" * 68)

    # ---------------------------------------------------------------
    # Scenario A — Authorized associate on their own matter
    # ---------------------------------------------------------------
    print("\n--- Scenario A: Authorized associate queries own matter ---")
    scope_a = MatterScope(
        matter_id="M-2024-0047",
        requesting_user_id="jchen_associate",
        authorized_matter_ids=frozenset({"M-2024-0047"}),
        authorized_privilege_tags=frozenset(
            {PrivilegeTag.ATTORNEY_CLIENT, PrivilegeTag.WORK_PRODUCT, PrivilegeTag.PUBLIC}
        ),
        # No cross-matter adverse parties — Precision Systems Corp is the known
        # defendant in THIS matter, not an adverse party from a different matter.
        adverse_parties=frozenset(),
    )
    run_query(
        label="Scenario A",
        description=(
            "Associate J. Chen queries case strategy for M-2024-0047. "
            "Authorized team member; no cross-matter adverse parties → full retrieval."
        ),
        scope=scope_a,
        query="What is our invalidity theory for claims 12-15?",
    )

    # ---------------------------------------------------------------
    # Scenario B — Paralegal queries a matter they're not assigned to
    # ---------------------------------------------------------------
    print("\n--- Scenario B: Paralegal queries unauthorized matter ---")
    scope_b = MatterScope(
        matter_id="M-2024-0052",
        requesting_user_id="paralegal_rodriguez",
        authorized_matter_ids=frozenset({"M-2024-0047"}),  # NOT authorized for 052
        authorized_privilege_tags=frozenset(
            {PrivilegeTag.ATTORNEY_CLIENT, PrivilegeTag.WORK_PRODUCT, PrivilegeTag.PUBLIC}
        ),
        adverse_parties=frozenset(),
    )
    run_query(
        label="Scenario B",
        description=(
            "Paralegal Rodriguez queries M-2024-0052 (EPA consent decree). "
            "Rodriguez is only on M-2024-0047 — Rule 1.6 blocks all matter-tagged docs."
        ),
        scope=scope_b,
        query="What is the EPA compliance timeline for Westlake?",
    )

    # ---------------------------------------------------------------
    # Scenario C — Query returns document mentioning adverse party
    # ---------------------------------------------------------------
    print("\n--- Scenario C: Adverse party conflict detected ---")
    scope_c = MatterScope(
        matter_id="M-2024-0081",
        requesting_user_id="mwilson_partner",
        authorized_matter_ids=frozenset({"M-2024-0081", "M-2024-0047"}),
        authorized_privilege_tags=frozenset(
            {PrivilegeTag.ATTORNEY_CLIENT, PrivilegeTag.WORK_PRODUCT, PrivilegeTag.PUBLIC}
        ),
        # Nexus Dynamics LLC is adverse in M-2024-0081
        adverse_parties=frozenset({"nexus dynamics llc", "marcus holloway"}),
    )
    run_query(
        label="Scenario C",
        description=(
            "Partner M. Wilson queries M-2024-0081. Results include a document "
            "mentioning 'Nexus Dynamics LLC' — an adverse party. "
            "ConflictChecker halts retrieval (Rule 1.7)."
        ),
        scope=scope_c,
        query="What is the securities fraud exposure for the defendant?",
    )

    # ---------------------------------------------------------------
    # Scenario D — Billing partner cross-matter financial isolation
    # ---------------------------------------------------------------
    print("\n--- Scenario D: Cross-matter client financial isolation ---")
    scope_d = MatterScope(
        matter_id="M-2024-0047",
        requesting_user_id="kmorrison_billing_partner",
        # Partner is authorized on both matters — but Rule 1.15 isolates financials
        authorized_matter_ids=frozenset({"M-2024-0047", "M-2024-0052"}),
        authorized_privilege_tags=frozenset(
            {
                PrivilegeTag.ATTORNEY_CLIENT,
                PrivilegeTag.WORK_PRODUCT,
                PrivilegeTag.CLIENT_FINANCIAL,
                PrivilegeTag.PUBLIC,
            }
        ),
        adverse_parties=frozenset(),
    )
    run_query(
        label="Scenario D",
        description=(
            "Billing partner queries M-2024-0047 financial summary. "
            "Partner is authorized on both matters but Rule 1.15 blocks "
            "M-2024-0052 financial records from appearing in a M-2024-0047 query."
        ),
        scope=scope_d,
        query="What is the trust account balance for the Northfield matter?",
    )

    # ---------------------------------------------------------------
    # Audit summary
    # ---------------------------------------------------------------
    print("\n" + "=" * 68)
    print("Compliance Audit Summary")
    print("=" * 68)
    for rec in audit_log:
        print(f"  {rec.to_log_entry()}")

    total_retrieved = sum(r.documents_retrieved for r in audit_log)
    total_blocked = sum(r.documents_blocked for r in audit_log)
    print(f"\n  Total retrieved across all scenarios : {total_retrieved}")
    print(f"  Total privilege-blocked              : {total_blocked}")
    print(f"  Total audit records                  : {len(audit_log)}")
    print("=" * 68)


if __name__ == "__main__":
    main()
