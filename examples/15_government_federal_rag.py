"""
15_government_federal_rag.py — CUI handling + FedRAMP + NIST 800-53 compliance
for a US federal agency procurement knowledge base assistant.

Demonstrates defense-in-depth RAG retrieval for a federal agency environment
where three distinct compliance obligations apply simultaneously:

    Layer 1  — CUI (32 CFR Part 2002 / EO 13556): Documents tagged as Controlled
               Unclassified Information may only be retrieved by users with
               documented CUI authorization. CUIFilter enforces the CUI registry
               boundary before documents reach the LLM context window.

    Layer 2  — FedRAMP (NIST SP 800-37 / FedRAMP Moderate ATO): The knowledge
               base document store may contain documents sourced from cloud
               services. Only documents sourced from FedRAMP-authorized providers
               (with current ATO) may be returned. FedRAMPSourceFilter enforces
               source authorization.

    Layer 3  — NIST 800-53 Rev 5 AC-3 (Access Enforcement): Role-based access
               control enforced at the retrieval layer. Agency-defined information
               categories (CONTROLLED, SENSITIVE_BUT_UNCLASSIFIED, UNCLASSIFIED)
               are gated by the requesting user's agency_role.

Scenarios
---------

  A. Cleared contractor with CUI authorization queries solicitation docs:
     CUIFilter passes (CUI-authorized), FedRAMP source passes, AC-3 passes → ALLOW.

  B. Uncleared vendor queries the same document set:
     CUIFilter blocks CUI-tagged documents; FedRAMP and AC-3 pass for public docs.
     Result: CUI documents blocked, public/unclassified documents returned.

  C. Query spans CUI + public documents:
     CUIFilter returns only the public subset; CUI documents are excluded.
     Demonstrates partial retrieval — the pipeline does not fail but silently
     excludes unauthorized categories.

  D. Agency analyst queries non-FedRAMP document source:
     FedRAMPSourceFilter blocks documents from a cloud source without current ATO.
     Even if the user has CUI authorization, non-FedRAMP-sourced docs are blocked.

No external dependencies required.

Run:
    python examples/15_government_federal_rag.py
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class CUICategory(str, Enum):
    """
    CUI Registry categories (National Archives CUI Registry, 32 CFR Part 2002).

    The CUI Registry defines authorized categories and subcategories.
    This enumeration covers the categories most relevant to procurement contexts.
    """

    PROCUREMENT_AND_ACQUISITION = "CUI//PROC"      # Procurement-sensitive
    EXPORT_CONTROLLED = "CUI//EXPT"                # Export Administration Regulations
    LAW_ENFORCEMENT_SENSITIVE = "CUI//LES"         # Law enforcement-sensitive
    CRITICAL_INFRASTRUCTURE = "CUI//CIKR"          # Critical infrastructure
    PRIVACY = "CUI//PRVCY"                          # Personal privacy
    CONTROLLED_TECHNICAL = "CUI//CTI"              # Controlled technical information
    UNCLASSIFIED = "UNCLASSIFIED"                  # Not CUI
    PUBLIC = "PUBLIC"                               # Publicly releasable


class FedRAMPImpactLevel(str, Enum):
    """FedRAMP cloud service authorization impact levels."""

    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    LI_SAAS = "LI-SAAS"    # Low Impact SaaS
    NOT_AUTHORIZED = "NOT_AUTHORIZED"


class AgencyRole(str, Enum):
    """
    Agency roles for NIST 800-53 AC-3 access enforcement.

    Maps to the agency-defined role hierarchy for procurement systems.
    """

    CUI_AUTHORIZED_OFFICER = "cui_authorized_officer"      # Full CUI access
    CONTRACTING_OFFICER = "contracting_officer"             # Procurement authority
    CONTRACTOR_CUI_CLEARED = "contractor_cui_cleared"      # External with CUI auth
    CONTRACTOR_UNCLEARED = "contractor_uncleared"          # External without CUI auth
    PUBLIC_USER = "public_user"                             # Unauthenticated


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class CUIAccessContext:
    """
    Defines the CUI authorization scope for a retrieval session.

    Analogous to ``StudentIdentityScope`` (FERPA) and ``MatterScope`` (legal).
    Established at session initiation from the agency's identity management system.

    Attributes:
        user_id: The user's agency/contractor identity.
        agency_role: The user's role for AC-3 enforcement.
        authorized_cui_categories: CUI categories this user is authorized to access.
            An empty set means the user has NO CUI authorization.
        fedramp_boundary: Whether the request originates from within a FedRAMP
            authorized boundary (impacts source filtering).
    """

    user_id: str
    agency_role: AgencyRole
    authorized_cui_categories: frozenset[CUICategory] = field(
        default_factory=frozenset
    )
    fedramp_boundary: bool = False

    def may_access_cui(self, category: CUICategory) -> bool:
        """Return True if this context authorizes access to the given CUI category."""
        if category in (CUICategory.UNCLASSIFIED, CUICategory.PUBLIC):
            return True
        return category in self.authorized_cui_categories


@dataclass
class FederalComplianceAuditRecord:
    """
    Audit record for a federal compliance-gated retrieval operation.

    Federal agencies are required to maintain logs of CUI access under
    32 CFR Part 2002. NIST 800-53 AU-2 (Event Logging) and AU-9 (Protection
    of Audit Information) apply.
    """

    record_id: str = field(default_factory=lambda: str(uuid4()))
    user_id: str = ""
    agency_role: str = ""
    query_hash: str = ""
    documents_retrieved: int = 0
    cui_documents_blocked: int = 0
    fedramp_documents_blocked: int = 0
    cui_categories_encountered: list[str] = field(default_factory=list)
    non_fedramp_sources_blocked: list[str] = field(default_factory=list)
    nist_controls_applied: list[str] = field(default_factory=list)
    outcome: str = "ALLOW"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_log_entry(self) -> str:
        return (
            f"[FEDERAL_AUDIT] record_id={self.record_id} "
            f"user={self.user_id} "
            f"role={self.agency_role} "
            f"outcome={self.outcome} "
            f"retrieved={self.documents_retrieved} "
            f"cui_blocked={self.cui_documents_blocked} "
            f"fedramp_blocked={self.fedramp_documents_blocked} "
            f"controls={self.nist_controls_applied} "
            f"timestamp={self.timestamp.isoformat()}"
        )


# ---------------------------------------------------------------------------
# Filter classes
# ---------------------------------------------------------------------------


class CUIFilter:
    """
    32 CFR Part 2002 CUI access control filter.

    Inspects each retrieved document's ``cui_category`` field and blocks
    documents that are CUI unless the requesting user's ``CUIAccessContext``
    includes the corresponding category in ``authorized_cui_categories``.

    Documents without a ``cui_category`` field are treated as UNCLASSIFIED
    and passed through unconditionally.

    Args:
        context: The ``CUIAccessContext`` for this retrieval session.
        audit_sink: Optional callable for ``FederalComplianceAuditRecord`` emission.
    """

    def __init__(
        self,
        context: CUIAccessContext,
        audit_sink: Callable[[FederalComplianceAuditRecord], None] | None = None,
    ) -> None:
        self._context = context
        self._audit_sink = audit_sink

    def filter(
        self,
        documents: list[dict],
        cui_field: str = "cui_category",
    ) -> tuple[list[dict], FederalComplianceAuditRecord]:
        """
        Filter documents by CUI authorization.

        Returns:
            Tuple of (authorized_documents, audit_record).
        """
        authorized: list[dict] = []
        blocked_count = 0
        categories_seen: list[str] = []

        for doc in documents:
            raw_cat = doc.get(cui_field, CUICategory.UNCLASSIFIED.value)
            try:
                category = CUICategory(raw_cat)
            except ValueError:
                category = CUICategory.UNCLASSIFIED

            if category not in categories_seen:
                categories_seen.append(category.value)

            if self._context.may_access_cui(category):
                authorized.append(doc)
            else:
                blocked_count += 1

        record = FederalComplianceAuditRecord(
            user_id=self._context.user_id,
            agency_role=self._context.agency_role.value,
            documents_retrieved=len(authorized),
            cui_documents_blocked=blocked_count,
            cui_categories_encountered=categories_seen,
            nist_controls_applied=["NIST-800-53-AC-3"],
            outcome="ALLOW" if len(authorized) > 0 else "DENY",
        )
        if self._audit_sink:
            self._audit_sink(record)
        return authorized, record


class FedRAMPSourceFilter:
    """
    FedRAMP source authorization filter (NIST SP 800-37 / FedRAMP Program).

    Blocks retrieval of documents sourced from cloud providers that do not
    have a current FedRAMP Authorization to Operate (ATO) at the required
    impact level. This enforces the FedRAMP boundary requirement: federal
    workloads must use authorized cloud services.

    Args:
        required_impact_level: Minimum FedRAMP impact level required (default: MODERATE).
        authorized_sources: Set of cloud provider IDs with current FedRAMP ATO.
    """

    #: Cloud providers with current FedRAMP Moderate (or higher) ATO
    #: In production, this list is fetched from the FedRAMP marketplace API.
    DEFAULT_AUTHORIZED_PROVIDERS: frozenset[str] = frozenset(
        {
            "aws_govcloud",
            "azure_government",
            "google_cloud_government",
            "salesforce_government",
            "servicenow_federal",
            "agency_on_premises",
        }
    )

    def __init__(
        self,
        authorized_sources: frozenset[str] | None = None,
        required_impact_level: FedRAMPImpactLevel = FedRAMPImpactLevel.MODERATE,
    ) -> None:
        self._authorized = authorized_sources or self.DEFAULT_AUTHORIZED_PROVIDERS
        self._required_level = required_impact_level

    def filter(
        self,
        documents: list[dict],
        source_field: str = "cloud_source",
    ) -> tuple[list[dict], list[str]]:
        """
        Filter documents by FedRAMP source authorization.

        Returns:
            Tuple of (authorized_documents, list_of_blocked_sources).
        """
        authorized: list[dict] = []
        blocked_sources: list[str] = []

        for doc in documents:
            source = doc.get(source_field)
            # Documents without a source field are treated as on-premises (always authorized)
            if source is None or source in self._authorized:
                authorized.append(doc)
            else:
                if source not in blocked_sources:
                    blocked_sources.append(source)

        return authorized, blocked_sources


class NIST80053AC3Filter:
    """
    NIST 800-53 Rev 5 AC-3 (Access Enforcement) filter.

    Enforces agency-defined access rules based on the requesting user's
    ``AgencyRole``. Each information sensitivity level maps to the minimum
    role required to access it.

    Args:
        context: The ``CUIAccessContext`` containing the user's role.
    """

    #: Minimum role required to access each information level
    _ROLE_HIERARCHY: dict[AgencyRole, int] = {
        AgencyRole.PUBLIC_USER: 0,
        AgencyRole.CONTRACTOR_UNCLEARED: 1,
        AgencyRole.CONTRACTOR_CUI_CLEARED: 2,
        AgencyRole.CONTRACTING_OFFICER: 3,
        AgencyRole.CUI_AUTHORIZED_OFFICER: 4,
    }

    #: Information level → minimum required role level
    _LEVEL_REQUIREMENTS: dict[str, int] = {
        "PUBLIC": 0,
        "UNCLASSIFIED": 0,
        "SENSITIVE_BUT_UNCLASSIFIED": 2,
        "CONTROLLED": 3,
        "RESTRICTED": 4,
    }

    def __init__(self, context: CUIAccessContext) -> None:
        self._context = context
        self._user_level = self._ROLE_HIERARCHY.get(context.agency_role, 0)

    def filter(
        self,
        documents: list[dict],
        level_field: str = "sensitivity_level",
    ) -> tuple[list[dict], int]:
        """
        Filter documents by NIST 800-53 AC-3 access level.

        Returns:
            Tuple of (authorized_documents, ac3_blocked_count).
        """
        authorized: list[dict] = []
        blocked = 0

        for doc in documents:
            level = doc.get(level_field, "UNCLASSIFIED")
            required = self._LEVEL_REQUIREMENTS.get(level, 0)
            if self._user_level >= required:
                authorized.append(doc)
            else:
                blocked += 1

        return authorized, blocked


# ---------------------------------------------------------------------------
# Mock federal document store
# ---------------------------------------------------------------------------

MOCK_DOCUMENTS: list[dict] = [
    # CUI Procurement — solicitation cost estimate (contractor must be CUI-cleared)
    {
        "id": "doc_cui_proc_001",
        "title": "Contract Solicitation — Government Cost Estimate",
        "cui_category": CUICategory.PROCUREMENT_AND_ACQUISITION.value,
        "sensitivity_level": "CONTROLLED",
        "cloud_source": "agency_on_premises",
        "content": (
            "Independent Government Cost Estimate — Solicitation W81XWH-26-R-0012\n"
            "Estimated contract value: $8.2M — $11.4M\n"
            "Period of performance: 24 months base + 12-month option\n"
            "NAICS Code: 541715 — Research and Development\n"
            "CUI//PROC — Not for release to offerors prior to award"
        ),
        "source_system": "procurement_system",
    },
    # CUI Controlled Technical — technical specs
    {
        "id": "doc_cui_cti_001",
        "title": "Technical Requirements — Controlled Technical Information",
        "cui_category": CUICategory.CONTROLLED_TECHNICAL.value,
        "sensitivity_level": "CONTROLLED",
        "cloud_source": "aws_govcloud",
        "content": (
            "Technical Data Package — Contract Item 0001\n"
            "CUI//CTI — Export Controlled: EAR99\n"
            "Specification covers: propulsion system interface requirements,\n"
            "vibration tolerances, and thermal management parameters.\n"
            "Distribution: US Government and authorized contractors only"
        ),
        "source_system": "technical_library",
    },
    # FOUO — Sensitive but unclassified
    {
        "id": "doc_sbu_001",
        "title": "Source Selection Evaluation Factors",
        "cui_category": CUICategory.UNCLASSIFIED.value,
        "sensitivity_level": "SENSITIVE_BUT_UNCLASSIFIED",
        "cloud_source": "azure_government",
        "content": (
            "Source Selection Evaluation Criteria — Solicitation W81XWH-26-R-0012\n"
            "Technical Approach: 40 points\n"
            "Past Performance: 30 points\n"
            "Price/Cost: 30 points\n"
            "FOUO — For Official Use Only. Not for public release."
        ),
        "source_system": "source_selection_system",
    },
    # Public solicitation notice
    {
        "id": "doc_public_001",
        "title": "Public Solicitation Notice",
        "cui_category": CUICategory.PUBLIC.value,
        "sensitivity_level": "UNCLASSIFIED",
        "cloud_source": "sam_gov",       # SAM.gov is NOT in FedRAMP registry
        "content": (
            "SOURCES SOUGHT — W81XWH-26-R-0012\n"
            "Agency: US Army Medical Research and Development Command\n"
            "Posted: 2026-04-01 on SAM.gov\n"
            "This sources sought synopsis is issued for market research purposes.\n"
            "No solicitation exists at this time. Responses are voluntary."
        ),
        "source_system": "sam_gov",
    },
    # FedRAMP-unauthorized source
    {
        "id": "doc_non_fedramp_001",
        "title": "Market Research — Commercial Cloud Vendor Data",
        "cui_category": CUICategory.UNCLASSIFIED.value,
        "sensitivity_level": "UNCLASSIFIED",
        "cloud_source": "commercial_cloud_provider",   # NOT FedRAMP authorized
        "content": (
            "Commercial cloud vendor comparison — internal market research\n"
            "Vendor A: $0.023/GB-month, 99.95% SLA, no FedRAMP ATO\n"
            "Vendor B: $0.031/GB-month, 99.99% SLA, FedRAMP Moderate pending\n"
            "Note: This data was sourced from a non-FedRAMP-authorized provider."
        ),
        "source_system": "commercial_cloud_provider",
    },
]

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

audit_log: list[FederalComplianceAuditRecord] = []


def record_audit(record: FederalComplianceAuditRecord) -> None:
    audit_log.append(record)


# ---------------------------------------------------------------------------
# Query runner
# ---------------------------------------------------------------------------


def run_query(
    label: str,
    description: str,
    context: CUIAccessContext,
    query: str,
    docs: list[dict] | None = None,
) -> None:
    all_docs = docs if docs is not None else MOCK_DOCUMENTS
    query_hash = hashlib.sha256(query.encode()).hexdigest()[:12]

    print(f"\n  Label:       {label}")
    print(f"  User:        {context.user_id} [{context.agency_role.value}]")
    print(f"  CUI Auth:    {[c.value for c in context.authorized_cui_categories] or 'NONE'}")
    print(f"  Query:       {query}")
    print(f"  Scenario:    {description}")

    # Layer 1 — CUI filter (32 CFR Part 2002)
    cui_filter = CUIFilter(context=context, audit_sink=record_audit)
    cui_docs, audit_record = cui_filter.filter(all_docs)

    # Layer 2 — FedRAMP source filter
    fedramp_filter = FedRAMPSourceFilter()
    fedramp_docs, blocked_sources = fedramp_filter.filter(cui_docs)
    audit_record.fedramp_documents_blocked = len(cui_docs) - len(fedramp_docs)
    audit_record.non_fedramp_sources_blocked = blocked_sources
    if blocked_sources:
        audit_record.nist_controls_applied.append("FEDRAMP-MODERATE-ATO")

    # Layer 3 — NIST 800-53 AC-3
    ac3_filter = NIST80053AC3Filter(context=context)
    final_docs, ac3_blocked = ac3_filter.filter(fedramp_docs)
    if ac3_blocked > 0:
        audit_record.nist_controls_applied.append("NIST-800-53-AC-3-LEVEL")

    # Update audit record with final counts
    audit_record.documents_retrieved = len(final_docs)
    audit_record.outcome = "ALLOW" if final_docs else "DENY"

    # Print results
    if not final_docs:
        print(f"  Decision:    DENY — no authorized documents after all three layers")
    else:
        print(f"  Decision:    ALLOW")
        print(f"  Docs returned: {len(final_docs)}")
    if audit_record.cui_documents_blocked > 0:
        print(f"  CUI-blocked: {audit_record.cui_documents_blocked} (32 CFR 2002)")
    if audit_record.fedramp_documents_blocked > 0:
        print(f"  FedRAMP-blocked: {audit_record.fedramp_documents_blocked} (sources: {blocked_sources})")
    if ac3_blocked > 0:
        print(f"  AC-3 blocked: {ac3_blocked} (NIST 800-53 AC-3)")

    for doc in final_docs:
        cui = doc.get("cui_category", "UNCLASSIFIED")
        src = doc.get("cloud_source", "unknown")
        preview = doc["content"][:55].replace("\n", " ")
        print(f"    [{cui:20s}] src={src} | {preview}...")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 68)
    print("Government/Federal RAG — CUI + FedRAMP + NIST 800-53")
    print("  Agency     : US Army Medical Research and Development Command")
    print("  System     : Procurement Knowledge Base Assistant")
    print("  Layers     : CUI (32 CFR 2002) | FedRAMP Moderate | NIST 800-53 AC-3")
    print("=" * 68)

    # ------------------------------------------------------------------
    # Scenario A — Cleared contractor with CUI//PROC authorization
    # ------------------------------------------------------------------
    print("\n--- Scenario A: Cleared contractor queries solicitation docs ---")
    ctx_a = CUIAccessContext(
        user_id="contractor_john_smith",
        agency_role=AgencyRole.CONTRACTOR_CUI_CLEARED,
        authorized_cui_categories=frozenset(
            {CUICategory.PROCUREMENT_AND_ACQUISITION, CUICategory.CONTROLLED_TECHNICAL}
        ),
        fedramp_boundary=True,
    )
    run_query(
        label="Scenario A",
        description=(
            "CMMC Level 2 certified contractor with CUI//PROC+CTI authorization. "
            "CUI layer passes. FedRAMP blocks sam_gov/commercial sources. "
            "AC-3: CONTROLLED docs require level 3 (Contracting Officer); "
            "contractor is level 2 → CONTROLLED blocked, FOUO/SBU returned."
        ),
        context=ctx_a,
        query="What is the independent government cost estimate for W81XWH-26-R-0012?",
    )

    # ------------------------------------------------------------------
    # Scenario B — Uncleared vendor (no CUI authorization)
    # ------------------------------------------------------------------
    print("\n--- Scenario B: Uncleared vendor (no CUI authorization) ---")
    ctx_b = CUIAccessContext(
        user_id="vendor_abc_corp",
        agency_role=AgencyRole.CONTRACTOR_UNCLEARED,
        authorized_cui_categories=frozenset(),  # No CUI authorization
        fedramp_boundary=False,
    )
    run_query(
        label="Scenario B",
        description=(
            "Unregistered vendor with no CUI authorization. "
            "CUI//PROC and CUI//CTI documents blocked; public notice returned."
        ),
        context=ctx_b,
        query="What are the evaluation factors for the W81XWH-26-R-0012 solicitation?",
    )

    # ------------------------------------------------------------------
    # Scenario C — Contracting officer queries (partial CUI access)
    # ------------------------------------------------------------------
    print("\n--- Scenario C: Mixed CUI + public retrieval ---")
    ctx_c = CUIAccessContext(
        user_id="co_mary_jones",
        agency_role=AgencyRole.CONTRACTING_OFFICER,
        authorized_cui_categories=frozenset(
            {CUICategory.PROCUREMENT_AND_ACQUISITION}
        ),
        fedramp_boundary=True,
    )
    run_query(
        label="Scenario C",
        description=(
            "Contracting officer with CUI//PROC but NOT CUI//CTI authorization. "
            "Gets cost estimate + evaluation factors + public notice. "
            "Controlled Technical Information blocked (not authorized for CTI)."
        ),
        context=ctx_c,
        query="Summarize all documents related to solicitation W81XWH-26-R-0012.",
    )

    # ------------------------------------------------------------------
    # Scenario D — Non-FedRAMP source blocked even for cleared user
    # ------------------------------------------------------------------
    print("\n--- Scenario D: FedRAMP source filter blocks non-authorized provider ---")
    ctx_d = CUIAccessContext(
        user_id="analyst_tom_lee",
        agency_role=AgencyRole.CUI_AUTHORIZED_OFFICER,
        authorized_cui_categories=frozenset(CUICategory),  # All categories
        fedramp_boundary=True,
    )
    # Use only the non-FedRAMP sourced documents for this scenario
    non_fedramp_docs = [
        d for d in MOCK_DOCUMENTS
        if d.get("cloud_source") in ("commercial_cloud_provider", "sam_gov")
    ]
    run_query(
        label="Scenario D",
        description=(
            "Fully cleared CUI officer queries documents from non-FedRAMP providers. "
            "commercial_cloud_provider lacks FedRAMP ATO → blocked. "
            "sam_gov also not in FedRAMP registry → blocked."
        ),
        context=ctx_d,
        query="What commercial cloud pricing data do we have?",
        docs=non_fedramp_docs,
    )

    # ------------------------------------------------------------------
    # Audit summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 68)
    print("Federal Compliance Audit Summary")
    print("=" * 68)
    for rec in audit_log:
        print(f"  {rec.to_log_entry()}")
    total_retrieved = sum(r.documents_retrieved for r in audit_log)
    total_cui_blocked = sum(r.cui_documents_blocked for r in audit_log)
    total_fedramp_blocked = sum(r.fedramp_documents_blocked for r in audit_log)
    print(f"\n  Total retrieved     : {total_retrieved}")
    print(f"  Total CUI-blocked   : {total_cui_blocked} (32 CFR 2002)")
    print(f"  Total FedRAMP-blocked: {total_fedramp_blocked} (FedRAMP ATO)")
    print(f"  Total audit records : {len(audit_log)}")
    print("=" * 68)


if __name__ == "__main__":
    main()
