"""
17_telecom_rag.py — FCC CPNI + TCPA + NPAC compliance for a
telecommunications customer service and operations knowledge base assistant.

Demonstrates defense-in-depth RAG retrieval for a telecommunications carrier
where three distinct regulatory compliance obligations apply simultaneously:

    Layer 1  — CPNI (47 CFR Part 64 / 47 U.S.C. § 222): Customer Proprietary
               Network Information includes call detail records, location data,
               network usage patterns, and account information derived from
               the provision of telecommunications service. CPNI may only be
               used for account servicing purposes unless the customer has
               affirmatively opted in to marketing use. CPNIFilter enforces
               authorized purpose and opt-in status before retrieval.

    Layer 2  — TCPA (47 U.S.C. § 227 / 47 CFR Part 64.1200): The Telephone
               Consumer Protection Act requires prior express written consent
               before using automated systems to contact customers for marketing
               purposes. TCPAFilter blocks retrieval of customer contact data
               (phone numbers, contact preferences) for marketing purposes when
               the customer has not provided documented TCPA consent.

    Layer 3  — NPAC/LNP Data Controls (47 CFR Part 52): Number Portability
               Administration Center routing data — porting status, interim
               number portability records, routing database entries — contains
               sensitive carrier network topology and inter-carrier financial
               settlement data. NPACFilter restricts this data to authorized
               carrier operations and porting team personnel.

Scenarios
---------

  A. Customer service agent queries account details for account servicing:
     CPNI permits (account_servicing purpose). TCPA permits (transactional).
     NPAC permits (non-porting data). Full account retrieval.

  B. Marketing agent queries usage patterns for upgrade campaign:
     CPNI blocks call detail records and location data (marketing purpose
     requires opt-in, customer has not opted in). Aggregate/non-CPNI product
     docs returned.

  C. Customer opted out of CPNI sharing entirely:
     CPNI filter blocks all CPNI-tagged documents regardless of purpose.
     Only public product information and non-account data returned.

  D. Carrier operations agent queries number porting status:
     NPAC filter permits porting data (authorized operations role). CPNI
     permits (non-customer-facing operational purpose). Full porting data
     returned.

No external dependencies required.

Run:
    python examples/17_telecom_rag.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------

class CPNICategory(str, Enum):
    """FCC CPNI categories under 47 CFR Part 64."""
    CALL_DETAIL_RECORDS = "CPNI//CDR"           # Call logs, duration, destination numbers
    LOCATION_DATA = "CPNI//LOCATION"            # Cell tower, GPS location derived from service
    NETWORK_USAGE = "CPNI//NETWORK_USAGE"       # Bandwidth, data usage patterns
    ACCOUNT_INFORMATION = "CPNI//ACCOUNT"       # Service plan, features, payment method
    AGGREGATE_ONLY = "CPNI//AGGREGATE"          # De-identified aggregate data — not individual CPNI
    NON_CPNI = "NON_CPNI"                       # Non-CPNI product/service information
    PUBLIC = "PUBLIC"                           # Public network information


class CPNIAuthorizedPurpose(str, Enum):
    """Authorized purposes for CPNI use under 47 CFR Part 64.2005."""
    ACCOUNT_SERVICING = "account_servicing"                    # Always permitted
    MARKETING_WIRELINE_SERVICES = "marketing_wireline_services"  # Permitted for existing customers (same service type)
    MARKETING_JOINT_VENTURE = "marketing_joint_venture"        # Requires opt-in
    MARKETING_THIRD_PARTY = "marketing_third_party"            # Requires opt-in
    NETWORK_OPERATIONS = "network_operations"                  # Internal operational use
    LAW_ENFORCEMENT = "law_enforcement"                        # Compelled disclosure


class NPACDataType(str, Enum):
    """NPAC/LNP data types (47 CFR Part 52)."""
    PORTING_STATUS = "NPAC//PORTING_STATUS"         # Number porting active/in-progress
    ROUTING_RECORD = "NPAC//ROUTING_RECORD"         # Interim number portability routing
    SPID_DATA = "NPAC//SPID_DATA"                   # Service Provider Identifier data
    SUBSCRIPTION_DATA = "NPAC//SUBSCRIPTION"        # Ported number subscriber data
    NON_NPAC = "NON_NPAC"


class AgentRole(str, Enum):
    """Telecom agent roles."""
    CUSTOMER_SERVICE = "customer_service"       # Consumer-facing service reps
    MARKETING = "marketing"                     # Marketing and upsell campaigns
    NETWORK_OPERATIONS = "network_ops"          # Network engineering and operations
    PORTING_TEAM = "porting_team"               # Local number portability team
    CARRIER_RELATIONS = "carrier_relations"     # Inter-carrier relations
    COMPLIANCE = "compliance"                   # Regulatory compliance


# ---------------------------------------------------------------------------
# Access context
# ---------------------------------------------------------------------------

@dataclass
class TelecomAccessContext:
    """Access boundary for a telecom customer service or operations session."""
    agent_id: str
    agent_role: AgentRole
    customer_account_id: str | None             # None for non-customer-specific queries
    authorized_purposes: frozenset[CPNIAuthorizedPurpose]
    customer_cpni_opt_out: bool = False         # Customer has opted out (47 CFR 64.2008)
    customer_tcpa_consent: bool = False         # Prior express written consent for marketing
    npac_authorized: bool = False               # Authorized for NPAC data access

    def may_access_cpni(self, category: CPNICategory, purpose: CPNIAuthorizedPurpose | None = None) -> bool:
        if category in (CPNICategory.NON_CPNI, CPNICategory.PUBLIC, CPNICategory.AGGREGATE_ONLY):
            return True
        if self.customer_cpni_opt_out:
            return False
        if purpose is None:
            return CPNIAuthorizedPurpose.ACCOUNT_SERVICING in self.authorized_purposes
        return purpose in self.authorized_purposes

    def may_access_for_marketing(self) -> bool:
        return self.customer_tcpa_consent and (
            CPNIAuthorizedPurpose.MARKETING_JOINT_VENTURE in self.authorized_purposes
            or CPNIAuthorizedPurpose.MARKETING_THIRD_PARTY in self.authorized_purposes
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class TelecomComplianceAuditRecord:
    """Per-query audit record for FCC CPNI/TCPA/NPAC compliance."""
    query_id: str
    agent_id: str
    agent_role: str
    customer_account_id: str | None
    total_candidates: int = 0
    cpni_blocked: list[str] = field(default_factory=list)
    tcpa_blocked: list[str] = field(default_factory=list)
    npac_blocked: list[str] = field(default_factory=list)
    documents_returned: list[str] = field(default_factory=list)
    applicable_regulations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.applicable_regulations = [
            "47 CFR Part 64 (FCC CPNI Rules)",
            "47 U.S.C. § 222 (CPNI Statute)",
            "47 U.S.C. § 227 / 47 CFR Part 64.1200 (TCPA)",
            "47 CFR Part 52 (NPAC/LNP Data Controls)",
        ]

    @property
    def total_blocked(self) -> int:
        blocked = set(self.cpni_blocked) | set(self.tcpa_blocked) | set(self.npac_blocked)
        return len(blocked)


# ---------------------------------------------------------------------------
# Layer 1 — CPNI Filter (47 CFR Part 64)
# ---------------------------------------------------------------------------

class CPNIFilter:
    """
    Enforces FCC Customer Proprietary Network Information access controls.

    Under 47 CFR Part 64.2005, CPNI may be used for:
    - Account servicing (always): billing, technical support, service changes
    - Marketing wireline services to existing customers: no opt-in required
    - Marketing joint ventures / third-party services: opt-in required

    If the customer has opted out (64.2008 opt-out mechanism), CPNI may
    only be used for account servicing (billing and technical support).
    Marketing use — even for same-type services — is blocked.
    """

    def __init__(self, default_purpose: CPNIAuthorizedPurpose = CPNIAuthorizedPurpose.ACCOUNT_SERVICING) -> None:
        self._default_purpose = default_purpose

    def filter(
        self,
        documents: list[dict],
        context: TelecomAccessContext,
        audit: TelecomComplianceAuditRecord,
    ) -> list[dict]:
        passed: list[dict] = []
        for doc in documents:
            cpni_cat_str = doc.get("cpni_category", CPNICategory.NON_CPNI.value)
            try:
                cpni_cat = CPNICategory(cpni_cat_str)
            except ValueError:
                cpni_cat = CPNICategory.NON_CPNI

            # Determine effective purpose for this agent role
            if context.agent_role in (AgentRole.MARKETING,):
                # Marketing agents use marketing purpose
                purpose = CPNIAuthorizedPurpose.MARKETING_THIRD_PARTY
            elif context.agent_role in (AgentRole.NETWORK_OPERATIONS, AgentRole.PORTING_TEAM):
                purpose = CPNIAuthorizedPurpose.NETWORK_OPERATIONS
            else:
                purpose = CPNIAuthorizedPurpose.ACCOUNT_SERVICING

            if context.may_access_cpni(cpni_cat, purpose):
                passed.append(doc)
            else:
                audit.cpni_blocked.append(doc["id"])

        return passed


# ---------------------------------------------------------------------------
# Layer 2 — TCPA Filter (47 U.S.C. § 227)
# ---------------------------------------------------------------------------

class TCPAFilter:
    """
    Enforces TCPA consent requirements for marketing contact data retrieval.

    Blocks retrieval of customer contact information (phone numbers, contact
    preferences, contact schedules) when the purpose is marketing and the
    customer has not provided prior express written consent (PEWC).

    Transactional contact data (for account servicing, fraud alerts, service
    notifications) is not subject to TCPA consent requirements.
    """

    _MARKETING_ROLES = frozenset({AgentRole.MARKETING})

    def filter(
        self,
        documents: list[dict],
        context: TelecomAccessContext,
        audit: TelecomComplianceAuditRecord,
    ) -> list[dict]:
        passed: list[dict] = []
        for doc in documents:
            is_marketing_contact = doc.get("tcpa_contact_data", False)

            if (
                is_marketing_contact
                and context.agent_role in self._MARKETING_ROLES
                and not context.customer_tcpa_consent
            ):
                audit.tcpa_blocked.append(doc["id"])
            else:
                passed.append(doc)

        return passed


# ---------------------------------------------------------------------------
# Layer 3 — NPAC/LNP Filter (47 CFR Part 52)
# ---------------------------------------------------------------------------

class NPACFilter:
    """
    Enforces access controls for Number Portability Administration Center data.

    NPAC data — porting status, interim number portability routing records,
    Service Provider Identifier (SPID) data — contains sensitive carrier
    network topology and inter-carrier settlement information. Access is
    restricted to authorized porting team, carrier relations, and network
    operations personnel.

    Customer-facing agents (customer service, marketing) may not access
    NPAC data — it contains no information useful for customer interactions
    and its exposure creates competitive intelligence risk between carriers.
    """

    _NPAC_AUTHORIZED_ROLES = frozenset({
        AgentRole.PORTING_TEAM,
        AgentRole.CARRIER_RELATIONS,
        AgentRole.NETWORK_OPERATIONS,
        AgentRole.COMPLIANCE,
    })

    def filter(
        self,
        documents: list[dict],
        context: TelecomAccessContext,
        audit: TelecomComplianceAuditRecord,
    ) -> list[dict]:
        passed: list[dict] = []
        for doc in documents:
            npac_type_str = doc.get("npac_type", NPACDataType.NON_NPAC.value)
            try:
                npac_type = NPACDataType(npac_type_str)
            except ValueError:
                npac_type = NPACDataType.NON_NPAC

            if npac_type == NPACDataType.NON_NPAC:
                passed.append(doc)
            elif context.agent_role in self._NPAC_AUTHORIZED_ROLES and context.npac_authorized:
                passed.append(doc)
            else:
                audit.npac_blocked.append(doc["id"])

        return passed


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

class TelecomRAGPipeline:
    """Three-layer defense-in-depth RAG pipeline for telecommunications operators."""

    def __init__(self) -> None:
        self._cpni = CPNIFilter()
        self._tcpa = TCPAFilter()
        self._npac = NPACFilter()

    def retrieve(
        self,
        query: str,
        candidates: list[dict],
        context: TelecomAccessContext,
    ) -> tuple[list[dict], TelecomComplianceAuditRecord]:
        audit = TelecomComplianceAuditRecord(
            query_id=str(uuid.uuid4()),
            agent_id=context.agent_id,
            agent_role=context.agent_role.value,
            customer_account_id=context.customer_account_id,
            total_candidates=len(candidates),
        )
        after_cpni = self._cpni.filter(candidates, context, audit)
        after_tcpa = self._tcpa.filter(after_cpni, context, audit)
        after_npac = self._npac.filter(after_tcpa, context, audit)
        audit.documents_returned = [doc["id"] for doc in after_npac]
        return after_npac, audit


# ---------------------------------------------------------------------------
# Document corpus
# ---------------------------------------------------------------------------

CORPUS: list[dict] = [
    # CPNI — Call detail records
    {
        "id": "doc-001", "title": "Customer Call History — Last 90 Days",
        "cpni_category": CPNICategory.CALL_DETAIL_RECORDS.value,
        "tcpa_contact_data": False, "npac_type": NPACDataType.NON_NPAC.value,
    },
    {
        "id": "doc-002", "title": "Customer Location Data — Cell Tower History",
        "cpni_category": CPNICategory.LOCATION_DATA.value,
        "tcpa_contact_data": False, "npac_type": NPACDataType.NON_NPAC.value,
    },
    {
        "id": "doc-003", "title": "Monthly Data Usage Report",
        "cpni_category": CPNICategory.NETWORK_USAGE.value,
        "tcpa_contact_data": False, "npac_type": NPACDataType.NON_NPAC.value,
    },
    {
        "id": "doc-004", "title": "Account Service Plan and Features",
        "cpni_category": CPNICategory.ACCOUNT_INFORMATION.value,
        "tcpa_contact_data": False, "npac_type": NPACDataType.NON_NPAC.value,
    },
    # TCPA — Marketing contact data
    {
        "id": "doc-005", "title": "Customer Contact Preferences and Marketing Opt-Ins",
        "cpni_category": CPNICategory.NON_CPNI.value,
        "tcpa_contact_data": True, "npac_type": NPACDataType.NON_NPAC.value,
    },
    {
        "id": "doc-006", "title": "Customer Mobile Numbers for Promotional Campaign",
        "cpni_category": CPNICategory.NON_CPNI.value,
        "tcpa_contact_data": True, "npac_type": NPACDataType.NON_NPAC.value,
    },
    # NPAC — Number portability data
    {
        "id": "doc-007", "title": "Number Porting Status — In-Progress Orders",
        "cpni_category": CPNICategory.NON_CPNI.value,
        "tcpa_contact_data": False, "npac_type": NPACDataType.PORTING_STATUS.value,
    },
    {
        "id": "doc-008", "title": "NPAC Routing Records — Interim Number Portability",
        "cpni_category": CPNICategory.NON_CPNI.value,
        "tcpa_contact_data": False, "npac_type": NPACDataType.ROUTING_RECORD.value,
    },
    # Non-CPNI, non-NPAC
    {
        "id": "doc-009", "title": "5G Service Plans and Pricing (Public)",
        "cpni_category": CPNICategory.PUBLIC.value,
        "tcpa_contact_data": False, "npac_type": NPACDataType.NON_NPAC.value,
    },
    {
        "id": "doc-010", "title": "Network Coverage Map — Public Information",
        "cpni_category": CPNICategory.PUBLIC.value,
        "tcpa_contact_data": False, "npac_type": NPACDataType.NON_NPAC.value,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_scenario(label: str, description: str, query: str) -> None:
    print(f"\n{'=' * 72}")
    print(f"Scenario {label}: {description}")
    print(f"Query: {query}")
    print("=" * 72)


def _print_result(docs: list[dict], audit: TelecomComplianceAuditRecord) -> None:
    print(f"Documents returned ({len(docs)}):")
    for d in docs:
        print(f"  + [{d['cpni_category']}] {d['title']}")
    if audit.cpni_blocked:
        print(f"CPNI blocked ({len(audit.cpni_blocked)}): {audit.cpni_blocked}")
    if audit.tcpa_blocked:
        print(f"TCPA blocked ({len(audit.tcpa_blocked)}): {audit.tcpa_blocked}")
    if audit.npac_blocked:
        print(f"NPAC blocked ({len(audit.npac_blocked)}): {audit.npac_blocked}")
    print(f"Total: {len(docs)} / {audit.total_candidates} candidates")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    pipeline = TelecomRAGPipeline()

    # ------------------------------------------------------------------
    # Scenario A: Customer service agent — account servicing purpose
    # CPNI: account_servicing purpose allowed. TCPA: non-marketing.
    # NPAC: customer service role not authorized. Full account data returned.
    # ------------------------------------------------------------------
    _print_scenario(
        "A",
        "Customer service agent (account_servicing purpose, no opt-out). "
        "All CPNI account/usage data returned. NPAC blocked (ops role required).",
        "Show me the customer's service plan, call history, and data usage.",
    )
    ctx_a = TelecomAccessContext(
        agent_id="csr-1001",
        agent_role=AgentRole.CUSTOMER_SERVICE,
        customer_account_id="acct-78234",
        authorized_purposes=frozenset({CPNIAuthorizedPurpose.ACCOUNT_SERVICING}),
        customer_cpni_opt_out=False,
        customer_tcpa_consent=False,
        npac_authorized=False,
    )
    docs_a, audit_a = pipeline.retrieve("service plan, call history, data usage", CORPUS, ctx_a)
    _print_result(docs_a, audit_a)

    # ------------------------------------------------------------------
    # Scenario B: Marketing agent — no CPNI opt-in, no TCPA consent
    # CPNI: marketing purpose blocks CDR, location, usage (opt-in required).
    # TCPA: no consent — marketing contact data blocked.
    # Only public product docs returned.
    # ------------------------------------------------------------------
    _print_scenario(
        "B",
        "Marketing agent (marketing_third_party purpose, customer not opted in, "
        "no TCPA consent). CPNI blocks CDR/location/usage. TCPA blocks contact data. "
        "Only public product docs returned.",
        "Find customers with high data usage for 5G upgrade campaign targeting.",
    )
    ctx_b = TelecomAccessContext(
        agent_id="mkt-2201",
        agent_role=AgentRole.MARKETING,
        customer_account_id="acct-78234",
        authorized_purposes=frozenset({CPNIAuthorizedPurpose.MARKETING_THIRD_PARTY}),
        customer_cpni_opt_out=False,  # Not opted out, but opt-in not given
        customer_tcpa_consent=False,
        npac_authorized=False,
    )
    docs_b, audit_b = pipeline.retrieve("high data usage customers for 5G campaign", CORPUS, ctx_b)
    _print_result(docs_b, audit_b)

    # ------------------------------------------------------------------
    # Scenario C: Customer opted out of CPNI sharing entirely
    # 47 CFR 64.2008: opt-out blocks all CPNI use except account servicing.
    # Account service agent still cannot retrieve CPNI for marketing queries.
    # ------------------------------------------------------------------
    _print_scenario(
        "C",
        "Customer opted out of CPNI (47 CFR 64.2008). CPNI filter blocks ALL "
        "CPNI-tagged documents regardless of agent purpose. Account plan (CPNI//ACCOUNT) "
        "also blocked. Only non-CPNI and public docs returned.",
        "Pull account details and usage history for customer review.",
    )
    ctx_c = TelecomAccessContext(
        agent_id="csr-1002",
        agent_role=AgentRole.CUSTOMER_SERVICE,
        customer_account_id="acct-99001",
        authorized_purposes=frozenset({CPNIAuthorizedPurpose.ACCOUNT_SERVICING}),
        customer_cpni_opt_out=True,  # Customer has opted out
        customer_tcpa_consent=False,
        npac_authorized=False,
    )
    docs_c, audit_c = pipeline.retrieve("account details and usage history", CORPUS, ctx_c)
    _print_result(docs_c, audit_c)

    # ------------------------------------------------------------------
    # Scenario D: Porting team agent — NPAC authorized
    # CPNI: network_operations purpose. TCPA: non-marketing.
    # NPAC: porting_team role + npac_authorized → porting/routing data returned.
    # ------------------------------------------------------------------
    _print_scenario(
        "D",
        "Carrier porting team agent (npac_authorized=True). CPNI passes for "
        "network_operations purpose. NPAC porting and routing data returned.",
        "Check porting status and routing records for number 555-0147.",
    )
    ctx_d = TelecomAccessContext(
        agent_id="port-3301",
        agent_role=AgentRole.PORTING_TEAM,
        customer_account_id=None,  # Porting queries are not customer-account-scoped
        authorized_purposes=frozenset({CPNIAuthorizedPurpose.NETWORK_OPERATIONS}),
        customer_cpni_opt_out=False,
        customer_tcpa_consent=False,
        npac_authorized=True,
    )
    docs_d, audit_d = pipeline.retrieve("porting status and routing records", CORPUS, ctx_d)
    _print_result(docs_d, audit_d)

    # Summary
    print(f"\n{'=' * 72}")
    print("COMPLIANCE LAYER SUMMARY")
    print("=" * 72)
    print(f"{'Scenario':<16} {'Returned':<12} {'CPNI blocked':<16} {'TCPA blocked':<15} {'NPAC blocked'}")
    print("-" * 72)
    for label, docs, audit in [
        ("A (CSR)", docs_a, audit_a),
        ("B (Marketing)", docs_b, audit_b),
        ("C (Opt-out)", docs_c, audit_c),
        ("D (Porting)", docs_d, audit_d),
    ]:
        print(
            f"{label:<16} {len(docs):<12} {len(audit.cpni_blocked):<16} "
            f"{len(audit.tcpa_blocked):<15} {len(audit.npac_blocked)}"
        )

    print("\nApplicable regulations:")
    for reg in audit_a.applicable_regulations:
        print(f"  - {reg}")

    print("\nDesign notes:")
    print("  - CPNI opt-out (47 CFR 64.2008) is customer-controlled and overrides")
    print("    all agent purpose claims except pure account servicing (billing fix).")
    print("  - TCPA consent is per-customer and per-contact-channel. PEWC for SMS")
    print("    does not imply PEWC for voice calls.")
    print("  - NPAC data is not customer data — it is inter-carrier routing data.")
    print("    Customer-facing agents never need it; exposure creates carrier")
    print("    competitive intelligence risk.")


if __name__ == "__main__":
    main()
