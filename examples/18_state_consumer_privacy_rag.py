"""
18_state_consumer_privacy_rag.py — Multi-state US consumer privacy law compliance
for a retail / e-commerce personalization and customer support knowledge base.

Demonstrates defense-in-depth RAG retrieval where the four leading US state
consumer privacy statutes each impose independent consent and opt-out obligations,
and where users residing in multiple regulated states are subject to the
most-restrictive combination of applicable laws.

    Layer 1  — CCPA/CPRA (Cal. Civ. Code §§ 1798.100–1798.199.100):
               California Consumer Privacy Act (2020) / California Privacy Rights
               Act (2023). Consumers have the right to opt out of the sale or
               sharing of their personal information. CPRA elevates sensitive
               personal information (SPI) to a separate category requiring
               explicit opt-in or a "limit use" instruction. Minors under 16
               require affirmative opt-in for sale/sharing.

    Layer 2  — VCDPA (Va. Code §§ 59.1-571 to 59.1-585, eff. Jan 2023):
               Virginia Consumer Data Protection Act. Processing of sensitive data
               (health, racial/ethnic origin, sexual orientation, citizenship,
               biometric, children's data, precise geolocation) requires consumer
               consent. Opt-out right covers targeted advertising and profiling.

    Layer 3  — CPA (Colo. Rev. Stat. §§ 6-1-1301 to 6-1-1313, eff. July 2023):
               Colorado Privacy Act. Universal opt-out mechanism (GPC signal)
               must be honored. Sensitive data processing requires consent.
               Profiling with legal/significant effects requires opt-out right.

    Layer 4  — CTDPA (Conn. P.A. 22-15, eff. July 2023):
               Connecticut Data Privacy Act. Closely mirrors VCDPA but adds
               specific protections for children (under 18) and requires
               recognition of universal opt-out signals from January 2025.

Scenarios
---------

  A. California resident — CPRA opt-out of sharing; SPI (geolocation) requested:
     Both the sale/sharing opt-out and the SPI "limit use" instruction block
     personalization documents. Only transactional/support documents returned.

  B. Virginia resident — no sensitive data consent on file; health data requested:
     VCDPA §59.1-578 requires consent for sensitive data processing. Health-tagged
     documents blocked. Non-sensitive purchase history and product docs returned.

  C. Colorado resident with GPC universal opt-out signal:
     CPA §6-1-1306(5) mandates GPC recognition. Targeted advertising and
     behavioral profiling documents blocked. Non-profiling product docs returned.

  D. Multi-state user (California + Virginia resident, dual-state):
     Most-restrictive-jurisdiction logic applies. California CPRA share opt-out
     AND Virginia consent requirement both enforced. Only public / transactional
     data returned.

No external dependencies required.

Run:
    python examples/18_state_consumer_privacy_rag.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------

class ConsumerPrivacyState(str, Enum):
    """US states with comprehensive consumer privacy statutes."""
    CALIFORNIA = "CA"    # CCPA/CPRA
    VIRGINIA = "VA"      # VCDPA
    COLORADO = "CO"      # CPA
    CONNECTICUT = "CT"   # CTDPA


class SensitivePICategory(str, Enum):
    """
    Sensitive personal information categories that receive heightened protection
    under at least one of the four covered state privacy laws.
    """
    PRECISE_GEOLOCATION = "SPI//GEOLOCATION"        # CCPA/CPRA, VCDPA, CPA, CTDPA
    HEALTH_MEDICAL = "SPI//HEALTH"                  # All four states
    RACIAL_ETHNIC_ORIGIN = "SPI//RACE_ETHNICITY"    # All four states
    SEXUAL_ORIENTATION = "SPI//SEXUAL_ORIENTATION"  # All four states
    CITIZENSHIP_IMMIGRATION = "SPI//CITIZENSHIP"    # All four states
    BIOMETRIC = "SPI//BIOMETRIC"                    # All four states
    FINANCIAL_ACCOUNT = "SPI//FINANCIAL"            # CCPA/CPRA; sensitive under others
    SSN_GOVERNMENT_ID = "SPI//GOVT_ID"              # CCPA/CPRA
    CHILDREN_DATA = "SPI//CHILDREN"                 # All four states; strictest limits
    PERSONAL_COMM_CONTENT = "SPI//COMM_CONTENT"     # CCPA/CPRA (messages, emails)
    NON_SENSITIVE = "NON_SPI"                       # Standard PI, not sensitive
    PUBLIC = "PUBLIC"                               # Publicly available; no restrictions


class DataProcessingPurpose(str, Enum):
    """Purposes for which consumer PI is being processed/retrieved."""
    ACCOUNT_SERVICING = "ACCOUNT_SERVICING"            # Fulfilling the service contract
    CUSTOMER_SUPPORT = "CUSTOMER_SUPPORT"              # Resolving service requests
    ORDER_FULFILLMENT = "ORDER_FULFILLMENT"            # Processing and shipping orders
    TARGETED_ADVERTISING = "TARGETED_ADVERTISING"     # Behavioral/interest-based ads
    PERSONALIZATION = "PERSONALIZATION"               # Recommendations based on history
    PROFILING = "PROFILING"                           # Building consumer profiles
    ANALYTICS = "ANALYTICS"                           # Aggregate behavioral analysis
    MARKETING_DIRECT = "MARKETING_DIRECT"             # First-party direct marketing
    THIRD_PARTY_SALE = "THIRD_PARTY_SALE"             # Selling PI to third parties
    SHARING_CROSS_CONTEXT = "SHARING_CROSS_CONTEXT"   # Cross-context behavioral advertising


# ---------------------------------------------------------------------------
# Access context
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConsumerPrivacyContext:
    """
    Privacy rights state for a specific consumer interaction.

    Attributes
    ----------
    resident_states:
        The US states whose privacy laws apply to this consumer. A consumer
        may be a resident of multiple states (e.g. recently relocated). The
        most restrictive combination of applicable laws is enforced.
    requested_purpose:
        The processing purpose for which retrieval is requested.
    consumer_opted_out_of_sale:
        Consumer has exercised CCPA/CPA/VCDPA/CTDPA right to opt out of
        sale of their personal information.
    consumer_opted_out_of_sharing:
        Consumer has exercised CPRA right to opt out of sharing of PI for
        cross-context behavioral advertising.
    consumer_opted_out_of_targeted_ads:
        Consumer has exercised right to opt out of targeted advertising
        (VCDPA §59.1-577, CPA §6-1-1306, CTDPA §6).
    consumer_gpc_signal:
        Consumer's browser/app transmitted a Global Privacy Control signal,
        which Colorado CPA (§6-1-1306(5)) and CTDPA (from Jan 2025) require
        to be honored as a universal opt-out of sale/targeted ads.
    sensitive_pi_consent:
        Mapping from SensitivePICategory → True if the consumer has given
        explicit consent for that sensitive category. Absence of a category
        entry means no consent (default deny for sensitive data).
    consumer_age_minor:
        True if the consumer is under 16 (CPRA) or under 18 (CTDPA).
        Minors require affirmative opt-in for any sale/sharing.
    spi_limit_use_instruction:
        Set of sensitive PI categories for which the consumer has instructed
        the business to limit use to necessary purposes only (CPRA).
    consumer_id:
        Pseudonymous identifier for audit purposes.
    """
    resident_states: frozenset[ConsumerPrivacyState]
    requested_purpose: DataProcessingPurpose
    consumer_opted_out_of_sale: bool = False
    consumer_opted_out_of_sharing: bool = False
    consumer_opted_out_of_targeted_ads: bool = False
    consumer_gpc_signal: bool = False
    sensitive_pi_consent: dict[SensitivePICategory, bool] = field(
        default_factory=dict
    )
    consumer_age_minor: bool = False
    spi_limit_use_instruction: frozenset[SensitivePICategory] = field(
        default_factory=frozenset
    )
    consumer_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# Document metadata
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Document:
    """A knowledge base document with privacy classification metadata."""
    doc_id: str
    content: str
    pi_classification: SensitivePICategory
    requires_sale_opt_in: bool = False        # Can only be used if consumer has NOT opted out of sale
    requires_sharing_opt_in: bool = False     # Can only be used if consumer has NOT opted out of sharing
    is_targeted_advertising: bool = False     # Requires opt-out check
    is_behavioral_profiling: bool = False     # Requires opt-out check (CPA)
    is_third_party_sale: bool = False         # Blocked by sale opt-out across all states
    data_controller_state: Optional[str] = None  # Where data was collected


# ---------------------------------------------------------------------------
# Layer 1 — CCPA/CPRA Filter
# ---------------------------------------------------------------------------

class CCPACPRAFilter:
    """
    Enforces California Consumer Privacy Act / California Privacy Rights Act
    (Cal. Civ. Code §§ 1798.100–1798.199.100).

    Key obligations enforced:
    - Right to opt out of sale (§1798.120) and sharing (§1798.135) of PI
    - SPI "limit use" instruction (CPRA §1798.121)
    - Minor consent requirements (§1798.120(c): under 16; under 13 different)
    - Cross-context behavioral advertising = "sharing" under CPRA
    """

    # Purposes that constitute "sale" or "sharing" under CPRA
    _SALE_SHARING_PURPOSES: frozenset[DataProcessingPurpose] = frozenset({
        DataProcessingPurpose.THIRD_PARTY_SALE,
        DataProcessingPurpose.SHARING_CROSS_CONTEXT,
        DataProcessingPurpose.TARGETED_ADVERTISING,
    })

    # SPI categories that require separate "limit use" consent under CPRA
    _CPRA_SPI_CATEGORIES: frozenset[SensitivePICategory] = frozenset({
        SensitivePICategory.PRECISE_GEOLOCATION,
        SensitivePICategory.HEALTH_MEDICAL,
        SensitivePICategory.RACIAL_ETHNIC_ORIGIN,
        SensitivePICategory.SEXUAL_ORIENTATION,
        SensitivePICategory.CITIZENSHIP_IMMIGRATION,
        SensitivePICategory.BIOMETRIC,
        SensitivePICategory.FINANCIAL_ACCOUNT,
        SensitivePICategory.SSN_GOVERNMENT_ID,
        SensitivePICategory.CHILDREN_DATA,
        SensitivePICategory.PERSONAL_COMM_CONTENT,
    })

    def filter(
        self,
        documents: list[Document],
        ctx: ConsumerPrivacyContext,
    ) -> tuple[list[Document], list[str]]:
        """Return (permitted_docs, blocked_reasons)."""
        if ConsumerPrivacyState.CALIFORNIA not in ctx.resident_states:
            return documents, []

        permitted: list[Document] = []
        blocked_reasons: list[str] = []
        is_sale_sharing_purpose = ctx.requested_purpose in self._SALE_SHARING_PURPOSES

        for doc in documents:
            reason = self._evaluate(doc, ctx, is_sale_sharing_purpose)
            if reason:
                blocked_reasons.append(f"CCPA/CPRA blocked {doc.doc_id}: {reason}")
            else:
                permitted.append(doc)

        return permitted, blocked_reasons

    def _evaluate(
        self,
        doc: Document,
        ctx: ConsumerPrivacyContext,
        is_sale_sharing_purpose: bool,
    ) -> str | None:
        """Return a block reason string, or None if permitted."""
        # Minor opt-in required for sale/sharing
        if ctx.consumer_age_minor and (doc.requires_sale_opt_in or is_sale_sharing_purpose):
            return "minor under 16 requires affirmative opt-in for sale/sharing (§1798.120(c))"

        # Sale opt-out blocks documents involved in third-party sale
        if ctx.consumer_opted_out_of_sale and doc.is_third_party_sale:
            return "consumer exercised right to opt out of sale (§1798.120)"

        # Sharing opt-out blocks cross-context behavioral advertising
        if ctx.consumer_opted_out_of_sharing and (
            doc.requires_sharing_opt_in or doc.is_targeted_advertising
        ):
            return "consumer exercised right to opt out of sharing (§1798.135)"

        # SPI "limit use" instruction blocks sensitive PI for non-essential purposes
        if doc.pi_classification in self._CPRA_SPI_CATEGORIES:
            if doc.pi_classification in ctx.spi_limit_use_instruction:
                if ctx.requested_purpose not in {
                    DataProcessingPurpose.ACCOUNT_SERVICING,
                    DataProcessingPurpose.CUSTOMER_SUPPORT,
                    DataProcessingPurpose.ORDER_FULFILLMENT,
                }:
                    return (
                        f"SPI limit-use instruction active for "
                        f"{doc.pi_classification.value} (§1798.121)"
                    )

        return None


# ---------------------------------------------------------------------------
# Layer 2 — VCDPA Filter
# ---------------------------------------------------------------------------

class VCDPAFilter:
    """
    Enforces Virginia Consumer Data Protection Act
    (Va. Code §§ 59.1-571 to 59.1-585).

    Key obligations enforced:
    - Consent required to process sensitive data (§59.1-578)
    - Right to opt out of targeted advertising (§59.1-577(A)(5))
    - Right to opt out of profiling with legal/significant effects (§59.1-577(A)(4))
    """

    # Sensitive data categories under VCDPA §59.1-572
    _VCDPA_SENSITIVE: frozenset[SensitivePICategory] = frozenset({
        SensitivePICategory.RACIAL_ETHNIC_ORIGIN,
        SensitivePICategory.HEALTH_MEDICAL,
        SensitivePICategory.SEXUAL_ORIENTATION,
        SensitivePICategory.CITIZENSHIP_IMMIGRATION,
        SensitivePICategory.BIOMETRIC,
        SensitivePICategory.CHILDREN_DATA,
        SensitivePICategory.PRECISE_GEOLOCATION,
    })

    def filter(
        self,
        documents: list[Document],
        ctx: ConsumerPrivacyContext,
    ) -> tuple[list[Document], list[str]]:
        if ConsumerPrivacyState.VIRGINIA not in ctx.resident_states:
            return documents, []

        permitted: list[Document] = []
        blocked_reasons: list[str] = []

        for doc in documents:
            reason = self._evaluate(doc, ctx)
            if reason:
                blocked_reasons.append(f"VCDPA blocked {doc.doc_id}: {reason}")
            else:
                permitted.append(doc)

        return permitted, blocked_reasons

    def _evaluate(self, doc: Document, ctx: ConsumerPrivacyContext) -> str | None:
        # Sensitive data requires explicit consent
        if doc.pi_classification in self._VCDPA_SENSITIVE:
            if not ctx.sensitive_pi_consent.get(doc.pi_classification, False):
                return (
                    f"consent required to process sensitive data "
                    f"{doc.pi_classification.value} (§59.1-578)"
                )

        # Opt-out of targeted advertising
        if ctx.consumer_opted_out_of_targeted_ads and doc.is_targeted_advertising:
            return "consumer opted out of targeted advertising (§59.1-577(A)(5))"

        # Opt-out of profiling
        if ctx.consumer_opted_out_of_targeted_ads and doc.is_behavioral_profiling:
            return "consumer opted out of profiling with significant effects (§59.1-577(A)(4))"

        return None


# ---------------------------------------------------------------------------
# Layer 3 — CPA Filter
# ---------------------------------------------------------------------------

class CPAFilter:
    """
    Enforces Colorado Privacy Act
    (Colo. Rev. Stat. §§ 6-1-1301 to 6-1-1313).

    Key obligations enforced:
    - Universal opt-out mechanism (GPC signal) must be honored (§6-1-1306(5))
    - Consent required for sensitive data processing (§6-1-1308(7))
    - Right to opt out of profiling with legal/significant effects (§6-1-1306(1)(b))
    """

    _CPA_SENSITIVE: frozenset[SensitivePICategory] = frozenset({
        SensitivePICategory.RACIAL_ETHNIC_ORIGIN,
        SensitivePICategory.HEALTH_MEDICAL,
        SensitivePICategory.SEXUAL_ORIENTATION,
        SensitivePICategory.CITIZENSHIP_IMMIGRATION,
        SensitivePICategory.BIOMETRIC,
        SensitivePICategory.CHILDREN_DATA,
        SensitivePICategory.PRECISE_GEOLOCATION,
        SensitivePICategory.FINANCIAL_ACCOUNT,
    })

    def filter(
        self,
        documents: list[Document],
        ctx: ConsumerPrivacyContext,
    ) -> tuple[list[Document], list[str]]:
        if ConsumerPrivacyState.COLORADO not in ctx.resident_states:
            return documents, []

        permitted: list[Document] = []
        blocked_reasons: list[str] = []

        # GPC signal = universal opt-out of sale and targeted advertising (§6-1-1306(5))
        effective_opted_out_of_targeted_ads = (
            ctx.consumer_opted_out_of_targeted_ads or ctx.consumer_gpc_signal
        )

        for doc in documents:
            reason = self._evaluate(doc, ctx, effective_opted_out_of_targeted_ads)
            if reason:
                blocked_reasons.append(f"CPA blocked {doc.doc_id}: {reason}")
            else:
                permitted.append(doc)

        return permitted, blocked_reasons

    def _evaluate(
        self,
        doc: Document,
        ctx: ConsumerPrivacyContext,
        effective_opted_out: bool,
    ) -> str | None:
        # GPC / universal opt-out covers targeted advertising
        if effective_opted_out and doc.is_targeted_advertising:
            signal = "GPC signal" if ctx.consumer_gpc_signal else "opt-out of targeted advertising"
            return f"consumer {signal} honored as universal opt-out (§6-1-1306(5))"

        # Opt-out of profiling with legal/significant effects
        if effective_opted_out and doc.is_behavioral_profiling:
            return "consumer opted out of profiling with significant effects (§6-1-1306(1)(b))"

        # Sensitive data requires consent
        if doc.pi_classification in self._CPA_SENSITIVE:
            if not ctx.sensitive_pi_consent.get(doc.pi_classification, False):
                return (
                    f"consent required for sensitive data "
                    f"{doc.pi_classification.value} (§6-1-1308(7))"
                )

        return None


# ---------------------------------------------------------------------------
# Layer 4 — CTDPA Filter
# ---------------------------------------------------------------------------

class CTDPAFilter:
    """
    Enforces Connecticut Data Privacy Act (Conn. P.A. 22-15).

    Key obligations enforced:
    - Consent required for sensitive data processing (§6)
    - Right to opt out of targeted advertising and profiling (§4(a))
    - Universal opt-out signal recognition (effective Jan 2025) (§6(d))
    - Enhanced protections for consumers under 18 (§9)
    """

    _CTDPA_SENSITIVE: frozenset[SensitivePICategory] = frozenset({
        SensitivePICategory.RACIAL_ETHNIC_ORIGIN,
        SensitivePICategory.HEALTH_MEDICAL,
        SensitivePICategory.SEXUAL_ORIENTATION,
        SensitivePICategory.CITIZENSHIP_IMMIGRATION,
        SensitivePICategory.BIOMETRIC,
        SensitivePICategory.CHILDREN_DATA,
        SensitivePICategory.PRECISE_GEOLOCATION,
    })

    def filter(
        self,
        documents: list[Document],
        ctx: ConsumerPrivacyContext,
    ) -> tuple[list[Document], list[str]]:
        if ConsumerPrivacyState.CONNECTICUT not in ctx.resident_states:
            return documents, []

        permitted: list[Document] = []
        blocked_reasons: list[str] = []

        # Connecticut recognizes universal opt-out signals from Jan 2025
        effective_opted_out = ctx.consumer_opted_out_of_targeted_ads or ctx.consumer_gpc_signal

        for doc in documents:
            reason = self._evaluate(doc, ctx, effective_opted_out)
            if reason:
                blocked_reasons.append(f"CTDPA blocked {doc.doc_id}: {reason}")
            else:
                permitted.append(doc)

        return permitted, blocked_reasons

    def _evaluate(
        self,
        doc: Document,
        ctx: ConsumerPrivacyContext,
        effective_opted_out: bool,
    ) -> str | None:
        # Minor protections (under 18 in Connecticut)
        if ctx.consumer_age_minor and doc.is_targeted_advertising:
            return "targeted advertising prohibited for consumers under 18 (§9)"

        if ctx.consumer_age_minor and doc.is_behavioral_profiling:
            return "profiling prohibited for consumers under 18 (§9)"

        # Universal opt-out / opt-out of targeted advertising
        if effective_opted_out and doc.is_targeted_advertising:
            return "consumer opted out of targeted advertising (§4(a))"

        if effective_opted_out and doc.is_behavioral_profiling:
            return "consumer opted out of profiling (§4(a))"

        # Sensitive data consent
        if doc.pi_classification in self._CTDPA_SENSITIVE:
            if not ctx.sensitive_pi_consent.get(doc.pi_classification, False):
                return (
                    f"consent required for sensitive data "
                    f"{doc.pi_classification.value} (§6)"
                )

        return None


# ---------------------------------------------------------------------------
# Multi-state privacy pipeline (most-restrictive-jurisdiction logic)
# ---------------------------------------------------------------------------

@dataclass
class StatePrivacyAuditRecord:
    """
    Audit record for a multi-state consumer privacy retrieval decision.

    Captures the per-law analysis required for CCPA/CPRA Business Purpose
    records, VCDPA/CPA/CTDPA data protection assessments, and regulatory
    inquiry response documentation.
    """
    request_id: str
    consumer_id: str
    resident_states: list[str]
    requested_purpose: str
    total_candidates: int
    permitted_count: int
    blocked_count: int
    per_law_blocked: dict[str, list[str]]  # law_name → [block reason strings]
    most_restrictive_law: str             # Law that blocked the most documents
    applicable_laws: list[str]
    gpc_signal_honored: bool


class MultiStatePrivacyPipeline:
    """
    Defense-in-depth retrieval pipeline applying all applicable state privacy
    laws. Each filter is applied independently; the most-restrictive result
    (union of all blocks) governs final retrieval.

    Architecture
    ------------
    Each state filter receives the *full candidate set* and returns its own
    blocked list. A document is permitted only if *every applicable state*
    permits it. This ensures that a California resident's CPRA opt-out is not
    circumvented by the absence of a Virginia consent block.
    """

    def __init__(self) -> None:
        self._ccpa_cpra = CCPACPRAFilter()
        self._vcdpa = VCDPAFilter()
        self._cpa = CPAFilter()
        self._ctdpa = CTDPAFilter()

    def retrieve(
        self,
        candidates: list[Document],
        ctx: ConsumerPrivacyContext,
    ) -> tuple[list[Document], StatePrivacyAuditRecord]:
        """
        Apply all applicable state privacy filters.

        Returns the intersection of documents permitted by every applicable
        filter and a comprehensive audit record.
        """
        per_law_blocked: dict[str, list[str]] = {}
        # Build set of blocked doc_ids per law
        blocked_sets: dict[str, set[str]] = {}

        # Run each filter independently over the full candidate set
        _, ccpa_blocked = self._ccpa_cpra.filter(candidates, ctx)
        _, vcdpa_blocked = self._vcdpa.filter(candidates, ctx)
        _, cpa_blocked = self._cpa.filter(candidates, ctx)
        _, ctdpa_blocked = self._ctdpa.filter(candidates, ctx)

        law_results = {
            "CCPA/CPRA": ccpa_blocked,
            "VCDPA": vcdpa_blocked,
            "CPA": cpa_blocked,
            "CTDPA": ctdpa_blocked,
        }

        # Collect blocked doc_ids per law
        # Reason strings have format: "{LAW} blocked {DOC_ID}: {reason}"
        for law, reasons in law_results.items():
            if reasons:
                per_law_blocked[law] = reasons
                # Extract doc_id: third token after "<law> blocked <doc_id>:"
                blocked_sets[law] = {r.split(" ", 3)[2].rstrip(":") for r in reasons}

        # Union of all blocked doc_ids (most-restrictive-jurisdiction)
        all_blocked_ids: set[str] = set()
        for ids in blocked_sets.values():
            all_blocked_ids |= ids

        permitted = [d for d in candidates if d.doc_id not in all_blocked_ids]

        # Determine which law blocked the most documents
        most_restrictive = max(
            blocked_sets,
            key=lambda k: len(blocked_sets[k]),
            default="none",
        )

        applicable_laws = [
            law
            for law, state in {
                "CCPA/CPRA": ConsumerPrivacyState.CALIFORNIA,
                "VCDPA": ConsumerPrivacyState.VIRGINIA,
                "CPA": ConsumerPrivacyState.COLORADO,
                "CTDPA": ConsumerPrivacyState.CONNECTICUT,
            }.items()
            if state in ctx.resident_states
        ]

        audit = StatePrivacyAuditRecord(
            request_id=str(uuid.uuid4()),
            consumer_id=ctx.consumer_id,
            resident_states=[s.value for s in ctx.resident_states],
            requested_purpose=ctx.requested_purpose.value,
            total_candidates=len(candidates),
            permitted_count=len(permitted),
            blocked_count=len(all_blocked_ids),
            per_law_blocked=per_law_blocked,
            most_restrictive_law=most_restrictive,
            applicable_laws=applicable_laws,
            gpc_signal_honored=ctx.consumer_gpc_signal
            and ConsumerPrivacyState.COLORADO in ctx.resident_states,
        )

        return permitted, audit


# ---------------------------------------------------------------------------
# Sample document corpus
# ---------------------------------------------------------------------------

SAMPLE_DOCUMENTS: list[Document] = [
    # Non-sensitive transactional / support documents
    Document(
        doc_id="DOC-001",
        content="Order confirmation and shipping tracking information for customer orders.",
        pi_classification=SensitivePICategory.NON_SENSITIVE,
        requires_sale_opt_in=False,
        is_targeted_advertising=False,
    ),
    Document(
        doc_id="DOC-002",
        content="Product catalog and pricing information for all SKUs.",
        pi_classification=SensitivePICategory.PUBLIC,
        is_targeted_advertising=False,
    ),
    Document(
        doc_id="DOC-003",
        content="Customer service knowledge base: return policies, refund procedures.",
        pi_classification=SensitivePICategory.NON_SENSITIVE,
        is_targeted_advertising=False,
    ),
    # Documents involving sale/sharing of PI
    Document(
        doc_id="DOC-004",
        content="Behavioral purchase history with purchase frequency and category affinity scores.",
        pi_classification=SensitivePICategory.NON_SENSITIVE,
        requires_sale_opt_in=True,
        requires_sharing_opt_in=True,
        is_targeted_advertising=True,
        is_behavioral_profiling=True,
    ),
    Document(
        doc_id="DOC-005",
        content="Customer segmentation profile: income bracket, lifestyle category, household size.",
        pi_classification=SensitivePICategory.NON_SENSITIVE,
        requires_sale_opt_in=True,
        requires_sharing_opt_in=True,
        is_targeted_advertising=True,
        is_behavioral_profiling=True,
        is_third_party_sale=True,
    ),
    # Sensitive PI — geolocation
    Document(
        doc_id="DOC-006",
        content="Customer precise GPS location history from mobile app sessions.",
        pi_classification=SensitivePICategory.PRECISE_GEOLOCATION,
        requires_sharing_opt_in=True,
        is_targeted_advertising=True,
    ),
    # Sensitive PI — health
    Document(
        doc_id="DOC-007",
        content="Customer self-reported dietary restrictions and health-related purchase preferences.",
        pi_classification=SensitivePICategory.HEALTH_MEDICAL,
        requires_sharing_opt_in=True,
    ),
    # Sensitive PI — financial
    Document(
        doc_id="DOC-008",
        content="Linked bank account and payment method information for saved payment profiles.",
        pi_classification=SensitivePICategory.FINANCIAL_ACCOUNT,
        requires_sale_opt_in=True,
    ),
    # Advertising personalization
    Document(
        doc_id="DOC-009",
        content="Interest-based ad targeting parameters: browsing history, affinity categories, retargeting lists.",
        pi_classification=SensitivePICategory.NON_SENSITIVE,
        requires_sharing_opt_in=True,
        is_targeted_advertising=True,
        is_behavioral_profiling=True,
        is_third_party_sale=True,
    ),
    # Account data — servicing only
    Document(
        doc_id="DOC-010",
        content="Customer account: name, email address, saved shipping addresses, order history.",
        pi_classification=SensitivePICategory.NON_SENSITIVE,
        requires_sale_opt_in=False,
        is_targeted_advertising=False,
    ),
]


# ---------------------------------------------------------------------------
# Scenario helpers
# ---------------------------------------------------------------------------

def _print_result(
    label: str,
    permitted: list[Document],
    audit: StatePrivacyAuditRecord,
) -> None:
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"{'='*70}")
    print(f"  Consumer ID  : {audit.consumer_id[:12]}…")
    print(f"  Resident     : {', '.join(audit.resident_states)}")
    print(f"  Purpose      : {audit.requested_purpose}")
    print(f"  Applicable   : {', '.join(audit.applicable_laws)}")
    print(f"  GPC honored  : {audit.gpc_signal_honored}")
    print(f"  Candidates   : {audit.total_candidates}")
    print(f"  Permitted    : {audit.permitted_count}  ✓")
    print(f"  Blocked      : {audit.blocked_count}  ✗  (most restrictive: {audit.most_restrictive_law})")
    print()
    if audit.per_law_blocked:
        print("  Block details:")
        for law, reasons in audit.per_law_blocked.items():
            for r in reasons:
                print(f"    [{law}] {r}")
    print()
    print("  Permitted documents:")
    for doc in permitted:
        print(f"    ✓  {doc.doc_id}  —  {doc.content[:60]}…")
    if not permitted:
        print("    (none — only non-personal public documents remain)")


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def scenario_a_california_cpra_opt_out() -> None:
    """
    California resident who has opted out of sharing AND issued a SPI
    limit-use instruction for precise geolocation. Requests personalization.
    """
    ctx = ConsumerPrivacyContext(
        resident_states=frozenset({ConsumerPrivacyState.CALIFORNIA}),
        requested_purpose=DataProcessingPurpose.PERSONALIZATION,
        consumer_opted_out_of_sale=False,
        consumer_opted_out_of_sharing=True,       # CPRA §1798.135 opt-out
        consumer_opted_out_of_targeted_ads=True,
        consumer_gpc_signal=False,
        sensitive_pi_consent={},                  # No SPI consent granted
        spi_limit_use_instruction=frozenset({     # CPRA §1798.121 limit-use
            SensitivePICategory.PRECISE_GEOLOCATION,
        }),
        consumer_age_minor=False,
    )
    pipeline = MultiStatePrivacyPipeline()
    permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx)
    _print_result(
        "Scenario A — California CPRA: sharing opt-out + SPI limit-use (geolocation)",
        permitted,
        audit,
    )


def scenario_b_virginia_sensitive_data_consent() -> None:
    """
    Virginia resident without sensitive data consent. Requests customer support
    query that would retrieve health-tagged dietary preference documents.
    """
    ctx = ConsumerPrivacyContext(
        resident_states=frozenset({ConsumerPrivacyState.VIRGINIA}),
        requested_purpose=DataProcessingPurpose.CUSTOMER_SUPPORT,
        consumer_opted_out_of_sale=False,
        consumer_opted_out_of_sharing=False,
        consumer_opted_out_of_targeted_ads=False,
        consumer_gpc_signal=False,
        sensitive_pi_consent={},                  # No consent for health data
        consumer_age_minor=False,
    )
    pipeline = MultiStatePrivacyPipeline()
    permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx)
    _print_result(
        "Scenario B — Virginia VCDPA: no consent for sensitive health data",
        permitted,
        audit,
    )


def scenario_c_colorado_gpc_universal_opt_out() -> None:
    """
    Colorado resident whose browser sends a GPC signal (Global Privacy Control).
    CPA §6-1-1306(5) requires the GPC signal to be treated as an opt-out of
    sale and targeted advertising.
    """
    ctx = ConsumerPrivacyContext(
        resident_states=frozenset({ConsumerPrivacyState.COLORADO}),
        requested_purpose=DataProcessingPurpose.TARGETED_ADVERTISING,
        consumer_opted_out_of_sale=False,
        consumer_opted_out_of_sharing=False,
        consumer_opted_out_of_targeted_ads=False,  # No explicit opt-out...
        consumer_gpc_signal=True,                  # ...but GPC signal present → must honor
        sensitive_pi_consent={},
        consumer_age_minor=False,
    )
    pipeline = MultiStatePrivacyPipeline()
    permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx)
    _print_result(
        "Scenario C — Colorado CPA: GPC universal opt-out signal honored",
        permitted,
        audit,
    )


def scenario_d_multi_state_most_restrictive() -> None:
    """
    Consumer who is a resident of both California AND Virginia (e.g., recently
    relocated; legal residence in both states asserted).

    California CPRA sharing opt-out AND Virginia sensitive-data consent
    requirement both apply. The most-restrictive combination governs.
    """
    ctx = ConsumerPrivacyContext(
        resident_states=frozenset({
            ConsumerPrivacyState.CALIFORNIA,
            ConsumerPrivacyState.VIRGINIA,
        }),
        requested_purpose=DataProcessingPurpose.PERSONALIZATION,
        consumer_opted_out_of_sale=True,           # CCPA/CPRA sale opt-out
        consumer_opted_out_of_sharing=True,        # CPRA sharing opt-out
        consumer_opted_out_of_targeted_ads=True,
        consumer_gpc_signal=False,
        sensitive_pi_consent={
            # Virginia requires consent for health; California SPI also blocked by limit-use
            SensitivePICategory.FINANCIAL_ACCOUNT: True,  # Only financial consent granted
        },
        spi_limit_use_instruction=frozenset({
            SensitivePICategory.PRECISE_GEOLOCATION,
            SensitivePICategory.HEALTH_MEDICAL,
        }),
        consumer_age_minor=False,
    )
    pipeline = MultiStatePrivacyPipeline()
    permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx)
    _print_result(
        "Scenario D — Multi-state (CA + VA): most-restrictive-jurisdiction applies",
        permitted,
        audit,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Multi-State US Consumer Privacy RAG Pipeline")
    print("CCPA/CPRA (CA) · VCDPA (VA) · CPA (CO) · CTDPA (CT)")
    print("Defense-in-depth: all applicable laws applied independently; union of blocks enforced")

    scenario_a_california_cpra_opt_out()
    scenario_b_virginia_sensitive_data_consent()
    scenario_c_colorado_gpc_universal_opt_out()
    scenario_d_multi_state_most_restrictive()

    print("\n" + "="*70)
    print("  All four scenarios complete.")
    print("  Each state law applied independently. Most-restrictive-jurisdiction")
    print("  logic ensures the union of all state blocks governs final retrieval.")
    print("="*70)
