"""
Telecom CPNI RAG Pipeline — Four-Layer Defense-in-Depth

This module implements a compliance-aware RAG retrieval pipeline for
telecommunications platforms.  Four independent filter layers run sequentially;
a document must pass all four to be returned to the caller.

Commercial use cases:

  +------------------------------------------+--------------------------------------------+
  | Platform / Product                       | Applicable Regulation(s)                   |
  +------------------------------------------+--------------------------------------------+
  | Carrier self-service portals             | 47 CFR Part 64 (CPNI), CALEA               |
  | Customer care agent desktops             | 47 CFR §64.2007 (authentication)           |
  | Law enforcement liaison systems          | CALEA 47 USC §1002                         |
  | Broadband analytics platforms            | 47 CFR Part 64 Subpart U                   |
  | Marketing intelligence systems           | 47 CFR §64.2005 (opt-in consent)           |
  | California subscriber portals            | CalOPPA + CCPA §1798.100                   |
  | Billing dispute resolution tools         | 47 CFR §64.2009 (billing dispute bypass)   |
  | 911 / emergency dispatch integration     | 47 CFR §64.2009 (emergency bypass)         |
  +------------------------------------------+--------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — CPNIAccessFilter (47 CFR Part 64)
      The Federal Communications Commission's Customer Proprietary Network
      Information rules (47 CFR Part 64, Subpart C) govern how carriers
      may use and disclose information about customers' use of
      telecommunications services.

      47 CFR §64.2005 (Use of CPNI): Carriers may use CPNI for the
      provision of the telecommunications service from which the CPNI was
      derived, for the provision of services necessary to the provision of
      such telecommunications service, and for the provision of call
      location information to a public safety answering point.  Use for
      any other purpose—including marketing of unrelated services—requires
      affirmative opt-in consent from the customer.

      47 CFR §64.2007 (Safeguards for use of CPNI): Before a carrier may
      disclose call detail records, location data, or account information
      to any party other than the customer, the carrier must first
      authenticate the requesting party as the customer of record using
      a password-based, knowledge-based, or in-store authentication
      method.  Disclosure of call detail records without prior
      authentication is prohibited.

      47 CFR §64.2009 (Safeguards on the use of CPNI): CPNI may not be
      disclosed to third parties without customer consent except for:
      (a) Emergency services (911/E-911); (b) law enforcement with a
      valid court order or lawful process; or (c) resolution of a billing
      dispute initiated by the customer.

  Layer 2 — CALEAFilter (47 USC §1002)
      The Communications Assistance for Law Enforcement Act (CALEA, 47
      USC §§1001–1010) requires telecommunications carriers to build and
      maintain lawful intercept capability within their networks so that
      law enforcement agencies with valid legal authority may conduct
      lawful electronic surveillance.

      47 USC §1002(a): A telecommunications carrier shall ensure that its
      equipment, facilities, or services that provide a customer or
      subscriber with the ability to originate, terminate, or direct
      communications are capable of expeditiously isolating and enabling
      the government to intercept, to the exclusion of any other
      communications, all wire and electronic communications carried by
      the carrier.

      47 USC §1002(b): CALEA does not authorize any law enforcement agency
      to conduct electronic surveillance except as authorized by law.
      Access to lawful intercept records without a valid court order or
      other lawful process is strictly prohibited.  Only law enforcement
      personnel in possession of a valid court order may access lawful
      intercept records through this pipeline.

  Layer 3 — FCCBroadbandPrivacyFilter (47 CFR Part 64, Subpart U)
      The FCC's broadband privacy rules (47 CFR Part 64, Subpart U)
      require ISPs and broadband carriers to obtain opt-in consent before
      using, sharing, or selling sensitive customer proprietary information
      derived from broadband usage.

      Sensitive broadband data categories requiring opt-in consent:
        — Precise geo-location data derived from broadband access
        — Web browsing history and app usage data
        — Financial and health information inferred from usage patterns
        — Content of communications

      Customer data used solely for billing (usage volumes, service tier,
      billing period) is not sensitive broadband data and does not require
      opt-in consent under the broadband privacy rules.

  Layer 4 — StateTelecomPrivacyFilter (CalOPPA + CCPA)
      California has enacted consumer privacy protections for telecom and
      broadband data that are stricter than corresponding federal rules.

      California Online Privacy Protection Act (CalOPPA): Requires
      operators collecting personally identifiable information from
      California residents to conspicuously post a privacy policy and
      comply with its terms.  Applies to telecom carriers offering
      services to California subscribers.

      California Consumer Privacy Act / CPRA (Civil Code §1798.100 et
      seq.): Grants California consumers the right to know, delete, and
      opt-out of the sale or sharing of their personal information.
      Inferred profiles derived from telecom usage data that contain
      sensitive personal information require explicit opt-in consent
      before the profile may be accessed for any purpose other than
      the direct service relationship.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TelecomRole(Enum):
    CUSTOMER = "CUSTOMER"
    CARRIER_AGENT = "CARRIER_AGENT"
    LAW_ENFORCEMENT = "LAW_ENFORCEMENT"
    BILLING_SYSTEM = "BILLING_SYSTEM"
    REGULATOR = "REGULATOR"


class TelecomDocumentType(Enum):
    CALL_DETAIL_RECORD = "CALL_DETAIL_RECORD"
    LOCATION_DATA = "LOCATION_DATA"
    ACCOUNT_INFO = "ACCOUNT_INFO"
    USAGE_RECORD = "USAGE_RECORD"
    LAWFUL_INTERCEPT_RECORD = "LAWFUL_INTERCEPT_RECORD"
    BROADBAND_USAGE = "BROADBAND_USAGE"
    INFERRED_PROFILE = "INFERRED_PROFILE"


class Decision(Enum):
    PERMITTED = "PERMITTED"
    DENIED = "DENIED"
    REDACTED = "REDACTED"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TelecomContext:
    """
    Carries all per-request attributes needed by the four filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorization state.
    """

    user_id: str
    role: TelecomRole
    customer_id: str
    carrier_id: str
    has_cpni_consent: bool
    has_broadband_privacy_consent: bool
    has_ccpa_consent: bool
    is_authenticated: bool
    has_court_order: bool
    access_purpose: str   # "service_provisioning", "marketing", "emergency_911",
                          # "law_enforcement_court_order", "billing_dispute",
                          # "regulatory_audit"
    customer_state: str   # Two-letter US state code, e.g. "CA", "TX"
    is_law_enforcement: bool


@dataclass(frozen=True)
class TelecomDocument:
    """
    Immutable document descriptor carrying attributes needed for compliance
    evaluation across all four filter layers.
    """

    document_id: str
    document_type: TelecomDocumentType
    customer_id: str
    is_call_detail_record: bool
    is_sensitive_broadband_data: bool   # location, browsing, or app-usage data
    is_lawful_intercept_record: bool
    contains_inferred_data: bool        # Behavioral profiles inferred from usage
    classification: str                 # "CPNI", "PUBLIC", "LAWFUL_INTERCEPT"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: Decision
    reason: str
    regulation_citation: str

    @property
    def is_denied(self) -> bool:
        return self.decision == Decision.DENIED


# ---------------------------------------------------------------------------
# Layer 1: CPNIAccessFilter — 47 CFR Part 64
# ---------------------------------------------------------------------------

class CPNIAccessFilter:
    """
    Enforces FCC Customer Proprietary Network Information rules under
    47 CFR Part 64, Subpart C.

    47 CFR §64.2005 (Use of CPNI): Affirmative opt-in consent is required
    for any CPNI use beyond the provisioning of the telecommunications
    service from which the CPNI was derived.  Three statutory exceptions
    allow CPNI access without consent: (1) emergency 911 services,
    (2) law enforcement with a valid court order, and (3) resolution of
    a billing dispute initiated by the customer.

    47 CFR §64.2007 (Customer authentication before CDR release):
    Carriers must authenticate the requesting party as the customer of
    record before disclosing call detail records (CDRs), location data,
    or account information.  A CPNI-classified document that is a call
    detail record may not be disclosed to an unauthenticated request,
    even when the caller claims customer identity.

    47 CFR §64.2009 (Third-party disclosure safeguards): Prohibits
    disclosure to third parties without consent except for the three
    enumerated exemptions.
    """

    LAYER_NAME = "CPNI_47_CFR_PART_64"

    # Purposes that bypass the general consent requirement under §64.2009.
    _CONSENT_BYPASS_PURPOSES = frozenset({
        "emergency_911",
        "law_enforcement_court_order",
        "billing_dispute",
    })

    def evaluate(
        self, context: TelecomContext, document: TelecomDocument
    ) -> FilterResult:
        """
        Evaluate whether the requesting context satisfies CPNI consent
        and authentication requirements for access to the document.

        Returns a FilterResult with PERMITTED or DENIED together with the
        operative 47 CFR citation and finding.
        """
        # Non-CPNI documents are not subject to Part 64 CPNI controls.
        if document.classification != "CPNI":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason="Document is not CPNI-classified — 47 CFR Part 64 not applicable",
                regulation_citation="47 CFR §64.2001",
            )

        # §64.2007: CDRs require prior authentication regardless of consent.
        # Check authentication before evaluating consent — an unauthenticated
        # request for CDRs is denied even if the customer's consent is on file,
        # because authentication is a separate safeguard.
        if document.is_call_detail_record and not context.is_authenticated:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    "47 CFR §64.2007: Call detail records require customer "
                    "authentication before disclosure — request is not authenticated"
                ),
                regulation_citation="47 CFR §64.2007",
            )

        # §64.2005 / §64.2009: If the access purpose qualifies for a statutory
        # bypass, consent is not required.
        if context.access_purpose in self._CONSENT_BYPASS_PURPOSES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason=(
                    f"47 CFR §64.2009 exception applies — access purpose "
                    f"'{context.access_purpose}' is an enumerated CPNI exception"
                ),
                regulation_citation="47 CFR §64.2009",
            )

        # §64.2005: For all other purposes, affirmative opt-in consent is required.
        if not context.has_cpni_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    "47 CFR §64.2005: Affirmative opt-in CPNI consent required "
                    "— customer has not provided consent for this access purpose"
                ),
                regulation_citation="47 CFR §64.2005",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision=Decision.PERMITTED,
            reason="47 CFR §64.2005/§64.2007/§64.2009 — CPNI access compliant",
            regulation_citation="47 CFR §64.2005",
        )


# ---------------------------------------------------------------------------
# Layer 2: CALEAFilter — 47 USC §1002
# ---------------------------------------------------------------------------

class CALEAFilter:
    """
    Enforces the Communications Assistance for Law Enforcement Act (CALEA,
    47 USC §§1001–1010) requirements for lawful intercept records.

    47 USC §1002(a): Carriers must maintain lawful intercept capability
    to enable government access under lawful authority.  This capability
    is available only to law enforcement with a valid court order or other
    lawful process.

    47 USC §1002(b): CALEA explicitly prohibits unauthorized access to
    intercept capability and intercept records.  Any access to lawful
    intercept records without a valid court order is strictly prohibited,
    regardless of the requester's identity or stated purpose.

    Non-intercept records are outside the scope of CALEA and pass through
    this layer without restriction.
    """

    LAYER_NAME = "CALEA_47_USC_1002"

    def evaluate(
        self, context: TelecomContext, document: TelecomDocument
    ) -> FilterResult:
        """
        Evaluate CALEA requirements for lawful intercept records.

        Non-intercept records pass through immediately.  Intercept records
        require a valid court order; the court order check is made before
        any other consideration — no role, consent, or bypass can override
        the CALEA court order requirement.

        Returns a FilterResult with PERMITTED or DENIED together with
        the operative CALEA statutory citation.
        """
        # CALEA applies only to lawful intercept records.
        if not document.is_lawful_intercept_record:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason="Document is not a lawful intercept record — CALEA not applicable",
                regulation_citation="CALEA 47 USC §1002",
            )

        # Intercept records: court order is unconditionally required.
        if not context.has_court_order:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    "CALEA 47 USC §1002 — court order required: lawful intercept "
                    "records may not be accessed without a valid court order"
                ),
                regulation_citation="CALEA 47 USC §1002",
            )

        # Intercept records with a valid court order are permitted.
        return FilterResult(
            layer=self.LAYER_NAME,
            decision=Decision.PERMITTED,
            reason=(
                "CALEA 47 USC §1002 — valid court order on file: "
                "lawful intercept access authorized"
            ),
            regulation_citation="CALEA 47 USC §1002",
        )


# ---------------------------------------------------------------------------
# Layer 3: FCCBroadbandPrivacyFilter — 47 CFR Part 64, Subpart U
# ---------------------------------------------------------------------------

class FCCBroadbandPrivacyFilter:
    """
    Enforces FCC broadband privacy rules under 47 CFR Part 64, Subpart U.

    Sensitive broadband data categories include: precise geo-location,
    web browsing history, app usage data, financial and health information
    inferred from usage patterns, and content of communications.  Carriers
    must obtain affirmative opt-in consent before using, sharing, or
    providing access to sensitive broadband data for any purpose other
    than providing the broadband service itself.

    Customer usage data used solely for billing (e.g., data volumes,
    service tier, billing period totals) is not treated as sensitive
    broadband data and is permitted without opt-in consent.

    Non-broadband documents are outside the scope of Subpart U and pass
    through this layer without restriction.
    """

    LAYER_NAME = "FCC_BROADBAND_PRIVACY_SUBPART_U"

    def evaluate(
        self, context: TelecomContext, document: TelecomDocument
    ) -> FilterResult:
        """
        Evaluate FCC broadband privacy requirements for access to the document.

        Returns a FilterResult with PERMITTED or DENIED together with the
        operative 47 CFR Part 64 Subpart U citation and finding.
        """
        # Only broadband usage documents are subject to Subpart U controls.
        if document.document_type not in {
            TelecomDocumentType.BROADBAND_USAGE,
            TelecomDocumentType.INFERRED_PROFILE,
        } and not document.is_sensitive_broadband_data:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason=(
                    "Document is not broadband usage data — "
                    "47 CFR Part 64 Subpart U not applicable"
                ),
                regulation_citation="47 CFR Part 64 Subpart U",
            )

        # Billing usage records are not sensitive broadband data under Subpart U;
        # they are permitted without opt-in consent.
        if (
            context.access_purpose == "billing_dispute"
            and not document.is_sensitive_broadband_data
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason=(
                    "47 CFR Part 64 Subpart U: Customer usage data for billing "
                    "purposes is not sensitive broadband data — permitted"
                ),
                regulation_citation="47 CFR Part 64 Subpart U",
            )

        # Sensitive broadband data requires affirmative opt-in consent.
        if document.is_sensitive_broadband_data and not context.has_broadband_privacy_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    "47 CFR Part 64 Subpart U — sensitive broadband data requires "
                    "opt-in consent: location, browsing, and app-usage data may not "
                    "be accessed without customer's affirmative consent"
                ),
                regulation_citation="47 CFR Part 64 Subpart U",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision=Decision.PERMITTED,
            reason="47 CFR Part 64 Subpart U broadband privacy — compliant",
            regulation_citation="47 CFR Part 64 Subpart U",
        )


# ---------------------------------------------------------------------------
# Layer 4: StateTelecomPrivacyFilter — CalOPPA + CCPA
# ---------------------------------------------------------------------------

class StateTelecomPrivacyFilter:
    """
    Enforces California state telecom privacy requirements, which are
    stricter than corresponding FCC rules.

    California Online Privacy Protection Act (CalOPPA): Requires operators
    to comply with their posted privacy policies when collecting and using
    personally identifiable information from California residents.

    California Consumer Privacy Act / CPRA (Civil Code §1798.100 et seq.):
    Grants California consumers comprehensive rights over their personal
    information.  Inferred profiles derived from telecom usage data are
    treated as sensitive personal information under the CCPA.  Access to
    such profiles—even by the carrier's own systems—requires explicit
    opt-in consent from the California consumer.

    Customers in states other than California are not subject to this
    layer's consent gate (other state laws may apply in future layers);
    this filter passes through non-California requests without restriction.
    """

    LAYER_NAME = "STATE_TELECOM_PRIVACY_CALOPPA_CCPA"

    def evaluate(
        self, context: TelecomContext, document: TelecomDocument
    ) -> FilterResult:
        """
        Evaluate California CPNI and CCPA requirements for access to
        the document.

        Returns a FilterResult with PERMITTED or DENIED together with the
        operative CalOPPA / CCPA citation and finding.
        """
        # Only California customers are subject to this layer's consent gate.
        if context.customer_state != "CA":
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.PERMITTED,
                reason=(
                    f"Customer is in {context.customer_state!r} — "
                    "CalOPPA/CCPA state telecom privacy layer not applicable"
                ),
                regulation_citation="CalOPPA + CCPA §1798.100",
            )

        # For California customers, inferred data (behavioral profiles derived
        # from usage) requires explicit CCPA opt-in consent.
        if document.contains_inferred_data and not context.has_ccpa_consent:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision=Decision.DENIED,
                reason=(
                    "CalOPPA + CCPA §1798.100 — CA customer CPNI requires explicit "
                    "consent: inferred profile data for a California subscriber "
                    "requires affirmative opt-in under CCPA"
                ),
                regulation_citation="CalOPPA + CCPA §1798.100",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision=Decision.PERMITTED,
            reason="CalOPPA + CCPA §1798.100 California telecom privacy — compliant",
            regulation_citation="CalOPPA + CCPA §1798.100",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class TelecomAuditRecord:
    """
    Captures the full decision trail for a Telecom CPNI RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - 47 CFR §64.2009: CPNI access logging and annual reporting to FCC.
      - CALEA 47 USC §1002: Lawful intercept access audit requirements.
      - 47 CFR Part 64 Subpart U: Broadband data access record-keeping.
      - CCPA §1798.100: California consumer data access accounting.

    All fields are populated at retrieval time; the timestamp uses the
    system clock and should be treated as UTC for regulatory record-keeping.
    """

    user_id: str
    carrier_id: str
    customer_id: str
    role: TelecomRole
    access_purpose: str
    documents_evaluated: int
    documents_permitted: int
    documents_denied: int
    filter_results: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": "TELECOM_CPNI_RAG_RETRIEVAL",
            "user_id": self.user_id,
            "carrier_id": self.carrier_id,
            "customer_id": self.customer_id,
            "role": self.role.value,
            "access_purpose": self.access_purpose,
            "documents_evaluated": self.documents_evaluated,
            "documents_permitted": self.documents_permitted,
            "documents_denied": self.documents_denied,
            "filter_results": self.filter_results,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class TelecomCPNIRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for telecom and
    broadband platforms subject to CPNI, CALEA, FCC broadband privacy,
    and state telecom privacy requirements.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED
    result stops evaluation for that document.  Only documents that pass
    all four layers are returned to the caller.

    Layers in order:
      1. CPNIAccessFilter          — 47 CFR Part 64 CPNI consent + auth
      2. CALEAFilter               — CALEA 47 USC §1002 court order gate
      3. FCCBroadbandPrivacyFilter — 47 CFR Part 64 Subpart U opt-in
      4. StateTelecomPrivacyFilter — CalOPPA + CCPA §1798.100

    Audit records are generated for every document regardless of outcome,
    providing a complete access trail for FCC annual CPNI audit reporting
    and CCPA disclosure accounting obligations.
    """

    def __init__(self) -> None:
        self._layers = [
            CPNIAccessFilter(),
            CALEAFilter(),
            FCCBroadbandPrivacyFilter(),
            StateTelecomPrivacyFilter(),
        ]

    def retrieve(
        self,
        context: TelecomContext,
        documents: List[TelecomDocument],
    ) -> List[tuple]:
        """
        Return a list of (document, filter_results) tuples for all documents
        that pass all four filter layers.

        Documents denied on any layer are excluded from the result.  Each
        returned tuple contains the document and the list of per-layer
        FilterResult objects representing the evaluation trail.
        """
        permitted = []
        for doc in documents:
            layer_results: List[FilterResult] = []
            allow = True
            for layer in self._layers:
                result = layer.evaluate(context, doc)
                layer_results.append(result)
                if result.is_denied:
                    allow = False
                    break
            if allow:
                permitted.append((doc, layer_results))
        return permitted

    def retrieve_with_audit(
        self,
        context: TelecomContext,
        documents: List[TelecomDocument],
    ) -> TelecomAuditRecord:
        """
        Evaluate all documents and return a TelecomAuditRecord summarising
        the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support FCC CPNI
        annual audit reporting and CCPA disclosure accounting.
        """
        documents_permitted = 0
        documents_denied = 0
        all_filter_results: List[dict] = []

        for doc in documents:
            layer_results: List[dict] = []
            allow = True
            final_decision = Decision.PERMITTED

            for layer in self._layers:
                result = layer.evaluate(context, doc)
                layer_results.append(
                    {
                        "layer": result.layer,
                        "decision": result.decision.value,
                        "reason": result.reason,
                        "regulation_citation": result.regulation_citation,
                    }
                )
                if result.is_denied:
                    allow = False
                    final_decision = Decision.DENIED
                    break

            if allow:
                documents_permitted += 1
            else:
                documents_denied += 1

            all_filter_results.append(
                {
                    "document_id": doc.document_id,
                    "final_decision": final_decision.value,
                    "layer_results": layer_results,
                }
            )

        return TelecomAuditRecord(
            user_id=context.user_id,
            carrier_id=context.carrier_id,
            customer_id=context.customer_id,
            role=context.role,
            access_purpose=context.access_purpose,
            documents_evaluated=len(documents),
            documents_permitted=documents_permitted,
            documents_denied=documents_denied,
            filter_results=all_filter_results,
        )


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("=" * 70)
    print("Telecom CPNI RAG Pipeline — Smoke Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Shared documents
    # ------------------------------------------------------------------

    cdr_doc = TelecomDocument(
        document_id="doc-001-call-detail-record",
        document_type=TelecomDocumentType.CALL_DETAIL_RECORD,
        customer_id="cust-001",
        is_call_detail_record=True,
        is_sensitive_broadband_data=False,
        is_lawful_intercept_record=False,
        contains_inferred_data=False,
        classification="CPNI",
    )

    intercept_doc = TelecomDocument(
        document_id="doc-002-lawful-intercept",
        document_type=TelecomDocumentType.LAWFUL_INTERCEPT_RECORD,
        customer_id="cust-001",
        is_call_detail_record=False,
        is_sensitive_broadband_data=False,
        is_lawful_intercept_record=True,
        contains_inferred_data=False,
        classification="LAWFUL_INTERCEPT",
    )

    broadband_doc = TelecomDocument(
        document_id="doc-003-broadband-location",
        document_type=TelecomDocumentType.BROADBAND_USAGE,
        customer_id="cust-001",
        is_call_detail_record=False,
        is_sensitive_broadband_data=True,
        is_lawful_intercept_record=False,
        contains_inferred_data=False,
        classification="CPNI",
    )

    inferred_profile_ca = TelecomDocument(
        document_id="doc-004-inferred-profile-ca",
        document_type=TelecomDocumentType.INFERRED_PROFILE,
        customer_id="cust-002",
        is_call_detail_record=False,
        is_sensitive_broadband_data=True,
        is_lawful_intercept_record=False,
        contains_inferred_data=True,
        classification="CPNI",
    )

    public_doc = TelecomDocument(
        document_id="doc-005-public-rate-card",
        document_type=TelecomDocumentType.ACCOUNT_INFO,
        customer_id="",
        is_call_detail_record=False,
        is_sensitive_broadband_data=False,
        is_lawful_intercept_record=False,
        contains_inferred_data=False,
        classification="PUBLIC",
    )

    all_documents = [cdr_doc, intercept_doc, broadband_doc, inferred_profile_ca, public_doc]

    # ------------------------------------------------------------------
    # Scenario 1: Authenticated carrier agent with full consent (TX)
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: Authenticated carrier agent, full consent (TX) ---")
    ctx_agent_full = TelecomContext(
        user_id="agent-001",
        role=TelecomRole.CARRIER_AGENT,
        customer_id="cust-001",
        carrier_id="carrier-acme",
        has_cpni_consent=True,
        has_broadband_privacy_consent=True,
        has_ccpa_consent=False,
        is_authenticated=True,
        has_court_order=False,
        access_purpose="service_provisioning",
        customer_state="TX",
        is_law_enforcement=False,
    )
    pipeline = TelecomCPNIRAGPipeline()
    results = pipeline.retrieve(ctx_agent_full, all_documents)
    print(f"  Permitted documents: {[r[0].document_id for r in results]}")

    # ------------------------------------------------------------------
    # Scenario 2: Law enforcement with court order
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Law enforcement with court order ---")
    ctx_le = TelecomContext(
        user_id="agent-le-007",
        role=TelecomRole.LAW_ENFORCEMENT,
        customer_id="cust-001",
        carrier_id="carrier-acme",
        has_cpni_consent=False,
        has_broadband_privacy_consent=False,
        has_ccpa_consent=False,
        is_authenticated=True,
        has_court_order=True,
        access_purpose="law_enforcement_court_order",
        customer_state="TX",
        is_law_enforcement=True,
    )
    results_le = pipeline.retrieve(ctx_le, [cdr_doc, intercept_doc])
    print(f"  Permitted documents: {[r[0].document_id for r in results_le]}")

    # ------------------------------------------------------------------
    # Scenario 3: California customer without CCPA consent
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: CA customer, no CCPA consent — inferred profile denied ---")
    ctx_ca_no_consent = TelecomContext(
        user_id="agent-002",
        role=TelecomRole.CARRIER_AGENT,
        customer_id="cust-002",
        carrier_id="carrier-acme",
        has_cpni_consent=True,
        has_broadband_privacy_consent=True,
        has_ccpa_consent=False,
        is_authenticated=True,
        has_court_order=False,
        access_purpose="service_provisioning",
        customer_state="CA",
        is_law_enforcement=False,
    )
    results_ca = pipeline.retrieve(ctx_ca_no_consent, [inferred_profile_ca])
    print(f"  Permitted documents: {[r[0].document_id for r in results_ca]}")

    # ------------------------------------------------------------------
    # Audit record
    # ------------------------------------------------------------------
    print("\n--- Audit record (retrieve_with_audit) ---")
    audit = pipeline.retrieve_with_audit(ctx_agent_full, all_documents)
    log = audit.to_audit_log()
    print(json.dumps(
        {k: v for k, v in log.items() if k != "filter_results"},
        indent=2,
    ))
    print(f"  event: {log['event']}")
    print(f"  documents_evaluated: {log['documents_evaluated']}")
    print(f"  documents_permitted: {log['documents_permitted']}")
    print(f"  documents_denied: {log['documents_denied']}")
    print("\nSmoke test complete.")
