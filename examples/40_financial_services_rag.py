"""
US Financial Services RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms subject to US financial services regulations.  Four independent
filter layers run sequentially; a document must pass all four to be
returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | Swap data repository access and reporting platforms      | Dodd-Frank §728 — 12 U.S.C. §5301        |
  | FSOC-designated SIFI monitoring systems                  | Dodd-Frank §113 — 12 U.S.C. §5323        |
  | Proprietary trading compliance platforms                 | Dodd-Frank §619 Volcker Rule              |
  | Consumer financial data analytics systems                | SEC Reg. S-P — 17 CFR Part 248            |
  | Cybersecurity incident response platforms                | SEC §229.106 — 17 CFR §229.106            |
  | FINRA member firm communication archiving                | FINRA Rule 2210                           |
  | Order management and trade surveillance systems          | FINRA Rule 3110                           |
  | Business continuity management platforms                 | FINRA Rule 4370                           |
  | Foreign account tax compliance platforms                 | FATCA — 26 U.S.C. §1471–1474             |
  | AML transaction monitoring systems                       | FinCEN — 31 CFR Part 1010                 |
  | Cross-border EU financial data transfer platforms        | EU GDPR Art. 46 + DORA (EU 2022/2554)    |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — DoddFrankFilter
      (Dodd-Frank Wall Street Reform and Consumer Protection Act
       12 U.S.C. §5301 et seq., enacted July 21, 2010)
      Controls access to documents containing swap data, FSOC-designated
      systemically important institution (SIFI) data, and proprietary
      trading records subject to the Volcker Rule.

      Dodd-Frank §728 (12 U.S.C. §5318; CFTC 17 CFR Part 49): Swap data
      repository access requires regulatory authorization.  Documents
      containing swap data without confirmed regulator access authorization
      are denied.

      Dodd-Frank §113 (12 U.S.C. §5323): FSOC-designated systemically
      important financial institutions require enhanced prudential oversight
      documentation.  Documents flagged as systemically important without
      confirmed FSOC oversight documentation are escalated to
      REQUIRES_HUMAN_REVIEW.

      Dodd-Frank §619 (12 U.S.C. §1851; 12 CFR §248 — Volcker Rule):
      Proprietary trading is prohibited for covered banking entities.
      Documents containing proprietary trading data without a documented
      compliance program are denied.

  Layer 2 — SECRegulationSPFilter
      (SEC Regulation S-P: Privacy of Consumer Financial Information
       17 CFR Part 248, and SEC Cybersecurity Disclosure Rule
       17 CFR §229.106)
      Controls access to documents containing nonpublic personal
      information (NPI) about financial consumers and material
      cybersecurity incident disclosures.

      17 CFR §248.4: Financial institutions subject to Regulation S-P must
      deliver an annual privacy notice to consumers before disclosing NPI
      to nonaffiliated third parties.  Documents containing NPI without
      confirmed privacy notice delivery are denied.

      17 CFR §248.7: Consumers must receive a clear and conspicuous opt-out
      notice and a reasonable opportunity to opt out before NPI is shared
      with nonaffiliated third parties.  Documents containing NPI without
      confirmed opt-out opportunity are denied.

      17 CFR §229.106 (SEC Cybersecurity Disclosure Rule, effective
      September 5, 2023): Public companies must disclose material
      cybersecurity incidents on Form 8-K within four business days of
      determining the incident is material.  Documents flagging material
      cybersecurity incidents without confirmed SEC disclosure are
      escalated to REQUIRES_HUMAN_REVIEW.

  Layer 3 — FINRAComplianceFilter
      (FINRA Rule 4370 — Business Continuity Plans;
       FINRA Rule 2210 — Communications with the Public;
       FINRA Rule 3110 — Supervision)
      Controls access to documents involving FINRA member firm
      communications, order data, and business continuity obligations.

      FINRA Rule 2210(b)(1): Customer communications must receive
      principal pre-approval or, for certain categories, post-use review
      by a registered principal.  Customer communications without
      principal approval are denied.

      FINRA Rule 3110: Member firms must establish and maintain a system
      to supervise the activities of each associated person.  Order
      handling and trading data without documented supervisory procedures
      are escalated to REQUIRES_HUMAN_REVIEW.

      FINRA Rule 4370: Each FINRA member firm must maintain a business
      continuity plan (BCP) reasonably designed to meet its obligations to
      customers and must file the plan with FINRA.  Documents flagged as
      requiring a BCP without one filed are denied.

  Layer 4 — FinancialServicesCrossBorderFilter
      (FATCA 26 U.S.C. §1471–1474; FinCEN AML 31 CFR Part 1010;
       OFAC SDN List 31 CFR Chapter V; EU GDPR Art. 46 +
       DORA EU 2022/2554 Art. 45)
      Controls cross-border financial data flows, FATCA reporting
      obligations, AML suspicious activity reporting, OFAC sanctions
      screening, and EU financial data transfer requirements.

      26 U.S.C. §1471–1474 (FATCA): Foreign account financial data
      involving US persons must be reported on IRS Form 8938 or FinCEN
      Form 114 (FBAR).  Documents containing FATCA-reportable data without
      confirmed IRS reporting are denied.

      31 CFR §1010.320 (FinCEN SAR Rule): Financial institutions must
      file a Suspicious Activity Report (SAR) within 30 days of detecting
      a suspicious transaction over $5,000.  Documents flagging suspicious
      activity without a filed SAR are denied.

      31 CFR Chapter V (OFAC SDN List): Financial data transfers to
      OFAC-sanctioned jurisdictions are prohibited under the Trading with
      the Enemy Act (50 U.S.C. §4301) and IEEPA (50 U.S.C. §1701).
      Documents involving destinations on the OFAC SDN list are denied.

      EU GDPR Art. 46 + DORA (EU 2022/2554) Art. 45: Cross-border
      transfers of EU financial data require Standard Contractual Clauses
      (SCCs) or equivalent safeguards.  Documents involving EU financial
      data without confirmed SCCs are escalated to REQUIRES_HUMAN_REVIEW.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FinancialServicesContext:
    """
    Carries all per-request attributes needed by the four US financial
    services regulatory filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    institution_type describes the requesting financial institution:
        "bank", "broker_dealer", "investment_adviser", "swap_dealer",
        "hedge_fund", "insurance_company", "fintech", "general"

    All boolean flags default to False to enforce a deny-by-default posture;
    callers must explicitly set flags that grant access.
    """

    institution_type: str
    is_broker_dealer: bool = False
    is_investment_adviser: bool = False
    has_swap_dealer_registration: bool = False


@dataclass(frozen=True)
class FinancialServicesDocument:
    """
    Immutable document descriptor carrying all attributes needed for US
    financial services regulatory compliance evaluation across the four
    filter layers.

    data_classification describes the sensitivity level:
        "public", "internal", "confidential", "restricted", "general"

    regulatory_scope lists applicable regulatory frameworks:
        ["dodd_frank", "reg_sp", "finra", "fatca", "fincen", "ofac"]
    """

    doc_id: str
    data_classification: str = "general"
    contains_pii: bool = False
    regulatory_scope: list = field(default_factory=list)

    # Layer 1 — Dodd-Frank fields
    swap_data: bool = False
    authorized_regulator_access: bool = False
    systemically_important: bool = False
    fsoc_oversight_documented: bool = False
    volcker_rule_applicable: bool = False
    proprietary_trading_data: bool = False
    compliance_program_documented: bool = False

    # Layer 2 — SEC Regulation S-P fields
    nonpublic_personal_information: bool = False
    privacy_notice_delivered: bool = False
    opt_out_opportunity: bool = False
    material_cybersecurity_incident: bool = False
    sec_4day_disclosure_made: bool = False

    # Layer 3 — FINRA fields
    customer_communication: bool = False
    principal_approved: bool = False
    order_data: bool = False
    supervision_documented: bool = False
    bcp_required: bool = False
    bcp_filed_with_finra: bool = False

    # Layer 4 — Cross-border fields
    fatca_reportable: bool = False
    irs_reporting_completed: bool = False
    suspicious_activity: bool = False
    sar_filed: bool = False
    destination_country: str = ""
    eu_financial_data: bool = False
    scc_executed: bool = False


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: str  # "APPROVED", "DENIED", "REQUIRES_HUMAN_REVIEW"
    reason: str
    regulation_citation: str
    requires_logging: bool = True

    @property
    def is_denied(self) -> bool:
        """True only when the decision is DENIED.

        REQUIRES_HUMAN_REVIEW does not stop the pipeline.
        """
        return self.decision == "DENIED"


# ---------------------------------------------------------------------------
# Layer 1: DoddFrankFilter
#          Dodd-Frank Wall Street Reform and Consumer Protection Act
#          12 U.S.C. §5301 et seq., enacted July 21, 2010
# ---------------------------------------------------------------------------


class DoddFrankFilter:
    """
    Enforces Dodd-Frank Wall Street Reform and Consumer Protection Act
    requirements under 12 U.S.C. §5301 et seq.

    Dodd-Frank §728 (CFTC 17 CFR Part 49): Swap data repository access
    requires regulatory authorization from either the CFTC or SEC.
    Documents containing swap data without confirmed regulator access
    authorization are denied.

    Dodd-Frank §113 (12 U.S.C. §5323): The Financial Stability Oversight
    Council (FSOC) may designate nonbank financial companies as
    systemically important financial institutions (SIFIs) subject to
    enhanced prudential oversight by the Federal Reserve.  Documents
    flagged as systemically important without confirmed FSOC oversight
    documentation are escalated to REQUIRES_HUMAN_REVIEW.

    Dodd-Frank §619 (12 U.S.C. §1851 — Volcker Rule; 12 CFR §248):
    Banking entities are prohibited from engaging in proprietary trading
    and from acquiring or retaining ownership interests in hedge funds or
    private equity funds.  Documents containing proprietary trading data
    for entities subject to the Volcker Rule without a documented
    compliance program are denied.

    Documents that do not trigger any of the above conditions are approved
    under the general Dodd-Frank compliance framework.
    """

    LAYER_NAME = "DODD_FRANK"

    def evaluate(self, context: FinancialServicesContext, document: FinancialServicesDocument) -> FilterResult:
        """
        Evaluate Dodd-Frank requirements under 12 U.S.C. §5301 et seq.

        Evaluation order:
          1. Swap data without regulator authorization (§728) — DENIED.
          2. Systemically important institution without FSOC documentation
             (§113) — REQUIRES_HUMAN_REVIEW.
          3. Volcker Rule proprietary trading without compliance program
             (§619) — DENIED.
          4. Otherwise — APPROVED under Dodd-Frank Wall Street Reform Act.
        """
        # §728: Swap data repository access requires regulatory authorization.
        if document.swap_data and not document.authorized_regulator_access:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Dodd-Frank §728: Swap data repository access requires regulatory "
                    "authorization (CFTC 17 CFR Part 49)"
                ),
                regulation_citation="Dodd-Frank §728; CFTC 17 CFR Part 49",
            )

        # §113: FSOC-designated SIFIs require enhanced prudential oversight
        # documentation.
        if document.systemically_important and not document.fsoc_oversight_documented:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Dodd-Frank §113: FSOC-designated systemically important institutions "
                    "require enhanced prudential oversight documentation"
                ),
                regulation_citation="Dodd-Frank §113; 12 U.S.C. §5323",
            )

        # §619 (Volcker Rule): Proprietary trading requires documented compliance
        # program.
        if (
            document.volcker_rule_applicable
            and document.proprietary_trading_data
            and not document.compliance_program_documented
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Dodd-Frank §619 (Volcker Rule): Proprietary trading data requires "
                    "documented compliance program (12 CFR §248)"
                ),
                regulation_citation="Dodd-Frank §619; 12 CFR §248",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Dodd-Frank Wall Street Reform Act — compliant",
            regulation_citation="12 U.S.C. §5301",
        )


# ---------------------------------------------------------------------------
# Layer 2: SECRegulationSPFilter
#          SEC Regulation S-P: Privacy of Consumer Financial Information
#          17 CFR Part 248, and SEC Cybersecurity Disclosure Rule
#          17 CFR §229.106
# ---------------------------------------------------------------------------


class SECRegulationSPFilter:
    """
    Enforces SEC Regulation S-P (17 CFR Part 248) and the SEC Cybersecurity
    Disclosure Rule (17 CFR §229.106).

    17 CFR §248.4 (Regulation S-P — Initial and Annual Privacy Notice):
    Financial institutions must deliver an initial and annual privacy notice
    to customers before disclosing nonpublic personal information (NPI) to
    nonaffiliated third parties.  Documents containing NPI without confirmed
    privacy notice delivery are denied.

    17 CFR §248.7 (Regulation S-P — Opt-Out Notice): Consumers must receive
    a clear and conspicuous opt-out notice and a reasonable opportunity to
    opt out before NPI is shared with nonaffiliated third parties.
    Documents containing NPI without a confirmed opt-out opportunity are
    denied.

    17 CFR §229.106 (SEC Cybersecurity Disclosure Rule, effective
    September 5, 2023): Registrants must disclose material cybersecurity
    incidents on SEC Form 8-K within four business days of determining
    the incident is material.  Documents flagging material cybersecurity
    incidents without confirmed Form 8-K disclosure are escalated to
    REQUIRES_HUMAN_REVIEW.

    Documents that do not trigger any of the above conditions are approved
    under the general SEC Regulation S-P compliance framework.
    """

    LAYER_NAME = "SEC_REGULATION_SP"

    def evaluate(self, context: FinancialServicesContext, document: FinancialServicesDocument) -> FilterResult:
        """
        Evaluate SEC Regulation S-P and cybersecurity disclosure requirements.

        Evaluation order:
          1. NPI without privacy notice delivered (§248.4) — DENIED.
          2. NPI without opt-out opportunity (§248.7) — DENIED.
          3. Material cybersecurity incident without 4-day SEC disclosure
             (§229.106) — REQUIRES_HUMAN_REVIEW.
          4. Otherwise — APPROVED under SEC Regulation S-P 17 CFR Part 248.
        """
        # §248.4: NPI requires annual privacy notice before disclosure.
        if document.nonpublic_personal_information and not document.privacy_notice_delivered:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "17 CFR §248.4: NPI requires annual privacy notice before disclosure to nonaffiliated third parties"
                ),
                regulation_citation="17 CFR §248.4",
            )

        # §248.7: NPI requires opt-out notice before sharing with nonaffiliated
        # third parties.
        if document.nonpublic_personal_information and not document.opt_out_opportunity:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "17 CFR §248.7: Consumer must receive opt-out notice before NPI "
                    "shared with nonaffiliated third parties"
                ),
                regulation_citation="17 CFR §248.7",
            )

        # §229.106: Material cybersecurity incidents require SEC Form 8-K
        # disclosure within 4 business days.
        if document.material_cybersecurity_incident and not document.sec_4day_disclosure_made:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "17 CFR §229.106: Material cybersecurity incidents require "
                    "SEC Form 8-K disclosure within 4 business days"
                ),
                regulation_citation="17 CFR §229.106",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="SEC Regulation S-P 17 CFR Part 248 — compliant",
            regulation_citation="17 CFR Part 248",
        )


# ---------------------------------------------------------------------------
# Layer 3: FINRAComplianceFilter
#          FINRA Rule 4370 — Business Continuity Plans
#          FINRA Rule 2210 — Communications with the Public
#          FINRA Rule 3110 — Supervision
# ---------------------------------------------------------------------------


class FINRAComplianceFilter:
    """
    Enforces FINRA Rule 4370 (Business Continuity Plans), FINRA Rule 2210
    (Communications with the Public), and FINRA Rule 3110 (Supervision).

    FINRA Rule 2210(b)(1): All retail communications and correspondence
    with customers must receive principal pre-approval or post-use review
    by a registered principal.  Customer communications without principal
    approval are denied.

    FINRA Rule 3110: Each FINRA member firm must establish, maintain, and
    enforce written procedures to supervise the types of business in which
    it engages and the activities of its associated persons.  Order
    handling and trading data without documented supervisory procedures
    are escalated to REQUIRES_HUMAN_REVIEW.

    FINRA Rule 4370: Each FINRA member firm must maintain a business
    continuity plan (BCP) that is reasonably designed to meet its
    obligations to customers in the event of an emergency or significant
    business disruption.  Firms must also file their BCP or summary with
    FINRA.  Documents flagged as requiring a BCP without one filed with
    FINRA are denied.

    Documents that do not trigger any of the above conditions are approved
    under the general FINRA compliance framework.
    """

    LAYER_NAME = "FINRA_COMPLIANCE"

    def evaluate(self, context: FinancialServicesContext, document: FinancialServicesDocument) -> FilterResult:
        """
        Evaluate FINRA Rules 4370, 2210, and 3110 requirements.

        Evaluation order:
          1. Customer communication without principal approval
             (Rule 2210(b)(1)) — DENIED.
          2. Order data without supervision documented
             (Rule 3110) — REQUIRES_HUMAN_REVIEW.
          3. BCP required without BCP filed with FINRA
             (Rule 4370) — DENIED.
          4. Otherwise — APPROVED under FINRA Rules 4370/2210/3110.
        """
        # Rule 2210(b)(1): Customer communications require principal pre-approval.
        if document.customer_communication and not document.principal_approved:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "FINRA Rule 2210(b)(1): Customer communications require principal pre-approval or post-use review"
                ),
                regulation_citation="FINRA Rule 2210(b)(1)",
            )

        # Rule 3110: Order handling and trading data requires documented
        # supervisory procedures.
        if document.order_data and not document.supervision_documented:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=("FINRA Rule 3110: Order handling and trading data requires documented supervisory procedures"),
                regulation_citation="FINRA Rule 3110",
            )

        # Rule 4370: Member firms must maintain and file BCPs with FINRA.
        if document.bcp_required and not document.bcp_filed_with_finra:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=("FINRA Rule 4370: Member firms must maintain and file business continuity plans with FINRA"),
                regulation_citation="FINRA Rule 4370",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="FINRA Rules 4370/2210/3110 — compliant",
            regulation_citation="FINRA Rules 4370; 2210; 3110",
        )


# ---------------------------------------------------------------------------
# Layer 4: FinancialServicesCrossBorderFilter
#          FATCA 26 U.S.C. §1471–1474; FinCEN AML 31 CFR Part 1010;
#          OFAC SDN List 31 CFR Chapter V;
#          EU GDPR Art. 46 + DORA (EU 2022/2554) Art. 45
# ---------------------------------------------------------------------------


class FinancialServicesCrossBorderFilter:
    """
    Enforces cross-border financial data requirements under FATCA
    (26 U.S.C. §1471–1474), FinCEN AML rules (31 CFR Part 1010), the OFAC
    Specially Designated Nationals (SDN) List (31 CFR Chapter V), and EU
    financial data transfer requirements under GDPR Art. 46 and DORA
    (EU 2022/2554) Art. 45.

    26 U.S.C. §1471–1474 (FATCA): Foreign Account Tax Compliance Act
    requires foreign financial institutions and US persons to report
    foreign account data to the IRS on Form 8938 or FinCEN Form 114
    (FBAR).  Documents containing FATCA-reportable data without confirmed
    IRS reporting are denied.

    31 CFR §1010.320 (FinCEN SAR Rule): Financial institutions must file
    a Suspicious Activity Report (SAR) within 30 days of detecting a
    suspicious transaction involving $5,000 or more.  Documents flagging
    suspicious activity without a filed SAR are denied.

    31 CFR Chapter V (OFAC SDN List): Financial data transfers to
    OFAC-sanctioned jurisdictions (Russia, Iran, North Korea, Cuba,
    Syria) are prohibited under IEEPA (50 U.S.C. §1701) and the Trading
    with the Enemy Act (50 U.S.C. §4301).  Documents destined for
    sanctioned jurisdictions are denied.

    EU GDPR Art. 46 + DORA (EU 2022/2554) Art. 45: Cross-border transfers
    of EU financial data require Standard Contractual Clauses (SCCs) or
    equivalent safeguards under GDPR Art. 46.  DORA additionally imposes
    ICT risk management and oversight requirements for cross-border
    financial data.  Documents involving EU financial data without
    confirmed SCCs are escalated to REQUIRES_HUMAN_REVIEW.

    Documents that do not trigger any of the above conditions are approved
    under the general FATCA/FinCEN/OFAC cross-border compliance framework.
    """

    LAYER_NAME = "FINANCIAL_SERVICES_CROSS_BORDER"

    _OFAC_SANCTIONED_COUNTRIES = frozenset({"Russia", "Iran", "North Korea", "Cuba", "Syria"})

    def evaluate(self, context: FinancialServicesContext, document: FinancialServicesDocument) -> FilterResult:
        """
        Evaluate FATCA, FinCEN AML, OFAC, and EU cross-border requirements.

        Evaluation order:
          1. FATCA-reportable data without IRS reporting completed
             (26 U.S.C. §1471) — DENIED.
          2. Suspicious activity without SAR filed
             (31 CFR §1010.320) — DENIED.
          3. Destination country on OFAC SDN list
             (31 CFR Chapter V) — DENIED.
          4. EU financial data without SCCs executed
             (EU GDPR Art. 46 + DORA Art. 45) — REQUIRES_HUMAN_REVIEW.
          5. Otherwise — APPROVED under FATCA/FinCEN/OFAC framework.
        """
        # 26 U.S.C. §1471–1474 (FATCA): FATCA-reportable data requires IRS
        # Form 8938 or FBAR reporting.
        if document.fatca_reportable and not document.irs_reporting_completed:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "26 U.S.C. §1471-1474 FATCA: Foreign account financial data requires "
                    "IRS Form 8938 or FBAR reporting"
                ),
                regulation_citation="26 U.S.C. §1471-1474; 31 CFR §1010.350",
            )

        # 31 CFR §1010.320 (FinCEN SAR Rule): Suspicious transactions over $5,000
        # require SAR filing within 30 days.
        if document.suspicious_activity and not document.sar_filed:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=("31 CFR §1010.320: Suspicious transactions over $5,000 require SAR filing within 30 days"),
                regulation_citation="31 CFR §1010.320",
            )

        # 31 CFR Chapter V (OFAC SDN List): Financial data transfers to sanctioned
        # jurisdictions are prohibited.
        if document.destination_country in self._OFAC_SANCTIONED_COUNTRIES:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "OFAC SDN List / 31 CFR Chapter V: Financial data transfer to "
                    "OFAC-sanctioned jurisdictions prohibited"
                ),
                regulation_citation="31 CFR Chapter V; IEEPA 50 U.S.C. §1701",
            )

        # EU GDPR Art. 46 + DORA Art. 45: EU financial data requires SCCs for
        # cross-border transfer.
        if document.eu_financial_data and not document.scc_executed:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "EU GDPR Art. 46 + DORA (EU 2022/2554) Art. 45: EU financial data "
                    "cross-border transfer requires Standard Contractual Clauses"
                ),
                regulation_citation="EU GDPR Art. 46; DORA EU 2022/2554 Art. 45",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="FATCA/FinCEN/OFAC cross-border financial compliance — compliant",
            regulation_citation="26 U.S.C. §1471; 31 CFR Part 1010; 31 CFR Chapter V",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------


@dataclass
class FinancialServicesAuditRecord:
    """
    Captures the full decision trail for a Financial Services RAG retrieval
    event.

    This record should be persisted to an immutable audit log to satisfy:
      - Dodd-Frank swap data and Volcker Rule record-keeping obligations.
      - SEC Regulation S-P consumer financial privacy audit requirements.
      - FINRA Rule 4511 books-and-records retention obligations.
      - FinCEN AML program documentation requirements.
      - FATCA due-diligence and reporting record-keeping obligations.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping purposes.
    """

    event: str
    institution_type: str
    is_broker_dealer: bool
    is_investment_adviser: bool
    documents_in: int
    documents_out: int
    decisions: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": self.event,
            "institution_type": self.institution_type,
            "is_broker_dealer": self.is_broker_dealer,
            "is_investment_adviser": self.is_investment_adviser,
            "documents_in": self.documents_in,
            "documents_out": self.documents_out,
            "decisions": self.decisions,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class FinancialServicesRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for platforms subject
    to US financial services regulations.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW results do
    not stop the pipeline — those documents are included in the result set
    but flagged for human oversight.  Only documents that receive a DENIED
    result from any layer are excluded from the returned set.

    Layers in order:
      1. DoddFrankFilter                    — §728 swap data; §113 FSOC; §619 Volcker Rule
      2. SECRegulationSPFilter              — 17 CFR §248.4 NPI notice; §248.7 opt-out;
                                             §229.106 cybersecurity 4-day disclosure
      3. FINRAComplianceFilter              — Rule 2210(b)(1) communications;
                                             Rule 3110 supervision; Rule 4370 BCP
      4. FinancialServicesCrossBorderFilter — FATCA §1471; FinCEN §1010.320;
                                             OFAC SDN; GDPR Art. 46 + DORA Art. 45

    Audit records are generated for every retrieval event regardless of
    outcome, providing a complete access trail for SEC examination, FINRA
    audit, FinCEN AML program review, and internal compliance assessments.
    """

    def __init__(self) -> None:
        self._layers = [
            DoddFrankFilter(),
            SECRegulationSPFilter(),
            FINRAComplianceFilter(),
            FinancialServicesCrossBorderFilter(),
        ]

    def filter_documents(
        self,
        context: FinancialServicesContext,
        documents: list[FinancialServicesDocument],
    ) -> list[FinancialServicesDocument]:
        """
        Return a list of documents that pass (or are flagged but not denied by)
        all four filter layers.

        Documents denied on any layer are excluded from the result.  Documents
        that receive REQUIRES_HUMAN_REVIEW on any layer are included, as that
        decision does not constitute a denial.
        """
        permitted = []
        for doc in documents:
            allow = True
            for layer in self._layers:
                result = layer.evaluate(context, doc)
                if result.is_denied:
                    allow = False
                    break
            if allow:
                permitted.append(doc)
        return permitted

    def filter_documents_with_audit(
        self,
        context: FinancialServicesContext,
        documents: list[FinancialServicesDocument],
    ) -> FinancialServicesAuditRecord:
        """
        Evaluate all documents and return a FinancialServicesAuditRecord
        summarising the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support SEC
        examination, FINRA audit, FinCEN AML review, and internal compliance
        audit obligations.
        """
        documents_out = 0
        all_decisions: list[dict] = []

        for doc in documents:
            layer_results: list[dict] = []
            allow = True
            final_decision = "APPROVED"

            for layer in self._layers:
                result = layer.evaluate(context, doc)
                layer_results.append(
                    {
                        "layer": result.layer,
                        "decision": result.decision,
                        "reason": result.reason,
                        "regulation_citation": result.regulation_citation,
                    }
                )
                if result.is_denied:
                    allow = False
                    final_decision = "DENIED"
                    break
                if result.decision == "REQUIRES_HUMAN_REVIEW" and final_decision == "APPROVED":
                    final_decision = "REQUIRES_HUMAN_REVIEW"

            if allow:
                documents_out += 1

            all_decisions.append(
                {
                    "document_id": doc.doc_id,
                    "final_decision": final_decision,
                    "layer_results": layer_results,
                }
            )

        return FinancialServicesAuditRecord(
            event="FINANCIAL_SERVICES_RAG_RETRIEVAL",
            institution_type=context.institution_type,
            is_broker_dealer=context.is_broker_dealer,
            is_investment_adviser=context.is_investment_adviser,
            documents_in=len(documents),
            documents_out=documents_out,
            decisions=all_decisions,
        )


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("US Financial Services RAG Pipeline — Demo")
    print("=" * 70)

    pipeline = FinancialServicesRAGPipeline()

    # ------------------------------------------------------------------
    # Demo 1: Dodd-Frank §728 blocks swap data without regulator authorization
    # ------------------------------------------------------------------
    print("\n[Demo 1] Dodd-Frank §728 blocks swap data without regulator authorization")
    ctx_df = FinancialServicesContext(institution_type="swap_dealer", has_swap_dealer_registration=True)
    doc_df = FinancialServicesDocument(
        doc_id="swap-doc-001",
        data_classification="restricted",
        swap_data=True,
        authorized_regulator_access=False,
    )
    df_result = DoddFrankFilter().evaluate(ctx_df, doc_df)
    print(f"  Decision : {df_result.decision}")
    print(f"  Reason   : {df_result.reason}")
    print(f"  Citation : {df_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 2: SEC Reg. S-P blocks NPI without privacy notice
    # ------------------------------------------------------------------
    print("\n[Demo 2] SEC Reg. S-P blocks NPI without privacy notice (17 CFR §248.4)")
    ctx_sec = FinancialServicesContext(institution_type="bank", is_investment_adviser=False)
    doc_sec = FinancialServicesDocument(
        doc_id="npi-doc-001",
        data_classification="confidential",
        contains_pii=True,
        nonpublic_personal_information=True,
        privacy_notice_delivered=False,
        opt_out_opportunity=True,
    )
    sec_result = SECRegulationSPFilter().evaluate(ctx_sec, doc_sec)
    print(f"  Decision : {sec_result.decision}")
    print(f"  Reason   : {sec_result.reason}")
    print(f"  Citation : {sec_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 3: FINRA Rule 2210 blocks unapproved customer communication
    # ------------------------------------------------------------------
    print("\n[Demo 3] FINRA Rule 2210(b)(1) blocks unapproved customer communication")
    ctx_finra = FinancialServicesContext(institution_type="broker_dealer", is_broker_dealer=True)
    doc_finra = FinancialServicesDocument(
        doc_id="comm-doc-001",
        data_classification="internal",
        customer_communication=True,
        principal_approved=False,
    )
    finra_result = FINRAComplianceFilter().evaluate(ctx_finra, doc_finra)
    print(f"  Decision : {finra_result.decision}")
    print(f"  Reason   : {finra_result.reason}")
    print(f"  Citation : {finra_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 4: FinCEN blocks suspicious activity without SAR
    # ------------------------------------------------------------------
    print("\n[Demo 4] FinCEN §1010.320 blocks suspicious activity without SAR")
    ctx_fincen = FinancialServicesContext(institution_type="bank")
    doc_fincen = FinancialServicesDocument(
        doc_id="sar-doc-001",
        data_classification="restricted",
        suspicious_activity=True,
        sar_filed=False,
    )
    fincen_result = FinancialServicesCrossBorderFilter().evaluate(ctx_fincen, doc_fincen)
    print(f"  Decision : {fincen_result.decision}")
    print(f"  Reason   : {fincen_result.reason}")
    print(f"  Citation : {fincen_result.regulation_citation}")

    # ------------------------------------------------------------------
    # Demo 5: Full pipeline — compliant general document passes all layers
    # ------------------------------------------------------------------
    print("\n[Demo 5] Full pipeline — compliant document passes all four layers")
    ctx_compliant = FinancialServicesContext(
        institution_type="bank",
        is_broker_dealer=False,
        is_investment_adviser=False,
        has_swap_dealer_registration=False,
    )
    docs_compliant = [
        FinancialServicesDocument(
            doc_id="clean-doc-001",
            data_classification="general",
        ),
        FinancialServicesDocument(
            doc_id="clean-doc-002",
            data_classification="internal",
        ),
    ]
    result_compliant = pipeline.filter_documents(ctx_compliant, docs_compliant)
    print(f"  Documents in  : {len(docs_compliant)}")
    print(f"  Documents out : {len(result_compliant)}")
    print(f"  All passed    : {len(result_compliant) == len(docs_compliant)}")

    # ------------------------------------------------------------------
    # Demo 6: OFAC blocks transfer to sanctioned jurisdiction
    # ------------------------------------------------------------------
    print("\n[Demo 6] OFAC SDN List blocks financial data transfer to Iran")
    ctx_ofac = FinancialServicesContext(institution_type="bank")
    doc_ofac = FinancialServicesDocument(
        doc_id="ofac-doc-001",
        data_classification="confidential",
        destination_country="Iran",
    )
    ofac_result = FinancialServicesCrossBorderFilter().evaluate(ctx_ofac, doc_ofac)
    print(f"  Decision : {ofac_result.decision}")
    print(f"  Reason   : {ofac_result.reason}")
    print(f"  Citation : {ofac_result.regulation_citation}")
