"""
Financial Services RAG Pipeline — Four-Layer Defense-in-Depth

This module implements a compliance-aware RAG retrieval pipeline for financial
services platforms. Four independent filter layers run sequentially; a document
must pass all four to be returned to the caller.

Regulatory frameworks enforced:

  Layer 1 — Gramm-Leach-Bliley Act (GLBA) Title V (15 USC §§ 6801–6809)
      The GLBA Privacy Rule requires financial institutions to protect the
      Non-Public Personal Information (NPI) of consumers and customers.
      Section 6801 establishes the obligation to protect customer information;
      Section 6802 restricts disclosure of NPI to affiliated and non-affiliated
      third parties and gives customers the right to opt out of certain sharing.
      Section 6809 defines "nonpublic personal information" as any personally
      identifiable financial information (account numbers, transaction history,
      income, credit) that is not publicly available.  The Safeguard Rule
      (§ 6801(b)) requires a written information security program.

  Layer 2 — SEC Regulation S-P (17 CFR Part 248)
      Regulation S-P (Privacy of Consumer Financial Information and Safeguarding
      Personal Information) implements GLBA for SEC-registered broker-dealers,
      investment advisers, and investment companies.  Section 248.10 restricts
      disclosure of NPI to non-affiliated third parties.  Section 248.30 (the
      Safeguard Rule) requires a written program to protect customer records and
      information.  Section 248.15 exempts disclosures required by law and
      disclosures made to regulators in the course of an examination.

  Layer 3 — FINRA Rule 3110 (Supervision)
      FINRA Rule 3110 requires broker-dealers to establish, maintain, and enforce
      a system to supervise the activities of associated persons.  Rule 3110(a)
      requires each member to designate a registered principal at each OSJ and
      branch office.  Rule 3110(b) requires Written Supervisory Procedures (WSPs)
      to be kept current.  Supervisory records, correspondence review logs, and
      account activity must be accessible to licensed principals and compliance
      officers with current WSPs; access without proper supervisory designation
      is non-compliant.

  Layer 4 — Bank Secrecy Act (BSA) / Anti-Money Laundering (AML)
      31 USC § 5318(g)(2) (the "tipping-off prohibition") makes it unlawful for
      any financial institution or its employees to notify a person involved in
      a transaction that a Suspicious Activity Report (SAR) has been filed with
      respect to that transaction.  This prohibition applies even to the subject
      of the SAR.  31 CFR § 1010.311 governs Currency Transaction Report (CTR)
      filing requirements.  AML investigation materials are separately protected
      as law enforcement sensitive and restricted to compliance and regulatory
      access.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FinancialRole(Enum):
    REGISTERED_REPRESENTATIVE = "registered_representative"
    COMPLIANCE_OFFICER = "compliance_officer"
    CUSTOMER = "customer"
    BRANCH_MANAGER = "branch_manager"
    INTERNAL_AUDITOR = "internal_auditor"
    EXTERNAL_AUDITOR = "external_auditor"
    REGULATOR = "regulator"
    ADMIN = "admin"


class NPICategory(Enum):
    """Non-Public Personal Information categories under GLBA."""
    ACCOUNT_INFORMATION = "account_information"
    TRANSACTION_HISTORY = "transaction_history"
    CREDIT_INFORMATION = "credit_information"
    INCOME_ASSETS = "income_assets"
    NOT_NPI = "not_npi"


class FinancialDecision(Enum):
    PERMITTED = "permitted"
    DENIED = "denied"
    REDACTED = "redacted"


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FinancialServicesContext:
    """
    Carries all per-request attributes needed by the four filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorization state.
    """

    user_id: str
    user_role: FinancialRole
    customer_id: str                    # Which customer's records are being requested
    account_id: str                     # Specific account referenced in the request
    is_same_customer: bool              # The requesting user IS the customer whose records are requested
    glba_opt_out_honored: bool          # Customer has opted out and that choice is respected
    affiliate_sharing_authorized: bool  # Customer has authorized affiliate sharing
    is_affiliated_institution: bool     # The requestor is an affiliated company / subsidiary
    has_safeguard_controls: bool        # Reg S-P Safeguard Rule compliance controls in place
    finra_wsp_current: bool             # FINRA Written Supervisory Procedures are current
    is_licensed_principal: bool         # Branch manager / principal with supervisory authority
    sar_access_authorized: bool         # SAR access authorized (senior compliance or law enforcement)
    ctr_review_authorized: bool         # CTR (Currency Transaction Report) review authorized
    is_law_enforcement: bool            # Law enforcement with proper legal process
    is_audit_access: bool               # Formal audit or regulatory examination access


@dataclass(frozen=True)
class FinancialDocument:
    """
    Immutable document descriptor carrying attributes needed for compliance
    evaluation across all four filter layers.
    """

    document_id: str
    npi_category: NPICategory           # What category of NPI this document contains
    customer_id: str                    # Whose NPI this document belongs to
    is_sar: bool                        # Whether this is a Suspicious Activity Report
    is_ctr: bool                        # Whether this is a Currency Transaction Report
    contains_aml_investigation: bool    # Whether this document contains AML investigation materials
    is_public: bool                     # Whether this document is publicly available


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FinancialFilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: FinancialDecision = FinancialDecision.PERMITTED
    reason: str = ""
    conditions: list = field(default_factory=list)

    @property
    def is_denied(self) -> bool:
        return self.decision == FinancialDecision.DENIED


# ---------------------------------------------------------------------------
# Layer 1: GLBAPrivacyFilter (Gramm-Leach-Bliley Act Title V)
# ---------------------------------------------------------------------------

class GLBAPrivacyFilter:
    """
    Enforces GLBA Title V privacy obligations (15 USC §§ 6801–6809).

    The GLBA Privacy Rule restricts when a financial institution may disclose
    a customer's NPI to affiliated and non-affiliated third parties.  The core
    obligations are:

      - Section 6801(b): Institutions must maintain a written safeguard program.
      - Section 6802(a): Affiliated sharing requires prior notice.
      - Section 6802(b): Non-affiliated third-party disclosure is prohibited
        unless the customer receives notice and an opportunity to opt out, and
        has not done so.
      - Section 6802(b)(2): Affiliate sharing without customer authorization
        or where the customer has opted out is prohibited.
      - Section 6809: NPI includes account numbers, transaction histories,
        income, credit information — anything not publicly available.

    Exemptions apply for: the customer's own records; regulatory examinations;
    compliance with applicable law; audit by an accountant; and securitization
    or other transaction-processing purposes with appropriate contractual
    confidentiality controls.
    """

    LAYER_NAME = "GLBA_TITLE_V_PRIVACY"

    def evaluate(
        self, context: FinancialServicesContext, document: FinancialDocument
    ) -> FinancialFilterResult:
        """
        Evaluate whether the requesting context has authorization to access
        the document under GLBA Title V.

        Returns a FinancialFilterResult with PERMITTED or DENIED together with
        the operative GLBA finding or condition.
        """
        # Publicly available documents carry no GLBA restriction.
        if document.is_public:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Publicly available document — GLBA Title V does not restrict access",
            )

        # Not NPI — no GLBA privacy obligation attaches.
        if document.npi_category == NPICategory.NOT_NPI:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Document does not contain NPI — GLBA Title V does not apply",
            )

        # Customer accessing their own NPI — always permitted.
        # GLBA §6802 restricts disclosure TO third parties, not access by the
        # subject consumer.  Annual privacy notice is still required.
        if context.is_same_customer:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="GLBA: Customer accessing own NPI — permitted under Title V",
                conditions=[
                    "GLBA: Customer accessing own NPI — annual privacy notice required"
                ],
            )

        # Regulators conducting examinations — exempt from normal privacy rules.
        if context.user_role == FinancialRole.REGULATOR:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="GLBA: Regulatory examination access — statutory exemption applies",
                conditions=[
                    "GLBA: Regulatory examination access — standard privacy protections "
                    "suspended for exam"
                ],
            )

        # Compliance officer with Safeguard Rule controls in place — permitted
        # under the institution's own internal oversight program.
        if (
            context.user_role == FinancialRole.COMPLIANCE_OFFICER
            and context.has_safeguard_controls
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="GLBA §6801: Compliance officer access with Safeguard Rule controls",
                conditions=[
                    "GLBA §6801: Safeguard Rule controls verified — NPI access logged"
                ],
            )

        # Internal auditor with formal audit access — exempt as part of the
        # institution's own oversight function.
        if (
            context.user_role == FinancialRole.INTERNAL_AUDITOR
            and context.is_audit_access
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="GLBA: Internal audit access — institution oversight function",
                conditions=[
                    "GLBA: Internal audit access — confidentiality protocols apply"
                ],
            )

        # External auditor with formal audit engagement — permitted under
        # contractual confidentiality obligations per §6802(e).
        if (
            context.user_role == FinancialRole.EXTERNAL_AUDITOR
            and context.is_audit_access
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="GLBA: External auditor access — §6802(e) exception applies",
                conditions=[
                    "GLBA: External auditor access under contractual confidentiality"
                ],
            )

        # Affiliated institution with customer authorization — permitted.
        if context.is_affiliated_institution and context.affiliate_sharing_authorized:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="GLBA §6802(a): Affiliate sharing with customer authorization",
                conditions=[
                    "GLBA §6802(a): Affiliate sharing authorized — opt-out honored"
                ],
            )

        # Affiliated institution WITHOUT customer authorization — denied.
        # §6802(b)(2) prohibits affiliate sharing where the customer has not
        # consented or has elected to opt out.
        if context.is_affiliated_institution and not context.affiliate_sharing_authorized:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.DENIED,
                reason=(
                    "GLBA §6802(b)(2): Affiliate sharing requires customer authorization "
                    "— opt-out election must be respected"
                ),
            )

        # Non-affiliated third party where the customer has not opted out AND
        # the opt-out status has not been properly honored — denied.
        non_privileged_roles = {
            FinancialRole.COMPLIANCE_OFFICER,
            FinancialRole.INTERNAL_AUDITOR,
            FinancialRole.EXTERNAL_AUDITOR,
            FinancialRole.REGULATOR,
        }
        if not context.glba_opt_out_honored and context.user_role not in non_privileged_roles:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.DENIED,
                reason=(
                    "GLBA §6802(b): Customer opt-out election must be honored before "
                    "NPI disclosure to non-affiliated third parties"
                ),
            )

        # Registered representative accessing the account of the customer they
        # service — permitted under the account administration exception.
        if context.user_role == FinancialRole.REGISTERED_REPRESENTATIVE and context.is_same_customer:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="GLBA: Account servicing exception for registered representative",
                conditions=[
                    "GLBA: Account servicing exception — NPI access for account administration"
                ],
            )

        # Default: NPI disclosure requires customer authorization or a
        # recognized statutory exception.  Deny to protect consumer privacy.
        return FinancialFilterResult(
            layer=self.LAYER_NAME,
            decision=FinancialDecision.DENIED,
            reason=(
                "GLBA Title V: NPI disclosure requires customer authorization or "
                "applicable exception"
            ),
        )


# ---------------------------------------------------------------------------
# Layer 2: SECRegSPFilter (SEC Regulation S-P, 17 CFR Part 248)
# ---------------------------------------------------------------------------

class SECRegSPFilter:
    """
    Enforces SEC Regulation S-P (17 CFR Part 248) privacy and safeguard rules.

    Reg S-P applies to SEC-registered broker-dealers, investment advisers, and
    investment companies.  Its two core obligations are:

      - §248.10 (Privacy Rule): Restricts disclosure of NPI to non-affiliated
        third parties; requires delivery of privacy notices; adopts the GLBA
        opt-out framework for broker-dealers and advisers.
      - §248.30 (Safeguard Rule): Requires every covered institution to adopt
        written policies and procedures that address administrative, technical,
        and physical safeguards for customer records and information.
      - §248.15: Exempts disclosures required by law or regulation, including
        responses to SEC and FINRA examinations.

    A covered institution that lacks a written safeguard program fails Reg S-P
    at the gate, regardless of the requesting user's role.  All access by
    broker-dealer personnel is subject to the safeguard program's logging and
    access-control requirements.
    """

    LAYER_NAME = "SEC_REG_SP"

    def evaluate(
        self, context: FinancialServicesContext, document: FinancialDocument
    ) -> FinancialFilterResult:
        """
        Evaluate whether the requesting context satisfies Reg S-P requirements
        for the given document.

        Returns a FinancialFilterResult with PERMITTED or DENIED together with
        the operative Reg S-P section finding or condition.
        """
        # Public documents are not NPI and Reg S-P does not restrict access.
        if document.is_public:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Public document — Reg S-P does not restrict access",
            )

        # Document contains no NPI — Reg S-P privacy rule does not apply.
        if document.npi_category == NPICategory.NOT_NPI:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Document does not contain NPI — Reg S-P §248.10 does not apply",
            )

        # Customer self-access — not a regulated disclosure.
        if context.is_same_customer:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Reg S-P: Customer self-access permitted",
                conditions=[
                    "Reg S-P: Customer self-access permitted"
                ],
            )

        # Regulators (SEC, FINRA examiners) — §248.15 exemption for
        # disclosures required by applicable law during an examination.
        if context.user_role == FinancialRole.REGULATOR:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Reg S-P §248.15: Regulatory examination exemption applies",
                conditions=[
                    "Reg S-P §248.15: SEC/FINRA examination — records access required"
                ],
            )

        # Safeguard controls are a precondition for ALL non-regulatory access.
        # A missing safeguard program blocks all NPI access under §248.30.
        if not context.has_safeguard_controls:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.DENIED,
                reason=(
                    "Reg S-P §248.30: Safeguard Rule — written program to protect "
                    "customer records and information required"
                ),
            )

        # Registered representative and branch manager — have safeguard controls
        # (verified above); permitted for account servicing under the safeguard program.
        if context.user_role in {
            FinancialRole.REGISTERED_REPRESENTATIVE,
            FinancialRole.BRANCH_MANAGER,
        }:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Reg S-P: Broker-dealer personnel with safeguard program in effect",
                conditions=[
                    "Reg S-P: Broker-dealer personnel access — safeguard program applies"
                ],
            )

        # Compliance officer — oversight access within the safeguard program.
        if context.user_role == FinancialRole.COMPLIANCE_OFFICER:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Reg S-P §248.30: Compliance officer safeguard program oversight",
                conditions=[
                    "Reg S-P §248.30: Compliance officer access — safeguard program oversight"
                ],
            )

        # Internal or external auditor with formal audit access — permitted
        # within the safeguard program's contractual controls.
        if context.user_role in {
            FinancialRole.INTERNAL_AUDITOR,
            FinancialRole.EXTERNAL_AUDITOR,
        } and context.is_audit_access:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Reg S-P: Audit access within safeguard program controls",
                conditions=[
                    "Reg S-P: Audit access under safeguard program"
                ],
            )

        # Default: NPI disclosure to non-affiliated parties restricted to
        # permitted purposes enumerated in §248.10.
        return FinancialFilterResult(
            layer=self.LAYER_NAME,
            decision=FinancialDecision.DENIED,
            reason=(
                "Reg S-P §248.10: Non-public personal information disclosure "
                "restricted to permitted purposes"
            ),
        )


# ---------------------------------------------------------------------------
# Layer 3: FINRASupervisionFilter (FINRA Rule 3110)
# ---------------------------------------------------------------------------

class FINRASupervisionFilter:
    """
    Enforces FINRA Rule 3110 supervision requirements.

    FINRA Rule 3110 requires broker-dealers to establish, maintain, and enforce
    a supervisory system for the activities of associated persons.  Key provisions:

      - Rule 3110(a): Each member must designate a registered principal at each
        OSJ and branch office with responsibility for supervising the activities
        of the office.  Only a licensed principal may exercise supervisory authority.
      - Rule 3110(b): Members must maintain WSPs that are current and reasonably
        designed to achieve compliance with applicable securities laws.  Access to
        supervisory records requires that WSPs be up to date.
      - Rule 3110(c): Records of supervisory review must be maintained per FINRA
        Rule 4511 and made available to FINRA examiners on request.

    SAR and AML investigation documents are handled by Layer 4 (BSA/AML), but
    this layer still gates access to routine supervisory records.
    """

    LAYER_NAME = "FINRA_RULE_3110_SUPERVISION"

    def evaluate(
        self, context: FinancialServicesContext, document: FinancialDocument
    ) -> FinancialFilterResult:
        """
        Evaluate whether the requesting context satisfies FINRA Rule 3110
        supervisory access requirements for the document.

        Returns a FinancialFilterResult with PERMITTED or DENIED together with
        the operative FINRA Rule 3110 finding or condition.
        """
        # Public documents — not supervisory records; no Rule 3110 restriction.
        if document.is_public:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Public document — FINRA Rule 3110 does not restrict access",
            )

        # Non-NPI documents that are not SAR or AML materials pass through.
        # SAR and AML documents are handled by Layer 4; this layer does not
        # double-gate them except to ensure supervisory prerequisites are met.
        if (
            document.npi_category == NPICategory.NOT_NPI
            and not document.is_sar
            and not document.contains_aml_investigation
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Non-NPI, non-SAR, non-AML document — FINRA Rule 3110 does not restrict",
            )

        # Regulators (FINRA, SEC examiners) — full supervisory records available
        # during examination; Rule 3110(c) requires member cooperation.
        if context.user_role == FinancialRole.REGULATOR:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="FINRA Rule 3110: Regulatory examination — supervisory records required",
                conditions=[
                    "FINRA Rule 3110: Regulatory access — full supervisory records "
                    "available for examination"
                ],
            )

        # Compliance officer with current WSPs — Rule 3110(b) oversight access.
        if (
            context.user_role == FinancialRole.COMPLIANCE_OFFICER
            and context.finra_wsp_current
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="FINRA Rule 3110(b): Compliance officer with current WSPs",
                conditions=[
                    "FINRA Rule 3110(b): Compliance review — WSP current and in effect"
                ],
            )

        # Branch manager or compliance officer without current WSPs — denied.
        # Rule 3110(b) requires procedures to be current; stale WSPs are a
        # compliance violation that blocks supervisory access.
        if not context.finra_wsp_current and context.user_role in {
            FinancialRole.BRANCH_MANAGER,
            FinancialRole.COMPLIANCE_OFFICER,
        }:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.DENIED,
                reason=(
                    "FINRA Rule 3110(b): Written Supervisory Procedures not current "
                    "— update WSPs before accessing supervisory records"
                ),
            )

        # Branch manager who is a licensed principal — Rule 3110(a) permits
        # supervisory review of correspondence and account activity.
        if (
            context.user_role == FinancialRole.BRANCH_MANAGER
            and context.is_licensed_principal
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="FINRA Rule 3110(a): Licensed principal supervisory access",
                conditions=[
                    "FINRA Rule 3110(a): Licensed principal supervisory access "
                    "— correspondence and account review authorized"
                ],
            )

        # Branch manager who is NOT a licensed principal — cannot exercise
        # supervisory authority per Rule 3110(a).
        if (
            context.user_role == FinancialRole.BRANCH_MANAGER
            and not context.is_licensed_principal
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.DENIED,
                reason=(
                    "FINRA Rule 3110(a): Branch manager must be registered principal "
                    "to conduct supervisory review"
                ),
            )

        # Registered representative accessing the account they service for the
        # same customer — permitted under the supervision of a licensed principal.
        if (
            context.user_role == FinancialRole.REGISTERED_REPRESENTATIVE
            and context.is_same_customer
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="FINRA: Representative accessing own supervised customer account",
                conditions=[
                    "FINRA: Representative access to own customer accounts under supervision"
                ],
            )

        # Customer accessing their own account records — FINRA Rule 3110 governs
        # broker-dealer supervision of associated persons, not the rights of
        # customers to access their own account information.  Pass through.
        if context.user_role == FinancialRole.CUSTOMER and context.is_same_customer:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason=(
                    "FINRA Rule 3110: Supervision rule governs associated persons — "
                    "customer self-access to own account records is not restricted"
                ),
            )

        # Default: supervisory access requires proper supervisory designation or
        # regulatory examination authority.
        return FinancialFilterResult(
            layer=self.LAYER_NAME,
            decision=FinancialDecision.DENIED,
            reason=(
                "FINRA Rule 3110: Access requires supervisory authorization or "
                "regulatory examination"
            ),
        )


# ---------------------------------------------------------------------------
# Layer 4: BSAAMLFilter (Bank Secrecy Act — SAR Confidentiality)
# ---------------------------------------------------------------------------

class BSAAMLFilter:
    """
    Enforces BSA/AML confidentiality requirements, primarily the SAR tipping-off
    prohibition under 31 USC § 5318(g)(2).

    Key BSA/AML provisions:

      - 31 USC § 5318(g)(2): The tipping-off prohibition.  Any financial
        institution, officer, director, or employee who discloses to any person
        involved in the transaction that a SAR has been filed is subject to
        criminal penalties.  This prohibition applies even if the requestor IS
        the subject of the SAR — the subject must not be informed that a report
        has been filed.
      - 31 CFR § 1010.311: Financial institutions must file a Currency Transaction
        Report (CTR) for cash transactions exceeding $10,000.  CTRs are law
        enforcement sensitive; access is restricted to compliance and regulators.
      - AML investigation materials are created in the context of financial crime
        detection and are confidential to compliance, law enforcement, and
        regulatory parties.

    This layer operates independently of the upstream three layers and will deny
    access to SAR documents for any user who is the subject of the SAR,
    regardless of what Layers 1–3 determined.
    """

    LAYER_NAME = "BSA_AML_SAR_CONFIDENTIALITY"

    def evaluate(
        self, context: FinancialServicesContext, document: FinancialDocument
    ) -> FinancialFilterResult:
        """
        Evaluate whether BSA/AML confidentiality rules bar the requesting context
        from accessing the document.

        Returns a FinancialFilterResult with PERMITTED or DENIED together with
        the operative BSA/AML provision and finding.

        Evaluation sequence:
          1. Public documents — always permitted at this layer.
          2. Non-SAR, non-CTR, non-AML documents — pass through.
          3. SAR documents — apply 31 USC § 5318(g)(2) tipping-off analysis.
          4. CTR documents — restrict to compliance and law enforcement.
          5. AML investigation materials — restrict to compliance, law enforcement,
             and regulators.
        """
        # Public documents are not BSA/AML sensitive.
        if document.is_public:
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Public document — BSA/AML confidentiality rules do not apply",
            )

        # Documents that are neither SARs, CTRs, nor AML investigation materials
        # pass through this layer without restriction.
        if (
            not document.is_sar
            and not document.contains_aml_investigation
            and not document.is_ctr
        ):
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.PERMITTED,
                reason="Document is not a SAR, CTR, or AML investigation — BSA layer does not restrict",
            )

        # ----------------------------------------------------------------
        # SAR handling — 31 USC § 5318(g)(2) tipping-off prohibition
        # ----------------------------------------------------------------
        if document.is_sar:
            # The tipping-off prohibition is absolute for the SAR subject.
            # Even if the customer is requesting their own records, disclosing
            # the existence of a SAR is prohibited under § 5318(g)(2).
            if context.is_same_customer:
                return FinancialFilterResult(
                    layer=self.LAYER_NAME,
                    decision=FinancialDecision.DENIED,
                    reason=(
                        "31 USC §5318(g)(2): SAR tipping-off prohibition — customer "
                        "may NOT be informed that a SAR has been filed"
                    ),
                )

            # Regulators and law enforcement — access to SAR is required for
            # examination and investigation; standard confidentiality maintained.
            if context.user_role == FinancialRole.REGULATOR or context.is_law_enforcement:
                return FinancialFilterResult(
                    layer=self.LAYER_NAME,
                    decision=FinancialDecision.PERMITTED,
                    reason="BSA: Regulator / law enforcement access to SAR authorized",
                    conditions=[
                        "31 USC §5318(g)(2): Law enforcement/regulator access to SAR "
                        "— standard confidentiality maintained"
                    ],
                )

            # Senior compliance officer with explicit SAR access authorization.
            if (
                context.user_role == FinancialRole.COMPLIANCE_OFFICER
                and context.sar_access_authorized
            ):
                return FinancialFilterResult(
                    layer=self.LAYER_NAME,
                    decision=FinancialDecision.PERMITTED,
                    reason="BSA: Senior compliance officer with SAR access authorization",
                    conditions=[
                        "BSA: Senior compliance officer SAR access authorized "
                        "— tipping-off prohibition strictly enforced"
                    ],
                )

            # Internal auditor with SAR access authorization and formal audit access.
            if (
                context.user_role == FinancialRole.INTERNAL_AUDITOR
                and context.sar_access_authorized
                and context.is_audit_access
            ):
                return FinancialFilterResult(
                    layer=self.LAYER_NAME,
                    decision=FinancialDecision.PERMITTED,
                    reason="BSA: Internal audit SAR access with authorization and formal audit scope",
                    conditions=[
                        "BSA: Internal audit SAR access — need-to-know basis only"
                    ],
                )

            # All other roles — SAR is strictly confidential.
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.DENIED,
                reason=(
                    "31 USC §5318(g)(2): SAR documents are strictly confidential "
                    "— access limited to law enforcement, regulators, and authorized "
                    "senior compliance"
                ),
            )

        # ----------------------------------------------------------------
        # CTR handling — 31 CFR § 1010.311
        # ----------------------------------------------------------------
        if document.is_ctr:
            # Compliance officers and regulators with explicit CTR review
            # authorization — FinCEN reporting compliance function.
            if context.user_role in {
                FinancialRole.REGULATOR,
                FinancialRole.COMPLIANCE_OFFICER,
            } and context.ctr_review_authorized:
                return FinancialFilterResult(
                    layer=self.LAYER_NAME,
                    decision=FinancialDecision.PERMITTED,
                    reason="BSA: CTR review authorized for compliance/regulator",
                    conditions=[
                        "BSA 31 CFR §1010.311: CTR review authorized — FinCEN reporting compliance"
                    ],
                )

            # Law enforcement — authorized to access CTR for investigation.
            if context.is_law_enforcement:
                return FinancialFilterResult(
                    layer=self.LAYER_NAME,
                    decision=FinancialDecision.PERMITTED,
                    reason="BSA: Law enforcement CTR access authorized",
                    conditions=[
                        "BSA: Law enforcement CTR access"
                    ],
                )

            # All other roles — CTR is restricted to compliance and law enforcement.
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.DENIED,
                reason=(
                    "BSA 31 CFR §1010.311: Currency Transaction Report access restricted "
                    "to compliance and law enforcement"
                ),
            )

        # ----------------------------------------------------------------
        # AML investigation materials
        # ----------------------------------------------------------------
        if document.contains_aml_investigation:
            # Compliance officers, regulators, and law enforcement — authorized
            # to access AML investigation materials; strict non-disclosure applies.
            if (
                context.user_role in {
                    FinancialRole.COMPLIANCE_OFFICER,
                    FinancialRole.REGULATOR,
                }
                or context.is_law_enforcement
            ):
                return FinancialFilterResult(
                    layer=self.LAYER_NAME,
                    decision=FinancialDecision.PERMITTED,
                    reason="BSA: AML investigation access for compliance/regulator/law enforcement",
                    conditions=[
                        "BSA: AML investigation access — confidentiality and non-disclosure maintained"
                    ],
                )

            # All other roles — AML investigation materials are confidential.
            return FinancialFilterResult(
                layer=self.LAYER_NAME,
                decision=FinancialDecision.DENIED,
                reason=(
                    "BSA: AML investigation materials — access restricted to compliance, "
                    "law enforcement, and regulators"
                ),
            )

        # Unreachable given the conditional structure above, but provide a safe
        # default that errs on the side of protection.
        return FinancialFilterResult(
            layer=self.LAYER_NAME,
            decision=FinancialDecision.DENIED,
            reason="BSA/AML: Unresolved document sensitivity state — access denied",
        )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class FinancialServicesRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for financial services.

    Each layer independently evaluates a document against the requesting context.
    The pipeline runs layers in sequence; the first DENIED result stops evaluation
    for that document.  Only documents that pass all four layers are returned.

    Layers in order:
      1. GLBAPrivacyFilter         — GLBA Title V NPI protection
      2. SECRegSPFilter            — SEC Regulation S-P safeguard rule
      3. FINRASupervisionFilter    — FINRA Rule 3110 supervisory access
      4. BSAAMLFilter              — BSA SAR/CTR/AML confidentiality

    Audit records are generated for every document regardless of outcome,
    providing a complete access trail for regulatory examination and compliance.
    """

    def __init__(self) -> None:
        self._layers = [
            GLBAPrivacyFilter(),
            SECRegSPFilter(),
            FINRASupervisionFilter(),
            BSAAMLFilter(),
        ]

    def retrieve(
        self,
        context: FinancialServicesContext,
        documents: list[FinancialDocument],
    ) -> list[FinancialDocument]:
        """
        Return the subset of documents that pass all four filter layers.

        Documents are evaluated independently; a denial on any layer
        causes the document to be excluded from the result set.
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

    def retrieve_with_audit(
        self,
        context: FinancialServicesContext,
        documents: list[FinancialDocument],
    ) -> tuple[list[FinancialDocument], list[FinancialAuditRecord]]:
        """
        Return permitted documents AND a full audit trail for every document.

        The audit trail captures the decision and per-layer results for each
        document regardless of whether it was ultimately permitted or denied.
        This supports regulatory examination and compliance reporting.
        """
        permitted: list[FinancialDocument] = []
        audit_records: list[FinancialAuditRecord] = []

        for doc in documents:
            layer_results: list[dict] = []
            allow = True
            final_decision = FinancialDecision.PERMITTED

            for layer in self._layers:
                result = layer.evaluate(context, doc)
                layer_results.append(
                    {
                        "layer": result.layer,
                        "decision": result.decision.value,
                        "reason": result.reason,
                        "conditions": result.conditions,
                    }
                )
                if result.is_denied:
                    allow = False
                    final_decision = FinancialDecision.DENIED
                    break

            if allow:
                permitted.append(doc)

            audit_records.append(
                FinancialAuditRecord(
                    user_id=context.user_id,
                    customer_id=context.customer_id,
                    account_id=context.account_id,
                    document_id=doc.document_id,
                    decision=final_decision,
                    layer_results=layer_results,
                )
            )

        return permitted, audit_records


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class FinancialAuditRecord:
    """
    Captures the full decision trail for a single RAG retrieval event.

    This record should be persisted to an immutable audit log for regulatory
    examination, internal audit, and compliance reporting purposes.  Under
    BSA record-keeping requirements, financial institutions must retain records
    of SAR-related access decisions for five years (31 CFR § 1010.430).
    """

    user_id: str
    customer_id: str
    account_id: str
    document_id: str
    decision: FinancialDecision
    layer_results: list          # Per-layer result dicts from retrieve_with_audit
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": "FINANCIAL_RAG_RETRIEVAL",
            "user_id": self.user_id,
            "customer_id": self.customer_id,
            "account_id": self.account_id,
            "document_id": self.document_id,
            "decision": self.decision.value,
            "layer_results": self.layer_results,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("=" * 70)
    print("Financial Services RAG Pipeline — Smoke Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Shared documents used across scenarios
    # ------------------------------------------------------------------

    npi_account_doc = FinancialDocument(
        document_id="doc-001-account-statement",
        npi_category=NPICategory.ACCOUNT_INFORMATION,
        customer_id="customer-jane-smith",
        is_sar=False,
        is_ctr=False,
        contains_aml_investigation=False,
        is_public=False,
    )

    sar_doc = FinancialDocument(
        document_id="doc-002-sar-filing",
        npi_category=NPICategory.TRANSACTION_HISTORY,
        customer_id="customer-jane-smith",
        is_sar=True,
        is_ctr=False,
        contains_aml_investigation=False,
        is_public=False,
    )

    ctr_doc = FinancialDocument(
        document_id="doc-003-currency-transaction-report",
        npi_category=NPICategory.TRANSACTION_HISTORY,
        customer_id="customer-jane-smith",
        is_sar=False,
        is_ctr=True,
        contains_aml_investigation=False,
        is_public=False,
    )

    public_prospectus = FinancialDocument(
        document_id="doc-004-public-prospectus",
        npi_category=NPICategory.NOT_NPI,
        customer_id="",
        is_sar=False,
        is_ctr=False,
        contains_aml_investigation=False,
        is_public=True,
    )

    all_documents = [npi_account_doc, sar_doc, ctr_doc, public_prospectus]

    pipeline = FinancialServicesRAGPipeline()

    # ------------------------------------------------------------------
    # Scenario 1: Compliance officer with safeguard controls accessing NPI
    # Expected: NPI account doc permitted; SAR permitted (with authorization);
    #           CTR permitted (with authorization); public prospectus permitted.
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: Compliance Officer with Full Authorization ---")

    compliance_context = FinancialServicesContext(
        user_id="user-compliance-officer-torres",
        user_role=FinancialRole.COMPLIANCE_OFFICER,
        customer_id="customer-jane-smith",
        account_id="acct-4892-7731",
        is_same_customer=False,
        glba_opt_out_honored=True,
        affiliate_sharing_authorized=False,
        is_affiliated_institution=False,
        has_safeguard_controls=True,
        finra_wsp_current=True,
        is_licensed_principal=False,
        sar_access_authorized=True,
        ctr_review_authorized=True,
        is_law_enforcement=False,
        is_audit_access=False,
    )

    permitted_docs, audit_records = pipeline.retrieve_with_audit(
        compliance_context, all_documents
    )

    print(
        f"  Context:  Compliance officer Torres — safeguard controls, WSP current, "
        f"SAR + CTR authorized"
    )
    print(f"  Documents submitted: {len(all_documents)}")
    print(f"  Documents permitted: {len(permitted_docs)}")
    for record in audit_records:
        layers_evaluated = len(record.layer_results)
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id} "
            f"({layers_evaluated} layer(s) evaluated)"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer']}: {lr['reason']}")
            for cond in lr.get("conditions", []):
                print(f"                    Condition: {cond}")

    assert len(permitted_docs) == 4, (
        f"Expected all 4 documents permitted for authorized compliance officer, "
        f"got {len(permitted_docs)}"
    )
    print(
        "  ASSERTION PASSED: All 4 documents permitted for compliance officer "
        "with full authorization."
    )

    # ------------------------------------------------------------------
    # Scenario 2: Customer accessing own NPI — permitted; same customer
    # accessing own SAR — denied by BSA tipping-off prohibition.
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Customer Accessing Own Records (SAR Tipping-Off Test) ---")

    customer_context = FinancialServicesContext(
        user_id="user-jane-smith",
        user_role=FinancialRole.CUSTOMER,
        customer_id="customer-jane-smith",
        account_id="acct-4892-7731",
        is_same_customer=True,
        glba_opt_out_honored=True,
        affiliate_sharing_authorized=False,
        is_affiliated_institution=False,
        has_safeguard_controls=True,
        finra_wsp_current=True,
        is_licensed_principal=False,
        sar_access_authorized=False,
        ctr_review_authorized=False,
        is_law_enforcement=False,
        is_audit_access=False,
    )

    permitted_customer, audit_customer = pipeline.retrieve_with_audit(
        customer_context, all_documents
    )

    print(
        "  Context:  Customer Jane Smith — is_same_customer=True; "
        "SAR/CTR access NOT authorized"
    )
    print(f"  Documents submitted: {len(all_documents)}")
    print(f"  Documents permitted: {len(permitted_customer)}")
    for record in audit_customer:
        layers_evaluated = len(record.layer_results)
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id} "
            f"({layers_evaluated} layer(s) evaluated)"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer']}: {lr['reason']}")
            for cond in lr.get("conditions", []):
                print(f"                    Condition: {cond}")

    # NPI account doc and public prospectus permitted; SAR denied (tipping-off);
    # CTR denied (not compliance or law enforcement).
    permitted_customer_ids = {d.document_id for d in permitted_customer}
    assert "doc-001-account-statement" in permitted_customer_ids, (
        "Expected NPI account doc permitted for customer accessing own records"
    )
    assert "doc-004-public-prospectus" in permitted_customer_ids, (
        "Expected public prospectus permitted for customer"
    )
    assert "doc-002-sar-filing" not in permitted_customer_ids, (
        "Expected SAR denied for customer — tipping-off prohibition"
    )
    assert "doc-003-currency-transaction-report" not in permitted_customer_ids, (
        "Expected CTR denied for customer — restricted to compliance and law enforcement"
    )
    print(
        "  ASSERTION PASSED: NPI + public permitted; SAR denied (tipping-off); "
        "CTR denied (restricted)."
    )

    # ------------------------------------------------------------------
    # Scenario 3: SAR — compliance officer with authorization permitted;
    #             customer denied (31 USC § 5318(g)(2)).
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: SAR Access — Compliance Officer vs. Customer ---")

    # Compliance officer — already tested in Scenario 1 (permitted).
    # Retrieve just the SAR document for focused output.
    sar_only = [sar_doc]

    permitted_compliance_sar, _ = pipeline.retrieve_with_audit(compliance_context, sar_only)
    permitted_customer_sar, _ = pipeline.retrieve_with_audit(customer_context, sar_only)

    print(
        f"  Compliance officer (sar_access_authorized=True): "
        f"{'PERMITTED' if permitted_compliance_sar else 'DENIED'}"
    )
    print(
        f"  Customer (is_same_customer=True):                "
        f"{'PERMITTED' if permitted_customer_sar else 'DENIED (tipping-off)'}"
    )

    assert len(permitted_compliance_sar) == 1, (
        "Expected SAR permitted for authorized compliance officer"
    )
    assert len(permitted_customer_sar) == 0, (
        "Expected SAR denied for customer — 31 USC §5318(g)(2) tipping-off prohibition"
    )
    print(
        "  ASSERTION PASSED: SAR permitted for compliance officer; "
        "denied for customer (tipping-off prohibition)."
    )

    # ------------------------------------------------------------------
    # Scenario 4: Affiliated institution without customer authorization
    #             — denied at GLBA Layer 1.
    # ------------------------------------------------------------------
    print("\n--- Scenario 4: Affiliated Institution Without Customer Authorization ---")

    affiliate_context = FinancialServicesContext(
        user_id="user-affiliate-bank-west",
        user_role=FinancialRole.REGISTERED_REPRESENTATIVE,
        customer_id="customer-jane-smith",
        account_id="acct-4892-7731",
        is_same_customer=False,
        glba_opt_out_honored=False,
        affiliate_sharing_authorized=False,   # No customer authorization
        is_affiliated_institution=True,        # This IS an affiliate
        has_safeguard_controls=True,
        finra_wsp_current=True,
        is_licensed_principal=False,
        sar_access_authorized=False,
        ctr_review_authorized=False,
        is_law_enforcement=False,
        is_audit_access=False,
    )

    permitted_affiliate, audit_affiliate = pipeline.retrieve_with_audit(
        affiliate_context, [npi_account_doc, public_prospectus]
    )

    print(
        "  Context:  Affiliated institution — is_affiliated_institution=True; "
        "affiliate_sharing_authorized=False"
    )
    print(f"  Documents submitted: 2 (NPI account doc + public prospectus)")
    print(f"  Documents permitted: {len(permitted_affiliate)}")
    for record in audit_affiliate:
        layers_evaluated = len(record.layer_results)
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id} "
            f"({layers_evaluated} layer(s) evaluated)"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer']}: {lr['reason']}")
            for cond in lr.get("conditions", []):
                print(f"                    Condition: {cond}")

    # NPI account doc must be denied at GLBA Layer 1 (§6802(b)(2));
    # public prospectus must still be permitted.
    permitted_affiliate_ids = {d.document_id for d in permitted_affiliate}
    assert "doc-001-account-statement" not in permitted_affiliate_ids, (
        "Expected NPI account doc denied for affiliate without customer authorization"
    )
    assert "doc-004-public-prospectus" in permitted_affiliate_ids, (
        "Expected public prospectus permitted even for unauthorized affiliate"
    )
    print(
        "  ASSERTION PASSED: NPI denied at GLBA Layer 1 (§6802(b)(2)); "
        "public prospectus permitted."
    )

    # ------------------------------------------------------------------
    # Scenario 5: Audit log output for compliance review
    # ------------------------------------------------------------------
    print("\n--- Scenario 5: Audit Log Output (first compliance officer record) ---")
    first_audit_record = audit_records[0]
    print(json.dumps(first_audit_record.to_audit_log(), indent=2))

    print("\n" + "=" * 70)
    print("All smoke tests passed.")
    print("=" * 70)
