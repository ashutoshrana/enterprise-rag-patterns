"""
US Real Estate / Proptech RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms operating in the US real estate sector.  Four independent filter
layers run sequentially; a document must pass all four to be returned to
the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | AI-assisted buyer/seller decision-support portals        | Fair Housing Act 42 U.S.C. §3604         |
  | Mortgage origination and credit underwriting systems     | ECOA 15 U.S.C. §1691 / Regulation B      |
  | Automated valuation model (AVM) platforms               | Dodd-Frank §1472 / USPAP Standards       |
  | Rental management and leasing platforms                  | CA Civil Code §1940.2                    |
  | Real estate agent / broker MLS search tools             | Fair Housing Act / HUD regulations       |
  | Title, escrow, and settlement service portals           | State real estate disclosure laws        |
  | Commercial real estate analytics platforms              | State property disclosure statutes       |
  | Proptech platforms serving multi-state markets          | NY RPL §462 / TX Property Code §5.008   |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — FairHousingActFilter (Fair Housing Act 42 U.S.C. §3604 + HUD regulations)
      Controls access to documents containing protected class data under the
      Fair Housing Act.

      42 U.S.C. §3604 prohibits discrimination in the sale or rental of
      housing based on race, color, national origin, religion, sex, familial
      status, or disability.  Protected class data — information that could
      enable or reveal discriminatory treatment — is restricted to regulatory
      and lending roles that have a bona fide compliance need.

      HUD Fair Housing Regulations require that personnel accessing protected
      class data have completed fair housing training to prevent inadvertent
      discriminatory use of the information.  Personnel without documented
      training are escalated to human review.

  Layer 2 — ECOALendingFilter (ECOA 15 U.S.C. §1691 + Regulation B 12 CFR §202)
      Controls access to documents used in credit decisions affecting real
      estate transactions.

      ECOA 15 U.S.C. §1691 prohibits discrimination in credit transactions
      and requires that applicants be notified of credit decisions.  Any
      credit decision involving real estate requires that the applicant
      receive the required ECOA notice before a determination is made.

      Regulation B 12 CFR §202 requires that when a lender takes adverse
      action on a credit application, the applicant must be provided with a
      written adverse action notice specifying the reasons for the decision.
      Retrieval of lending documents for an adverse decision without the
      required notice triggers human review escalation.

  Layer 3 — AppraisalIndependenceFilter (Dodd-Frank §1472 + USPAP Standards)
      Controls access to appraisal and automated valuation documents for
      real estate transactions.

      Dodd-Frank Act §1472 (codified at 15 U.S.C. §1639e) establishes
      appraisal independence requirements for federally related mortgage
      loans.  Automated valuation models (AVMs) used for purchase
      transactions must have human appraiser review to prevent conflicts of
      interest and ensure accuracy.

      Uniform Standards of Professional Appraisal Practice (USPAP) require
      that appraisal independence be maintained and that borrowers receive
      disclosure of the appraisal process.  Lender access to appraisal
      documents without required borrower disclosure is denied.

  Layer 4 — StateRealEstateLawFilter (state-specific real estate disclosure laws)
      Enforces state-level real estate disclosure requirements that vary
      by state.

      California Civil Code §1940.2 requires that landlords and property
      managers disclose known material defects before entering into a rental
      agreement.  Rental documents without the required disclosure trigger
      human review for California properties.

      New York Real Property Law §462 requires that sellers provide buyers
      with a property condition disclosure statement before transfer of
      residential property.  Purchase transaction documents without the
      required disclosure are denied for New York properties.

      Texas Property Code §5.008 requires sellers of residential real
      property to furnish buyers with a seller's disclosure notice before
      execution of a binding contract.  Purchase transaction documents
      involving a Texas seller without the required disclosure trigger
      human review.

      Other states default to a general state real estate disclosure law
      approval, as specific statutory requirements vary widely and are
      governed by state-level implementation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RealEstateContext:
    """
    Carries all per-request attributes needed by the four real estate filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    role describes the requesting party's position in the transaction:
        "buyer", "seller", "agent", "lender", "appraiser", "regulator"

    property_state is a 2-letter US state code (e.g. "CA", "NY", "TX").

    transaction_type describes the nature of the transaction:
        "purchase", "refinance", "rental", "commercial"
    """

    user_id: str
    role: str                           # "buyer", "seller", "agent", "lender", "appraiser", "regulator"
    property_state: str                 # US state code e.g. "CA", "NY", "TX"
    transaction_type: str               # "purchase", "refinance", "rental", "commercial"
    is_protected_class_data: bool = False
    has_fair_housing_training: bool = True
    involves_credit_decision: bool = False
    has_ecoa_notice: bool = False
    involves_appraisal: bool = False
    is_automated_valuation: bool = False
    has_disclosure: bool = True
    involves_rental: bool = False
    has_adverse_action_notice: bool = False


@dataclass(frozen=True)
class RealEstateDocument:
    """
    Immutable document descriptor carrying all attributes needed for real estate
    compliance evaluation across the four filter layers.

    doc_type describes the category of document:
        "property_record", "appraisal", "credit_report", "listing",
        "lease", "disclosure"
    """

    content: str
    document_id: str
    doc_type: str = "property_record"   # "appraisal", "credit_report", "listing", "lease", "disclosure"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: str               # "APPROVED", "DENIED", "REQUIRES_HUMAN_REVIEW"
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
# Layer 1: FairHousingActFilter — Fair Housing Act 42 U.S.C. §3604 + HUD regulations
# ---------------------------------------------------------------------------

class FairHousingActFilter:
    """
    Enforces Fair Housing Act requirements and HUD regulations for access to
    documents containing protected class data in real estate platforms.

    Fair Housing Act 42 U.S.C. §3604 prohibits discriminatory practices in
    the sale or rental of housing.  Protected class data — information that
    could enable or reveal discriminatory treatment based on race, color,
    national origin, religion, sex, familial status, or disability — is
    restricted to roles with a bona fide regulatory or compliance need.

    HUD Fair Housing Regulations require that personnel accessing protected
    class data have completed documented fair housing training.  Personnel
    without training are escalated for human review to prevent inadvertent
    discriminatory use of the information.
    """

    LAYER_NAME = "FAIR_HOUSING_ACT_HUD"

    _PROTECTED_CLASS_AUTHORIZED_ROLES = frozenset({"regulator", "lender"})

    def evaluate(self, context: RealEstateContext, document: RealEstateDocument) -> FilterResult:
        """
        Evaluate Fair Housing Act and HUD regulation requirements.

        Evaluation order:
          1. Protected class data + unauthorised role (§3604) — DENIED.
          2. Protected class data + no fair housing training (HUD) — REQUIRES_HUMAN_REVIEW.
          3. Otherwise — APPROVED.
        """
        # §3604: Protected class data restricted to regulator and lender roles.
        if (
            context.is_protected_class_data
            and context.role not in self._PROTECTED_CLASS_AUTHORIZED_ROLES
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "Fair Housing Act 42 U.S.C. §3604: Protected class data not "
                    "accessible for this role"
                ),
                regulation_citation="Fair Housing Act 42 U.S.C. §3604",
            )

        # HUD: Fair housing training required before accessing protected class data.
        if context.is_protected_class_data and not context.has_fair_housing_training:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "HUD Fair Housing Regulations: Fair housing training required "
                    "before accessing protected class data"
                ),
                regulation_citation="HUD Fair Housing Regulations",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Fair Housing Act access check passed",
            regulation_citation="Fair Housing Act 42 U.S.C. §3604",
        )


# ---------------------------------------------------------------------------
# Layer 2: ECOALendingFilter — ECOA 15 U.S.C. §1691 + Regulation B 12 CFR §202
# ---------------------------------------------------------------------------

class ECOALendingFilter:
    """
    Enforces Equal Credit Opportunity Act requirements for credit decisions
    in real estate transactions.

    ECOA 15 U.S.C. §1691 prohibits discrimination in any credit transaction
    and requires that the ECOA notice be provided to applicants.  Credit
    decisions involving real estate require the applicant to receive the
    required notice.

    Regulation B 12 CFR §202 requires written adverse action notices when
    a lender declines a credit application or takes other adverse action.
    Lender retrieval of lending documents for an adverse decision without the
    required written notice is escalated for human review.
    """

    LAYER_NAME = "ECOA_LENDING_REG_B"

    def evaluate(self, context: RealEstateContext, document: RealEstateDocument) -> FilterResult:
        """
        Evaluate ECOA and Regulation B requirements for credit-related access.

        Evaluation order:
          1. Credit decision + no ECOA notice (§1691) — DENIED.
          2. Credit decision + lender role + no adverse action notice (Reg B) — REQUIRES_HUMAN_REVIEW.
          3. Otherwise — APPROVED.
        """
        # ECOA §1691: Credit decisions require ECOA notice to applicant.
        if context.involves_credit_decision and not context.has_ecoa_notice:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "ECOA 15 U.S.C. §1691: Credit decisions require ECOA notice "
                    "to applicant"
                ),
                regulation_citation="ECOA 15 U.S.C. §1691",
            )

        # Regulation B §202: Adverse action requires written notice.
        if (
            context.involves_credit_decision
            and context.role == "lender"
            and not context.has_adverse_action_notice
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Regulation B 12 CFR §202: Adverse action requires written notice"
                ),
                regulation_citation="Regulation B 12 CFR §202",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="ECOA and Regulation B access check passed",
            regulation_citation="ECOA 15 U.S.C. §1691 / Regulation B",
        )


# ---------------------------------------------------------------------------
# Layer 3: AppraisalIndependenceFilter — Dodd-Frank §1472 + USPAP Standards
# ---------------------------------------------------------------------------

class AppraisalIndependenceFilter:
    """
    Enforces Dodd-Frank appraisal independence requirements and USPAP standards
    for access to appraisal and automated valuation documents.

    Dodd-Frank Act §1472 (15 U.S.C. §1639e) establishes appraisal
    independence requirements for federally related mortgage loans.
    Automated valuation models (AVMs) used for purchase transactions must be
    reviewed by a licensed human appraiser to ensure independence and accuracy.

    USPAP Standards require disclosure of the appraisal process to borrowers.
    Lender access to appraisal documents without the required borrower
    disclosure violates USPAP independence requirements.
    """

    LAYER_NAME = "APPRAISAL_INDEPENDENCE_USPAP"

    def evaluate(self, context: RealEstateContext, document: RealEstateDocument) -> FilterResult:
        """
        Evaluate Dodd-Frank and USPAP appraisal independence requirements.

        Evaluation order:
          1. Appraisal + AVM + purchase transaction (§1472) — REQUIRES_HUMAN_REVIEW.
          2. Appraisal + lender role + missing disclosure (USPAP) — DENIED.
          3. Otherwise — APPROVED.
        """
        # Dodd-Frank §1472: AVM for purchase transactions requires human appraiser review.
        if (
            context.involves_appraisal
            and context.is_automated_valuation
            and context.transaction_type == "purchase"
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Dodd-Frank §1472: Automated valuations for purchase transactions "
                    "require human appraiser review"
                ),
                regulation_citation="Dodd-Frank §1472",
            )

        # USPAP: Appraisal independence requires disclosure to borrower.
        if (
            context.involves_appraisal
            and context.role == "lender"
            and not context.has_disclosure
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "USPAP Standards: Appraisal independence requires disclosure "
                    "to borrower"
                ),
                regulation_citation="Dodd-Frank §1472 / USPAP Standards",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Appraisal independence requirements satisfied",
            regulation_citation="Dodd-Frank §1472 / USPAP Standards",
        )


# ---------------------------------------------------------------------------
# Layer 4: StateRealEstateLawFilter — state-specific real estate disclosure laws
# ---------------------------------------------------------------------------

class StateRealEstateLawFilter:
    """
    Enforces state-specific real estate disclosure laws for California,
    New York, Texas, and other states.

    California Civil Code §1940.2 requires landlords and property managers
    to disclose known material defects to tenants before entering into a
    rental agreement.  Rental documents without the required disclosure
    trigger human review escalation.

    New York Real Property Law §462 requires sellers to provide buyers with
    a property condition disclosure statement before the transfer of
    residential property.  Purchase transaction documents without the
    required disclosure are denied.

    Texas Property Code §5.008 requires sellers of residential real property
    to furnish buyers with a seller's disclosure notice before execution of a
    binding contract.  Texas seller purchase documents without the required
    disclosure trigger human review escalation.

    Other states default to a general approval under state real estate
    disclosure law, as the specific statutory requirements vary by
    jurisdiction and are governed by state-level implementation.
    """

    LAYER_NAME = "STATE_REAL_ESTATE_LAW"

    def evaluate(self, context: RealEstateContext, document: RealEstateDocument) -> FilterResult:
        """
        Evaluate state-specific real estate disclosure law requirements.

        Evaluation order:
          1. California + rental + no disclosure (CA Civil Code §1940.2) — REQUIRES_HUMAN_REVIEW.
          2. New York + purchase + no disclosure (NY RPL §462) — DENIED.
          3. Texas + purchase + seller role + no disclosure (TX Prop. Code §5.008) — REQUIRES_HUMAN_REVIEW.
          4. Other states — APPROVED.
        """
        # California Civil Code §1940.2: Rental requires disclosure of known defects.
        if (
            context.property_state == "CA"
            and context.involves_rental
            and not context.has_disclosure
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "CA Civil Code §1940.2: Rental agreements require disclosure "
                    "of known defects"
                ),
                regulation_citation="CA Civil Code §1940.2",
            )

        # New York RPL §462: Property condition disclosure required before purchase.
        if (
            context.property_state == "NY"
            and context.transaction_type == "purchase"
            and not context.has_disclosure
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "NY RPL §462: Property condition disclosure required "
                    "before purchase"
                ),
                regulation_citation="NY RPL §462",
            )

        # Texas Property Code §5.008: Seller's disclosure notice required.
        if (
            context.property_state == "TX"
            and context.transaction_type == "purchase"
            and context.role == "seller"
            and not context.has_disclosure
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "TX Property Code §5.008: Seller's disclosure notice required"
                ),
                regulation_citation="TX Property Code §5.008",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="State real estate disclosure requirements satisfied",
            regulation_citation="State Real Estate Disclosure Law",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class RealEstateAuditRecord:
    """
    Captures the full decision trail for a US real estate RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - Fair Housing Act HUD audit and investigation requirements.
      - ECOA Regulation B adverse action record-keeping obligations.
      - Dodd-Frank appraisal independence documentation requirements.
      - State real estate disclosure compliance records.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping.
    """

    event: str
    user_id: str
    role: str
    state: str
    documents_in: int
    documents_out: int
    decisions: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": self.event,
            "user_id": self.user_id,
            "role": self.role,
            "state": self.state,
            "documents_in": self.documents_in,
            "documents_out": self.documents_out,
            "decisions": self.decisions,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class RealEstateRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for US real estate and
    proptech platforms subject to the Fair Housing Act, ECOA, Dodd-Frank
    appraisal independence requirements, and state real estate disclosure laws.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW results do not
    stop the pipeline — those documents are included in the result set but
    flagged for human oversight.  Only documents that receive a DENIED result
    from any layer are excluded from the returned set.

    Layers in order:
      1. FairHousingActFilter          — FHA 42 U.S.C. §3604, HUD regulations
      2. ECOALendingFilter             — ECOA §1691, Regulation B §202
      3. AppraisalIndependenceFilter   — Dodd-Frank §1472, USPAP Standards
      4. StateRealEstateLawFilter      — CA §1940.2, NY RPL §462, TX §5.008

    Audit records are generated for every retrieval event regardless of outcome,
    providing a complete access trail for Fair Housing Act, ECOA, and state
    disclosure compliance audits.
    """

    def __init__(self) -> None:
        self._layers = [
            FairHousingActFilter(),
            ECOALendingFilter(),
            AppraisalIndependenceFilter(),
            StateRealEstateLawFilter(),
        ]

    def filter_documents(
        self,
        context: RealEstateContext,
        documents: List[RealEstateDocument],
    ) -> List[RealEstateDocument]:
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
        context: RealEstateContext,
        documents: List[RealEstateDocument],
    ) -> RealEstateAuditRecord:
        """
        Evaluate all documents and return a RealEstateAuditRecord summarising
        the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support Fair Housing
        Act, ECOA, and state disclosure compliance auditing.
        """
        documents_out = 0
        all_decisions: List[dict] = []

        for doc in documents:
            layer_results: List[dict] = []
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
                    "document_id": doc.document_id,
                    "final_decision": final_decision,
                    "layer_results": layer_results,
                }
            )

        return RealEstateAuditRecord(
            event="REAL_ESTATE_RAG_RETRIEVAL",
            user_id=context.user_id,
            role=context.role,
            state=context.property_state,
            documents_in=len(documents),
            documents_out=documents_out,
            decisions=all_decisions,
        )
