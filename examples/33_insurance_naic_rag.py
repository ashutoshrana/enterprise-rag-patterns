"""
US Insurance NAIC RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pipeline for
platforms operating in the US insurance sector.  Four independent filter
layers run sequentially; a document must pass all four to be returned to
the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | Insurance underwriting decision-support systems          | NAIC Model Privacy Protection Act        |
  | Claims adjudication and fraud analytics platforms        | NAIC Model Law + FCRA §1681b             |
  | Credit-based insurance scoring engines                   | FCRA §1681m adverse action               |
  | Consumer insurance file access portals                   | NAIC Model Privacy Act §13 consumer DSR  |
  | State insurance market conduct examination systems       | NAIC Market Conduct Examination standards|
  | AI/ML-driven underwriting and rating platforms           | CA CDI Bulletin 2022-5, IL IDOI 2021     |
  | Actuarial modeling and reserve calculation tools         | NAIC Actuarial Standard of Practice      |
  | Multi-state insurance compliance portals                 | State insurance privacy regulations      |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — NAICModelActFilter (NAIC Model Insurance Privacy Protection Act + NAIC AI Guidance)
      Controls access to insurance documents based on the requesting
      party's role and the document's sensitivity under NAIC Model Law.

      NAIC Model Privacy Protection Act §13 grants consumers the right to
      access information in their own insurance file.  A consumer making a
      self-access request for their own consumer report document is always
      permitted.

      NAIC Market Conduct Examination guidance grants state regulators and
      examiners broad access to carrier records to perform supervisory
      functions.  Regulator role or exam-mode access is unconditionally
      approved at this layer.

      NAIC Model Privacy Protection Act §7 restricts access to medical
      information to authorized personnel directly involved in underwriting,
      claims, actuarial analysis, regulatory oversight, or audit functions.

      NAIC AI Guidance (2020, updated 2023) recommends that AI/ML models
      used in insurance underwriting or rating be validated and registered
      with state regulators before use.  In jurisdictions (CA, CO, IL) with
      enacted AI insurance regulations, unregistered AI models are escalated
      for human review.

  Layer 2 — FCRAInsuranceFilter (FCRA 15 USC §1681 — insurance use of consumer reports)
      Controls access to consumer report information and credit-based
      insurance scores under the Fair Credit Reporting Act.

      FCRA §1681b(a)(3)(C) establishes "insurance purposes" as a permissible
      purpose for obtaining consumer reports.  Access is restricted to roles
      that have a bona fide insurance permissible purpose (underwriters,
      adjusters, actuaries, agents, regulators, and audit personnel).

      FCRA §1681m(a) requires that before taking any adverse action based in
      whole or in part on information from a consumer reporting agency, the
      insurer must provide the consumer with an adverse action notice.  If an
      adverse action is being taken using a credit-based insurance score and
      no notice has been sent, retrieval of that score is denied.

  Layer 3 — StateInsuranceAIFilter (CA CDI + IL IDOI AI guidance + state privacy)
      Enforces state-level insurance AI regulations and consumer privacy
      requirements at the retrieval layer.

      California CDI Bulletin 2022-5 requires that AI/ML models used in
      rating and underwriting be validated for algorithmic bias before being
      used in California insurance decisions.  Unregistered models trigger
      human review escalation.

      Illinois IDOI Guidance (2021) requires that automated underwriting
      systems operating in Illinois be audited for proxy discrimination.
      AI access to Illinois underwriting files triggers human review.

      California Proposition 103 (codified in Cal. Ins. Code §1861.02)
      prohibits the use of credit-based insurance scores as a rating factor
      in California.  Access to credit score documents in a California
      context triggers mandatory human review.

      State insurance privacy acts (most states) require consumer consent
      before medical information may be shared for insurance purposes.
      Texas and Florida have narrower consent exemptions for insurance
      processing.

  Layer 4 — InsuranceLoBFilter (Line of Business authorization)
      Enforces access boundaries based on the requester's authorized lines
      of business and role-based access to actuarial data.

      Insurance personnel are licensed and authorized per line of business
      (LIFE, HEALTH, AUTO, PROPERTY, etc.).  Accessing documents outside an
      agent's or adjuster's authorized lines violates internal access controls
      and, for licensed agents, potentially state insurance licensing law.

      NAIC Actuarial Standard of Practice restricts detailed actuarial data
      to actuaries, regulators, and audit personnel; other roles lack the
      professional context to use such data appropriately.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class InsuranceRequesterRole(Enum):
    UNDERWRITER = "UNDERWRITER"
    CLAIMS_ADJUSTER = "CLAIMS_ADJUSTER"
    ACTUARY = "ACTUARY"
    AGENT = "AGENT"
    CONSUMER = "CONSUMER"
    REGULATOR = "REGULATOR"
    AUDIT = "AUDIT"


class InsuranceDocumentCategory(Enum):
    UNDERWRITING_FILE = "UNDERWRITING_FILE"
    CLAIMS_FILE = "CLAIMS_FILE"
    ACTUARIAL_DATA = "ACTUARIAL_DATA"
    CONSUMER_REPORT = "CONSUMER_REPORT"
    CREDIT_BASED_INSURANCE_SCORE = "CREDIT_BASED_INSURANCE_SCORE"
    ADVERSE_ACTION_NOTICE = "ADVERSE_ACTION_NOTICE"
    POLICY_FILE = "POLICY_FILE"
    MEDICAL_RECORD = "MEDICAL_RECORD"
    PUBLIC_FILING = "PUBLIC_FILING"


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InsuranceRAGContext:
    """
    Carries all per-request attributes needed by the four insurance filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorisation state.

    state is a 2-letter US state code (e.g. "CA", "IL", "TX", "NY").

    authorized_lines_of_business is a frozenset of line-of-business codes the
    requester is authorized to access, e.g. frozenset({"AUTO", "PROPERTY"}).
    An empty frozenset means no LoB restriction is applied.

    processing_purpose describes why the requester needs the information, e.g.
        "underwriting_review", "claims_investigation", "regulatory_exam".
    """

    user_id: str
    role: InsuranceRequesterRole
    company_id: str
    state: str                              # 2-letter US state code
    is_consumer_request: bool               # FCRA §1681g consumer file disclosure right
    has_underwriting_authority: bool        # NAIC underwriter access
    is_ai_model_decision: bool              # AI/ML model making the retrieval
    ai_model_registered: bool               # State insurance AI registry if required
    has_adverse_action_basis: bool          # FCRA §1681m — adverse action being taken
    adverse_action_notice_sent: bool
    authorized_lines_of_business: frozenset  # LIFE, HEALTH, AUTO, PROPERTY, etc.
    is_state_regulator_exam: bool           # Exam access by state regulator
    customer_consent_given: bool
    processing_purpose: str


@dataclass(frozen=True)
class InsuranceRAGDocument:
    """
    Immutable document descriptor carrying all attributes needed for insurance
    compliance evaluation across the four filter layers.

    contains_consumer_report_info is True when the document contains information
    obtained from a consumer reporting agency (CRA) subject to FCRA.

    contains_credit_score is True when the document contains a credit-based
    insurance score as defined in FCRA §1681m.

    contains_medical_info is True when the document contains protected health
    information subject to HIPAA or state insurance privacy acts.

    is_adverse_action_doc is True when this document is or contains an adverse
    action notice under FCRA §1681m.

    requires_state_approval is True when the document or decision embedded in
    the document requires prior state regulatory approval before use.
    """

    document_id: str
    category: InsuranceDocumentCategory
    consumer_id: str
    line_of_business: str
    state: str
    contains_consumer_report_info: bool     # FCRA — from a CRA
    contains_credit_score: bool             # FCRA §1681m — credit-based insurance score
    contains_medical_info: bool             # HIPAA / state insurance privacy
    is_adverse_action_doc: bool
    requires_state_approval: bool


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: str               # "APPROVED", "DENIED", "REDACTED", "REQUIRES_HUMAN_REVIEW"
    reason: str
    regulation_citation: str
    requires_logging: bool = True

    @property
    def is_denied(self) -> bool:
        """True only when the decision is DENIED.

        REDACTED and REQUIRES_HUMAN_REVIEW do not stop the pipeline.
        """
        return self.decision == "DENIED"


# ---------------------------------------------------------------------------
# Layer 1: NAICModelActFilter — NAIC Model Insurance Privacy Protection Act + AI Guidance
# ---------------------------------------------------------------------------

class NAICModelActFilter:
    """
    Enforces NAIC Model Insurance Privacy Protection Act requirements and NAIC
    AI guidance for insurance AI/ML models.

    NAIC Model Privacy Protection Act §13 grants consumers the right to access
    their own insurance information file.  A consumer making a self-access
    request for their consumer report is unconditionally approved.

    NAIC Market Conduct Examination guidance provides state regulators and
    examiners with broad supervisory access to all carrier records.  Regulator
    role or state examiner access is unconditionally approved.

    NAIC Model Privacy Protection Act §7 restricts medical information to
    authorized personnel: underwriters, claims adjusters, actuaries, regulators,
    and audit personnel.  All other roles are denied.

    NAIC AI Guidance (updated 2023) recommends AI/ML models used in insurance
    underwriting or rating be registered and validated in states with enacted AI
    insurance regulations (CA, CO, IL) before use.  Unregistered models in those
    states are escalated for human review.
    """

    LAYER_NAME = "NAIC_MODEL_ACT_PRIVACY_AI"

    _AI_REGULATED_STATES = frozenset({"CA", "CO", "IL"})

    _MEDICAL_AUTHORIZED_ROLES = frozenset({
        InsuranceRequesterRole.UNDERWRITER,
        InsuranceRequesterRole.CLAIMS_ADJUSTER,
        InsuranceRequesterRole.ACTUARY,
        InsuranceRequesterRole.REGULATOR,
        InsuranceRequesterRole.AUDIT,
    })

    _CONSUMER_ACCESSIBLE_CATEGORIES = frozenset({
        InsuranceDocumentCategory.CONSUMER_REPORT,
        InsuranceDocumentCategory.ADVERSE_ACTION_NOTICE,
        InsuranceDocumentCategory.POLICY_FILE,
    })

    def evaluate(
        self, context: InsuranceRAGContext, document: InsuranceRAGDocument
    ) -> FilterResult:
        """
        Evaluate NAIC Model Act privacy and AI guidance requirements.

        Evaluation order:
          1. Consumer self-access of own consumer report (§13) — approved.
          2. Regulator or state exam access — approved.
          3. Consumer access to non-consumer-accessible category — denied.
          4. Medical info without authorized role (§7) — denied.
          5. AI model unregistered in AI-regulated state — REQUIRES_HUMAN_REVIEW.
          6. Otherwise — approved.
        """
        # §13: Consumer right to access their own file.
        if (
            context.is_consumer_request
            and document.category == InsuranceDocumentCategory.CONSUMER_REPORT
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason=(
                    "NAIC Model Privacy Protection Act §13: Consumer right to access "
                    "their own file"
                ),
                regulation_citation="NAIC Model Privacy Protection Act §13",
            )

        # Market conduct exam: regulators always have supervisory access.
        if context.role == InsuranceRequesterRole.REGULATOR or context.is_state_regulator_exam:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="NAIC Market Conduct Examination — regulatory access authorized",
                regulation_citation="NAIC Market Conduct Examination",
            )

        # Consumers may only access their own insurance records.
        if (
            context.role == InsuranceRequesterRole.CONSUMER
            and document.category not in self._CONSUMER_ACCESSIBLE_CATEGORIES
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "NAIC Model Privacy Protection Act: Consumer access restricted "
                    "to own insurance records"
                ),
                regulation_citation="NAIC Model Privacy Protection Act",
            )

        # §7: Medical information restricted to authorized personnel.
        if (
            document.contains_medical_info
            and context.role not in self._MEDICAL_AUTHORIZED_ROLES
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "NAIC Model Privacy Protection Act §7: Medical information "
                    "access restricted to authorized personnel"
                ),
                regulation_citation="NAIC Model Privacy Protection Act §7",
            )

        # AI guidance: unregistered models in AI-regulated states.
        if (
            context.is_ai_model_decision
            and not context.ai_model_registered
            and context.state in self._AI_REGULATED_STATES
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    f"State AI Insurance Regulation: AI models used in underwriting "
                    f"must be registered in {context.state} before use"
                ),
                regulation_citation=(
                    f"State AI Insurance Regulation ({context.state})"
                ),
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="NAIC Model Insurance Privacy Protection Act — access check passed",
            regulation_citation="NAIC Model Insurance Privacy Protection Act",
        )


# ---------------------------------------------------------------------------
# Layer 2: FCRAInsuranceFilter — FCRA 15 USC §1681 insurance use of consumer reports
# ---------------------------------------------------------------------------

class FCRAInsuranceFilter:
    """
    Enforces FCRA requirements for insurance use of consumer reports and
    credit-based insurance scores.

    FCRA §1681b(a)(3)(C) establishes "insurance purposes" as a permissible
    purpose for obtaining and using consumer reports.  Access is limited to
    roles with a bona fide insurance permissible purpose.

    FCRA §1681m(a) requires an adverse action notice to be sent to the
    consumer before taking an adverse action based in whole or in part on a
    consumer report or credit-based insurance score.  Retrieving a credit
    score for an adverse decision without first sending the notice is denied.
    """

    LAYER_NAME = "FCRA_INSURANCE_1681"

    _CONSUMER_REPORT_AUTHORIZED_ROLES = frozenset({
        InsuranceRequesterRole.UNDERWRITER,
        InsuranceRequesterRole.CLAIMS_ADJUSTER,
        InsuranceRequesterRole.ACTUARY,
        InsuranceRequesterRole.AGENT,
        InsuranceRequesterRole.REGULATOR,
        InsuranceRequesterRole.AUDIT,
    })

    _CREDIT_SCORE_AUTHORIZED_ROLES = frozenset({
        InsuranceRequesterRole.UNDERWRITER,
        InsuranceRequesterRole.ACTUARY,
        InsuranceRequesterRole.REGULATOR,
    })

    def evaluate(
        self, context: InsuranceRAGContext, document: InsuranceRAGDocument
    ) -> FilterResult:
        """
        Evaluate FCRA requirements for insurance consumer report and credit
        score access.

        Evaluation order:
          1. No consumer report info or credit score — approved (FCRA not applicable).
          2. Credit score + adverse action without notice (§1681m(a)) — denied.
          3. Credit score accessed by unauthorized role — denied.
          4. Consumer report info accessed by unauthorized role — denied.
          5. Otherwise — approved.
        """
        # FCRA not applicable if document contains no consumer report information.
        if not document.contains_consumer_report_info and not document.contains_credit_score:
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="APPROVED",
                reason="FCRA: Document does not contain consumer report information",
                regulation_citation="FCRA §1681b",
            )

        # §1681m(a): Adverse action notice required before using credit score adversely.
        if (
            document.contains_credit_score
            and context.has_adverse_action_basis
            and not context.adverse_action_notice_sent
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "FCRA §1681m(a): Adverse action notice required before using "
                    "credit-based insurance score in adverse decision"
                ),
                regulation_citation="FCRA §1681m(a)",
            )

        # Credit score restricted to authorized insurance purposes.
        if (
            document.contains_credit_score
            and context.role not in self._CREDIT_SCORE_AUTHORIZED_ROLES
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "FCRA §1681b(a)(3)(C): Credit-based insurance scores restricted "
                    "to authorized insurance purposes"
                ),
                regulation_citation="FCRA §1681b(a)(3)(C)",
            )

        # Consumer report restricted to authorized insurance purposes.
        if (
            document.contains_consumer_report_info
            and context.role not in self._CONSUMER_REPORT_AUTHORIZED_ROLES
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "FCRA §1681b(a)(3)(C): Consumer report access for insurance "
                    "purposes restricted to authorized users"
                ),
                regulation_citation="FCRA §1681b(a)(3)(C)",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="FCRA §1681b(a)(3)(C): Insurance permissible purpose",
            regulation_citation="FCRA §1681b(a)(3)(C): Insurance permissible purpose",
        )


# ---------------------------------------------------------------------------
# Layer 3: StateInsuranceAIFilter — CA CDI + IL IDOI AI guidance + state privacy
# ---------------------------------------------------------------------------

class StateInsuranceAIFilter:
    """
    Enforces state-level insurance AI regulations and consumer privacy
    requirements at the retrieval layer.

    California CDI Bulletin 2022-5 requires that AI/ML models used in
    insurance rating and underwriting be validated for algorithmic bias
    before use in California.

    Illinois IDOI Guidance (2021) requires that automated underwriting
    systems be audited for proxy discrimination; AI access to Illinois
    underwriting files is escalated for human review.

    California Proposition 103 prohibits credit-based insurance scoring
    in California; access to credit score documents in a California
    insurance context requires mandatory human review.

    Most state insurance privacy acts require consumer consent for medical
    information sharing.  Texas and Florida have narrower exemptions and
    are excluded from the blanket consent requirement.
    """

    LAYER_NAME = "STATE_INSURANCE_AI_PRIVACY"

    _MEDICAL_CONSENT_EXEMPT_STATES = frozenset({"TX", "FL"})

    def evaluate(
        self, context: InsuranceRAGContext, document: InsuranceRAGDocument
    ) -> FilterResult:
        """
        Evaluate state insurance AI and privacy requirements.

        Evaluation order:
          1. CA + AI model unregistered — REQUIRES_HUMAN_REVIEW.
          2. IL + AI model + underwriting file — REQUIRES_HUMAN_REVIEW.
          3. Medical info + non-exempt state + no consent — DENIED.
          4. CA + credit score document — REQUIRES_HUMAN_REVIEW.
          5. Otherwise — approved.
        """
        # California CDI Bulletin 2022-5: unregistered AI models.
        if (
            context.state == "CA"
            and context.is_ai_model_decision
            and not context.ai_model_registered
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "California CDI Bulletin 2022-5: AI/ML models used in rating and "
                    "underwriting must be validated for bias before use"
                ),
                regulation_citation="California CDI Bulletin 2022-5",
            )

        # Illinois IDOI AI Guidance (2021): automated underwriting systems.
        if (
            context.state == "IL"
            and context.is_ai_model_decision
            and document.category == InsuranceDocumentCategory.UNDERWRITING_FILE
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "Illinois IDOI AI Guidance (2021): Automated underwriting systems "
                    "must be audited for proxy discrimination"
                ),
                regulation_citation="Illinois IDOI AI Guidance (2021)",
            )

        # State insurance privacy: medical info requires consumer consent.
        # Regulators and state examiners are exempt from the consent requirement.
        if (
            document.contains_medical_info
            and context.state not in self._MEDICAL_CONSENT_EXEMPT_STATES
            and not context.customer_consent_given
            and context.role != InsuranceRequesterRole.REGULATOR
            and not context.is_state_regulator_exam
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "State Insurance Privacy Act: Medical information requires "
                    "consumer consent"
                ),
                regulation_citation="State Insurance Privacy Act",
            )

        # California Proposition 103: credit scores prohibited in CA insurance rating.
        if (
            document.category == InsuranceDocumentCategory.CREDIT_BASED_INSURANCE_SCORE
            and context.state == "CA"
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="REQUIRES_HUMAN_REVIEW",
                reason=(
                    "California Proposition 103: Credit scores prohibited for insurance "
                    "rating in California — human review required"
                ),
                regulation_citation="California Proposition 103",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="State insurance regulations satisfied",
            regulation_citation="State insurance regulations satisfied",
        )


# ---------------------------------------------------------------------------
# Layer 4: InsuranceLoBFilter — Line of Business authorization
# ---------------------------------------------------------------------------

class InsuranceLoBFilter:
    """
    Enforces access boundaries based on the requester's authorized lines of
    business and role-based access to actuarial data.

    Insurance personnel are licensed and authorized per line of business.
    Accessing documents outside an agent's or adjuster's authorized lines
    violates both internal access policy and, for licensed agents, state
    insurance licensing law.

    NAIC Actuarial Standard of Practice restricts detailed actuarial data to
    actuaries, regulators, and audit personnel.  Other roles lack the
    professional framework to use actuarial data appropriately.
    """

    LAYER_NAME = "INSURANCE_LINE_OF_BUSINESS"

    _ACTUARIAL_AUTHORIZED_ROLES = frozenset({
        InsuranceRequesterRole.ACTUARY,
        InsuranceRequesterRole.REGULATOR,
        InsuranceRequesterRole.AUDIT,
    })

    def evaluate(
        self, context: InsuranceRAGContext, document: InsuranceRAGDocument
    ) -> FilterResult:
        """
        Evaluate line-of-business authorization and actuarial data restrictions.

        Evaluation order:
          1. Consumer accessing underwriting file — denied.
          2. Document LoB not in authorized LoB set (when both non-empty) — denied.
          3. Actuarial data accessed by non-actuarial role — denied.
          4. Otherwise — approved.
        """
        # Consumers may not access underwriting files.
        if (
            context.role == InsuranceRequesterRole.CONSUMER
            and document.category == InsuranceDocumentCategory.UNDERWRITING_FILE
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason="Insurance privacy: Underwriting files not accessible to consumers",
                regulation_citation="NAIC Model Insurance Privacy Protection Act",
            )

        # Line-of-business boundary enforcement.
        if (
            document.line_of_business
            and context.authorized_lines_of_business
            and document.line_of_business not in context.authorized_lines_of_business
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    f"Insurance authority boundary: User not authorized for "
                    f"{document.line_of_business} line"
                ),
                regulation_citation="Insurance line of business authorization",
            )

        # Actuarial data restricted to actuaries, regulators, and auditors.
        if (
            document.category == InsuranceDocumentCategory.ACTUARIAL_DATA
            and context.role not in self._ACTUARIAL_AUTHORIZED_ROLES
        ):
            return FilterResult(
                layer=self.LAYER_NAME,
                decision="DENIED",
                reason=(
                    "NAIC Actuarial Standard: Actuarial data restricted to "
                    "actuaries and regulators"
                ),
                regulation_citation="NAIC Actuarial Standard of Practice",
            )

        return FilterResult(
            layer=self.LAYER_NAME,
            decision="APPROVED",
            reason="Insurance line of business authorization satisfied",
            regulation_citation="Insurance line of business authorization satisfied",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class InsuranceRAGAuditRecord:
    """
    Captures the full decision trail for a US insurance NAIC RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - NAIC Market Conduct Examination record-keeping requirements.
      - FCRA §1681s-2: Responsibilities of furnishers of information and
        record-keeping for adverse action decisions.
      - State insurance department examination and audit requirements.
      - NAIC AI Governance Framework: logging and accountability for AI-assisted
        insurance decisions.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping.
    """

    context: InsuranceRAGContext
    documents_evaluated: int
    documents_permitted: int
    documents_denied: int
    documents_redacted: int
    filter_results: list
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": "INSURANCE_NAIC_RAG_RETRIEVAL",
            "user_id": self.context.user_id,
            "role": self.context.role.value,
            "company_id": self.context.company_id,
            "state": self.context.state,
            "is_consumer_request": self.context.is_consumer_request,
            "is_ai_model_decision": self.context.is_ai_model_decision,
            "ai_model_registered": self.context.ai_model_registered,
            "has_adverse_action_basis": self.context.has_adverse_action_basis,
            "adverse_action_notice_sent": self.context.adverse_action_notice_sent,
            "is_state_regulator_exam": self.context.is_state_regulator_exam,
            "processing_purpose": self.context.processing_purpose,
            "documents_evaluated": self.documents_evaluated,
            "documents_permitted": self.documents_permitted,
            "documents_denied": self.documents_denied,
            "documents_redacted": self.documents_redacted,
            "filter_results": self.filter_results,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class InsuranceNAICRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for US insurance
    platforms subject to NAIC Model Law, FCRA, and state insurance AI
    regulations.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  REQUIRES_HUMAN_REVIEW and REDACTED
    results do not stop the pipeline — those documents are included in the
    result set but flagged for human oversight.  Only documents that receive
    a DENIED result from any layer are excluded from the returned set.

    Layers in order:
      1. NAICModelActFilter       — NAIC Model Privacy Act §13/§7, AI Guidance
      2. FCRAInsuranceFilter      — FCRA §1681b permissible purpose, §1681m adverse action
      3. StateInsuranceAIFilter   — CA CDI 2022-5, IL IDOI 2021, state privacy
      4. InsuranceLoBFilter       — Line of business authorization, actuarial access

    Audit records are generated for every document regardless of outcome,
    providing a complete access trail for NAIC examination record-keeping and
    FCRA adverse action accountability requirements.
    """

    def __init__(self) -> None:
        self._layers = [
            NAICModelActFilter(),
            FCRAInsuranceFilter(),
            StateInsuranceAIFilter(),
            InsuranceLoBFilter(),
        ]

    def retrieve(
        self,
        context: InsuranceRAGContext,
        documents: List[InsuranceRAGDocument],
    ) -> List[InsuranceRAGDocument]:
        """
        Return a list of documents that pass (or are flagged but not denied by)
        all four filter layers.

        Documents denied on any layer are excluded from the result.  Documents
        that receive REQUIRES_HUMAN_REVIEW or REDACTED decisions on any layer
        are included, as those decisions do not constitute a denial.
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
        context: InsuranceRAGContext,
        documents: List[InsuranceRAGDocument],
    ) -> InsuranceRAGAuditRecord:
        """
        Evaluate all documents and return an InsuranceRAGAuditRecord summarising
        the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support NAIC Market
        Conduct Examination record-keeping and FCRA adverse action logging.
        """
        documents_permitted = 0
        documents_denied = 0
        documents_redacted = 0
        all_filter_results: List[dict] = []

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
                if result.decision == "REDACTED":
                    final_decision = "REDACTED"
                elif result.decision == "REQUIRES_HUMAN_REVIEW" and final_decision == "APPROVED":
                    final_decision = "REQUIRES_HUMAN_REVIEW"

            if allow:
                if final_decision == "REDACTED":
                    documents_redacted += 1
                else:
                    documents_permitted += 1
            else:
                documents_denied += 1

            all_filter_results.append(
                {
                    "document_id": doc.document_id,
                    "final_decision": final_decision,
                    "layer_results": layer_results,
                }
            )

        return InsuranceRAGAuditRecord(
            context=context,
            documents_evaluated=len(documents),
            documents_permitted=documents_permitted,
            documents_denied=documents_denied,
            documents_redacted=documents_redacted,
            filter_results=all_filter_results,
        )


# ---------------------------------------------------------------------------
# Smoke test / demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("=" * 70)
    print("US Insurance NAIC RAG Pipeline — Smoke Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Shared documents
    # ------------------------------------------------------------------

    consumer_report_doc = InsuranceRAGDocument(
        document_id="doc-001-consumer-report",
        category=InsuranceDocumentCategory.CONSUMER_REPORT,
        consumer_id="cons-001",
        line_of_business="AUTO",
        state="IL",
        contains_consumer_report_info=True,
        contains_credit_score=False,
        contains_medical_info=False,
        is_adverse_action_doc=False,
        requires_state_approval=False,
    )

    underwriting_doc = InsuranceRAGDocument(
        document_id="doc-002-underwriting",
        category=InsuranceDocumentCategory.UNDERWRITING_FILE,
        consumer_id="cons-001",
        line_of_business="AUTO",
        state="IL",
        contains_consumer_report_info=False,
        contains_credit_score=False,
        contains_medical_info=False,
        is_adverse_action_doc=False,
        requires_state_approval=False,
    )

    credit_score_doc = InsuranceRAGDocument(
        document_id="doc-003-credit-score",
        category=InsuranceDocumentCategory.CREDIT_BASED_INSURANCE_SCORE,
        consumer_id="cons-001",
        line_of_business="AUTO",
        state="CA",
        contains_consumer_report_info=True,
        contains_credit_score=True,
        contains_medical_info=False,
        is_adverse_action_doc=False,
        requires_state_approval=True,
    )

    public_doc = InsuranceRAGDocument(
        document_id="doc-004-public-filing",
        category=InsuranceDocumentCategory.PUBLIC_FILING,
        consumer_id="",
        line_of_business="",
        state="NY",
        contains_consumer_report_info=False,
        contains_credit_score=False,
        contains_medical_info=False,
        is_adverse_action_doc=False,
        requires_state_approval=False,
    )

    all_documents = [consumer_report_doc, underwriting_doc, credit_score_doc, public_doc]

    # ------------------------------------------------------------------
    # Scenario 1: Underwriter (IL) — standard access
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: Underwriter in IL, standard access ---")
    ctx_uw = InsuranceRAGContext(
        user_id="uw-001",
        role=InsuranceRequesterRole.UNDERWRITER,
        company_id="acme-ins",
        state="IL",
        is_consumer_request=False,
        has_underwriting_authority=True,
        is_ai_model_decision=False,
        ai_model_registered=False,
        has_adverse_action_basis=False,
        adverse_action_notice_sent=False,
        authorized_lines_of_business=frozenset({"AUTO", "PROPERTY"}),
        is_state_regulator_exam=False,
        customer_consent_given=True,
        processing_purpose="underwriting_review",
    )
    pipeline = InsuranceNAICRAGPipeline()
    results = pipeline.retrieve(ctx_uw, all_documents)
    print(f"  Permitted documents: {[d.document_id for d in results]}")

    # ------------------------------------------------------------------
    # Scenario 2: Consumer self-access (§13)
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Consumer self-access to own file (§13) ---")
    ctx_consumer = InsuranceRAGContext(
        user_id="cons-001",
        role=InsuranceRequesterRole.CONSUMER,
        company_id="acme-ins",
        state="NY",
        is_consumer_request=True,
        has_underwriting_authority=False,
        is_ai_model_decision=False,
        ai_model_registered=False,
        has_adverse_action_basis=False,
        adverse_action_notice_sent=False,
        authorized_lines_of_business=frozenset(),
        is_state_regulator_exam=False,
        customer_consent_given=True,
        processing_purpose="consumer_file_access",
    )
    results_consumer = pipeline.retrieve(ctx_consumer, [consumer_report_doc])
    print(f"  Permitted documents: {[d.document_id for d in results_consumer]}")

    # ------------------------------------------------------------------
    # Scenario 3: AI model in CA without registration — REQUIRES_HUMAN_REVIEW
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: AI model in CA, unregistered — REQUIRES_HUMAN_REVIEW ---")
    ctx_ai_ca = InsuranceRAGContext(
        user_id="ai-sys-001",
        role=InsuranceRequesterRole.UNDERWRITER,
        company_id="acme-ins",
        state="CA",
        is_consumer_request=False,
        has_underwriting_authority=True,
        is_ai_model_decision=True,
        ai_model_registered=False,
        has_adverse_action_basis=False,
        adverse_action_notice_sent=False,
        authorized_lines_of_business=frozenset({"AUTO"}),
        is_state_regulator_exam=False,
        customer_consent_given=True,
        processing_purpose="automated_underwriting",
    )
    results_ai_ca = pipeline.retrieve(ctx_ai_ca, [underwriting_doc])
    print(f"  Permitted documents (incl. REQUIRES_HUMAN_REVIEW): {[d.document_id for d in results_ai_ca]}")

    # ------------------------------------------------------------------
    # Scenario 4: Regulator exam — full access
    # ------------------------------------------------------------------
    print("\n--- Scenario 4: State regulator exam — full access ---")
    ctx_reg = InsuranceRAGContext(
        user_id="reg-001",
        role=InsuranceRequesterRole.REGULATOR,
        company_id="state-dept",
        state="NY",
        is_consumer_request=False,
        has_underwriting_authority=False,
        is_ai_model_decision=False,
        ai_model_registered=False,
        has_adverse_action_basis=False,
        adverse_action_notice_sent=False,
        authorized_lines_of_business=frozenset(),
        is_state_regulator_exam=True,
        customer_consent_given=False,
        processing_purpose="regulatory_exam",
    )
    results_reg = pipeline.retrieve(ctx_reg, all_documents)
    print(f"  Permitted documents: {[d.document_id for d in results_reg]}")

    # ------------------------------------------------------------------
    # Scenario 5: Adverse action without notice — DENIED
    # ------------------------------------------------------------------
    print("\n--- Scenario 5: Adverse action without notice — FCRA §1681m DENIED ---")
    ctx_adverse = InsuranceRAGContext(
        user_id="uw-002",
        role=InsuranceRequesterRole.UNDERWRITER,
        company_id="acme-ins",
        state="TX",
        is_consumer_request=False,
        has_underwriting_authority=True,
        is_ai_model_decision=False,
        ai_model_registered=False,
        has_adverse_action_basis=True,
        adverse_action_notice_sent=False,
        authorized_lines_of_business=frozenset({"AUTO"}),
        is_state_regulator_exam=False,
        customer_consent_given=True,
        processing_purpose="adverse_action_review",
    )
    results_adverse = pipeline.retrieve(ctx_adverse, [credit_score_doc])
    print(f"  Permitted documents: {[d.document_id for d in results_adverse]}")

    # ------------------------------------------------------------------
    # Audit record
    # ------------------------------------------------------------------
    print("\n--- Audit record (retrieve_with_audit) ---")
    audit = pipeline.retrieve_with_audit(ctx_uw, all_documents)
    log = audit.to_audit_log()
    print(json.dumps(
        {k: v for k, v in log.items() if k != "filter_results"},
        indent=2,
    ))
    print(f"  event: {log['event']}")
    print(f"  documents_evaluated: {log['documents_evaluated']}")
    print(f"  documents_permitted: {log['documents_permitted']}")
    print(f"  documents_denied: {log['documents_denied']}")
    print(f"  documents_redacted: {log['documents_redacted']}")
    print("\nSmoke test complete.")
