"""
20_real_estate_mortgage_rag.py — Fair Housing Act + HMDA + CFPB UDAAP + RESPA compliance
for a mortgage lender's knowledge base assistant.

Demonstrates defense-in-depth RAG retrieval where four overlapping federal regulatory
frameworks each impose independent access control obligations on a mortgage lending
information system:

    Layer 1  — Fair Housing Act (42 U.S.C. §§ 3604–3606) / ECOA (15 U.S.C. § 1691):
               Prohibits discrimination in residential real estate transactions based
               on race, color, national origin, religion, sex, familial status,
               disability (FHA) and additional classes under ECOA. The disparate
               impact doctrine (Texas Dept. of Housing v. Inclusive Communities, 2015)
               means that even facially neutral policies with discriminatory effects
               violate the FHA. Documents containing neighborhood demographic data,
               racial composition of census tracts, or protected class proxies must
               not be surfaced in underwriting decisioning contexts.

    Layer 2  — Home Mortgage Disclosure Act (HMDA, 12 U.S.C. § 2801; Reg C 12 CFR 1003):
               Lenders meeting coverage thresholds must collect, report, and disclose
               HMDA data. Protected characteristic data (race, ethnicity, sex, age)
               collected for HMDA may only be used for regulatory reporting, not
               for underwriting decisions. Accessing HMDA-collected demographic fields
               in a loan decision context is impermissible use.

    Layer 3  — CFPB UDAAP / ECOA Adverse Action (12 CFR 1002.9; Reg B):
               Any denial, counter-offer, or adverse action on a covered loan requires
               a written statement of specific reasons. AI/ML decisioning systems must
               be able to produce adverse action explanations citing specific, principal
               reasons from the credit file — not from protected class attributes.
               The CFPB has signaled (Circular 2022-03) that black-box AI adverse
               actions violate ECOA.

    Layer 4  — RESPA (12 U.S.C. § 2607) + State Licensing (SAFE Act, 12 U.S.C. § 5104):
               Loan officers must be licensed in the state where the property is
               located. Settlement service providers must be licensed for the relevant
               transaction type. Cross-state document access requires matching
               license jurisdiction.

Scenarios
---------

  A. Loan officer queries comparable sales for an appraisal review:
     FHA: NEIGHBORHOOD_DEMOGRAPHIC data blocked (disparate impact risk).
     HMDA: Demographic characteristic references blocked for underwriting context.
     Appraisal, comparable sales, property assessment permitted.
     Loan officer holds valid state license for property state.

  B. Compliance analyst queries HMDA demographic data for annual report:
     HMDA data access permitted for regulatory reporting context (not underwriting).
     FHA disparate impact filter still blocks direct protected class proxies.

  C. Unlicensed cross-state query:
     RESPA/SAFE Act blocks all access — loan officer not licensed in property state.

  D. Automated adverse action — explainability gate:
     CFPB UDAAP filter requires adverse action notice populated with specific reasons.
     Returns only documents with non-protected-class credit factors.

No external dependencies required.

Run:
    python examples/20_real_estate_mortgage_rag.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class ProtectedCharacteristic(str, Enum):
    """
    Protected classes under the Fair Housing Act (42 U.S.C. § 3604) and ECOA
    (15 U.S.C. § 1691). Must not influence lending decisions.
    """
    RACE = "RACE"
    COLOR = "COLOR"
    NATIONAL_ORIGIN = "NATIONAL_ORIGIN"
    RELIGION = "RELIGION"
    SEX = "SEX"
    FAMILIAL_STATUS = "FAMILIAL_STATUS"
    DISABILITY = "DISABILITY"
    # ECOA additional protected classes
    AGE = "AGE"
    MARITAL_STATUS = "MARITAL_STATUS"
    RECEIPT_OF_PUBLIC_ASSISTANCE = "RECEIPT_OF_PUBLIC_ASSISTANCE"


class MortgageDocumentCategory(str, Enum):
    """
    Categories of documents in a mortgage lending knowledge base.
    Determines which regulatory filters apply.
    """
    # Application and underwriting documents
    LOAN_APPLICATION = "LOAN_APPLICATION"          # 1003 URLA — base application
    CREDIT_REPORT = "CREDIT_REPORT"                # Credit bureau reports (no protected class)
    INCOME_VERIFICATION = "INCOME_VERIFICATION"    # W-2, paystubs, tax returns
    ASSET_STATEMENT = "ASSET_STATEMENT"            # Bank statements, investment accounts
    DEBT_OBLIGATIONS = "DEBT_OBLIGATIONS"          # Existing debts schedule
    # Property documents
    APPRAISAL_REPORT = "APPRAISAL_REPORT"          # Full URAR appraisal
    COMPARABLE_SALES = "COMPARABLE_SALES"          # Comparable transaction data
    PROPERTY_ASSESSMENT = "PROPERTY_ASSESSMENT"   # Tax assessment, title search
    # Neighborhood/demographic data — disparate impact risk
    NEIGHBORHOOD_DEMOGRAPHIC = "NEIGHBORHOOD_DEMOGRAPHIC"  # Census tract demographics
    CENSUS_TRACT_DATA = "CENSUS_TRACT_DATA"        # ACS data with racial composition
    # Decision and disclosure documents
    APPROVAL_NOTICE = "APPROVAL_NOTICE"            # Approval with terms
    DENIAL_NOTICE = "DENIAL_NOTICE"                # Adverse action notice + reasons
    RATE_SHEET = "RATE_SHEET"                      # Pricing matrix
    COUNTER_OFFER = "COUNTER_OFFER"                # Alternative product offer
    # HMDA data — regulatory use only
    HMDA_LAR_DATA = "HMDA_LAR_DATA"               # Loan Application Register entries
    HMDA_DEMOGRAPHIC = "HMDA_DEMOGRAPHIC"          # Collected race/ethnicity/sex fields
    # Settlement and closing
    CLOSING_DISCLOSURE = "CLOSING_DISCLOSURE"      # CD (TRID)
    SETTLEMENT_STATEMENT = "SETTLEMENT_STATEMENT"  # HUD-1 / ALTA
    TITLE_COMMITMENT = "TITLE_COMMITMENT"          # Title insurance commitment
    # Internal policy
    UNDERWRITING_GUIDELINES = "UNDERWRITING_GUIDELINES"  # Credit policy manual
    COMPLIANCE_PROCEDURE = "COMPLIANCE_PROCEDURE"         # CMS procedures


class LoanPurpose(str, Enum):
    """Loan purpose for HMDA and RESPA applicability."""
    HOME_PURCHASE = "HOME_PURCHASE"
    REFINANCE = "REFINANCE"
    HOME_IMPROVEMENT = "HOME_IMPROVEMENT"
    CASH_OUT_REFINANCE = "CASH_OUT_REFINANCE"
    HELOC = "HELOC"


class QueryContext(str, Enum):
    """
    The business context driving the query — determines which restrictions apply.
    UNDERWRITING contexts face the strictest controls.
    """
    UNDERWRITING_DECISION = "UNDERWRITING_DECISION"   # Loan approval/denial decisioning
    APPRAISAL_REVIEW = "APPRAISAL_REVIEW"             # Reviewing collateral value
    ADVERSE_ACTION = "ADVERSE_ACTION"                  # Generating adverse action notice
    HMDA_REPORTING = "HMDA_REPORTING"                  # Annual regulatory filing
    COMPLIANCE_AUDIT = "COMPLIANCE_AUDIT"              # CRA/HMDA/FHA audit
    SERVICING = "SERVICING"                            # Post-closing servicing
    GENERAL_QUERY = "GENERAL_QUERY"                    # General policy lookup


# ---------------------------------------------------------------------------
# Access context and document model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MortgageAccessContext:
    """
    Captures everything needed to evaluate access to a mortgage document.

    Attributes
    ----------
    loan_officer_id : str
        Identifier for the requesting loan officer or system.
    license_state : str
        Two-letter state code where the loan officer holds a SAFE Act license.
    property_state : str
        Two-letter state code where the subject property is located.
    query_context : QueryContext
        The business purpose driving the query.
    adverse_action_notice_required : bool
        True when an adverse action notice will be issued (triggers CFPB UDAAP gate).
    hmda_reporting_context : bool
        True when the query is for HMDA LAR completion/submission (not underwriting).
    loan_purpose : LoanPurpose
        Loan purpose — affects RESPA coverage and HMDA applicability.
    """
    loan_officer_id: str
    license_state: str
    property_state: str
    query_context: QueryContext
    adverse_action_notice_required: bool = False
    hmda_reporting_context: bool = False
    loan_purpose: LoanPurpose = LoanPurpose.HOME_PURCHASE


@dataclass(frozen=True)
class MortgageDocument:
    """
    A document in the mortgage lending knowledge base.

    Attributes
    ----------
    doc_id : str
        Unique identifier.
    category : MortgageDocumentCategory
        Document classification.
    title : str
        Human-readable title.
    contains_protected_class_data : bool
        True if the document contains explicit references to FHA/ECOA protected classes.
    contains_hmda_demographic_fields : bool
        True if the document includes HMDA-collected race/ethnicity/sex/age fields.
    property_state : str
        State where the subject property is located (for jurisdiction matching).
    adverse_action_factors : list[str]
        For denial/counter-offer documents: the specific credit factors cited.
        Must not include protected class attributes.
    is_public_disclosure : bool
        True for documents that are public record or already publicly disclosed.
    """
    doc_id: str
    category: MortgageDocumentCategory
    title: str
    contains_protected_class_data: bool = False
    contains_hmda_demographic_fields: bool = False
    property_state: str = "CA"
    adverse_action_factors: tuple[str, ...] = field(default_factory=tuple)
    is_public_disclosure: bool = False


# ---------------------------------------------------------------------------
# Filter layer 1 — Fair Housing Act disparate impact filter
# ---------------------------------------------------------------------------


class FHADisparateImpactFilter:
    """
    Layer 1: Fair Housing Act (42 U.S.C. §§ 3604–3606) + ECOA (15 U.S.C. § 1691).

    Blocks documents that contain neighborhood demographic data or explicit
    protected class references in any underwriting, appraisal, or decisioning
    context. Disparate impact theory (Texas Dept. of Housing v. Inclusive
    Communities Project, Inc., 576 U.S. 519, 2015) holds that facially neutral
    policies producing discriminatory effects violate the FHA — surfacing
    demographic data in lending decisions creates this risk.

    Categories blocked in underwriting/appraisal contexts:
        - NEIGHBORHOOD_DEMOGRAPHIC: Census tract racial composition
        - CENSUS_TRACT_DATA: ACS data with protected class proxies

    Any document with contains_protected_class_data=True is blocked in
    non-HMDA-reporting contexts regardless of category.
    """

    # Document categories that carry inherent disparate impact risk in lending decisions
    _HIGH_RISK_CATEGORIES: frozenset[MortgageDocumentCategory] = frozenset({
        MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC,
        MortgageDocumentCategory.CENSUS_TRACT_DATA,
    })

    # Contexts where FHA disparate impact analysis applies strictly
    _RESTRICTED_CONTEXTS: frozenset[QueryContext] = frozenset({
        QueryContext.UNDERWRITING_DECISION,
        QueryContext.APPRAISAL_REVIEW,
        QueryContext.ADVERSE_ACTION,
        QueryContext.GENERAL_QUERY,
    })

    def filter(
        self,
        documents: list[MortgageDocument],
        context: MortgageAccessContext,
    ) -> tuple[list[MortgageDocument], list[str]]:
        """
        Apply FHA disparate impact filter.

        Returns
        -------
        (permitted, reasons)
            permitted : documents that passed this filter layer.
            reasons   : human-readable rejection reasons for audit log.
        """
        permitted: list[MortgageDocument] = []
        reasons: list[str] = []

        for doc in documents:
            rejection = self._evaluate(doc, context)
            if rejection is None:
                permitted.append(doc)
            else:
                reasons.append(f"FHA blocked {doc.doc_id}: {rejection}")

        return permitted, reasons

    def _evaluate(
        self,
        doc: MortgageDocument,
        context: MortgageAccessContext,
    ) -> Optional[str]:
        """Return rejection reason string or None if permitted."""
        # Public disclosures are not restricted by FHA in this context
        if doc.is_public_disclosure:
            return None

        # HMDA reporting context: FHA demographic controls still apply
        # but the specific block is handled by HMDAComplianceFilter

        # High-risk demographic categories in restricted contexts
        if (
            doc.category in self._HIGH_RISK_CATEGORIES
            and context.query_context in self._RESTRICTED_CONTEXTS
        ):
            return (
                f"§3604 disparate impact risk — {doc.category.value} contains "
                f"neighborhood demographic data; prohibited in {context.query_context.value} "
                f"context (Texas Dept. of Housing v. Inclusive Communities, 576 U.S. 519)"
            )

        # Documents with explicit protected class data in non-HMDA contexts
        if (
            doc.contains_protected_class_data
            and not context.hmda_reporting_context
            and context.query_context in self._RESTRICTED_CONTEXTS
        ):
            return (
                f"§3604/§1691 — document contains protected class attributes; "
                f"blocked in {context.query_context.value} to prevent discriminatory use"
            )

        return None


# ---------------------------------------------------------------------------
# Filter layer 2 — HMDA compliance filter
# ---------------------------------------------------------------------------


class HMDAComplianceFilter:
    """
    Layer 2: Home Mortgage Disclosure Act (12 U.S.C. § 2801; Reg C, 12 CFR 1003).

    HMDA requires covered lenders to collect race, ethnicity, sex, and age data
    for home purchase, refinance, and home improvement loans. This data is
    collected solely for regulatory fair lending analysis and must NOT be used
    in underwriting decisions (12 CFR 1002.5(d); FFIEC Interagency Fair Lending
    Examination Procedures).

    Filter behavior:
        - HMDA_DEMOGRAPHIC and HMDA_LAR_DATA documents are blocked in all
          underwriting, appraisal, and decisioning contexts.
        - In hmda_reporting_context=True, HMDA data documents are permitted
          to support regulatory LAR preparation and submission.
        - Contains_hmda_demographic_fields=True on any document triggers a
          warning in underwriting contexts (field-level isolation not possible
          without re-extraction, so the document is blocked).
    """

    _BLOCKED_CATEGORIES_IN_UNDERWRITING: frozenset[MortgageDocumentCategory] = frozenset({
        MortgageDocumentCategory.HMDA_LAR_DATA,
        MortgageDocumentCategory.HMDA_DEMOGRAPHIC,
    })

    _UNDERWRITING_CONTEXTS: frozenset[QueryContext] = frozenset({
        QueryContext.UNDERWRITING_DECISION,
        QueryContext.APPRAISAL_REVIEW,
        QueryContext.ADVERSE_ACTION,
    })

    def filter(
        self,
        documents: list[MortgageDocument],
        context: MortgageAccessContext,
    ) -> tuple[list[MortgageDocument], list[str]]:
        permitted: list[MortgageDocument] = []
        reasons: list[str] = []

        for doc in documents:
            rejection = self._evaluate(doc, context)
            if rejection is None:
                permitted.append(doc)
            else:
                reasons.append(f"HMDA blocked {doc.doc_id}: {rejection}")

        return permitted, reasons

    def _evaluate(
        self,
        doc: MortgageDocument,
        context: MortgageAccessContext,
    ) -> Optional[str]:
        # HMDA reporting context: HMDA data documents are permitted
        if context.hmda_reporting_context:
            return None

        # Block HMDA demographic data categories in underwriting/decisioning contexts
        if (
            doc.category in self._BLOCKED_CATEGORIES_IN_UNDERWRITING
            and context.query_context in self._UNDERWRITING_CONTEXTS
        ):
            return (
                f"12 CFR 1002.5(d) — HMDA-collected demographic data "
                f"({doc.category.value}) prohibited in {context.query_context.value}; "
                f"use restricted to Reg C LAR reporting only"
            )

        # Any document embedding HMDA demographic fields is blocked in underwriting
        if (
            doc.contains_hmda_demographic_fields
            and context.query_context in self._UNDERWRITING_CONTEXTS
        ):
            return (
                f"12 CFR 1003.4 — document contains HMDA-collected demographic fields; "
                f"must not be used in {context.query_context.value} per FFIEC guidance"
            )

        return None


# ---------------------------------------------------------------------------
# Filter layer 3 — CFPB UDAAP / ECOA adverse action explainability filter
# ---------------------------------------------------------------------------


class CFPBUDAAPFilter:
    """
    Layer 3: CFPB UDAAP (12 U.S.C. § 5531) + ECOA Adverse Action (12 CFR 1002.9).

    When an adverse action (denial, counter-offer, withdrawal) is issued on a
    covered loan, Reg B requires a written statement of the principal specific
    reasons for the action. The CFPB's Circular 2022-03 (Unanticipated Uses of
    Customer Data; AI/ML Adverse Action) confirmed that black-box or
    unexplainable adverse actions violate ECOA's adverse action notice requirement.

    This filter enforces two rules in ADVERSE_ACTION contexts:
        1. Adverse action notice documents must contain specific, non-protected-
           class credit factors (adverse_action_factors not empty, no protected
           class attributes in factors).
        2. Documents that cannot produce explainable reasons (no factors listed)
           are blocked — they cannot be used as the basis for adverse action.

    In non-ADVERSE_ACTION contexts, this filter is a pass-through.
    """

    _PROTECTED_CLASS_TERMS: frozenset[str] = frozenset({
        "race", "color", "national origin", "religion", "sex", "gender",
        "familial status", "disability", "age", "marital status",
        "public assistance",
    })

    def filter(
        self,
        documents: list[MortgageDocument],
        context: MortgageAccessContext,
    ) -> tuple[list[MortgageDocument], list[str]]:
        permitted: list[MortgageDocument] = []
        reasons: list[str] = []

        for doc in documents:
            rejection = self._evaluate(doc, context)
            if rejection is None:
                permitted.append(doc)
            else:
                reasons.append(f"CFPB UDAAP blocked {doc.doc_id}: {rejection}")

        return permitted, reasons

    def _evaluate(
        self,
        doc: MortgageDocument,
        context: MortgageAccessContext,
    ) -> Optional[str]:
        # Only applies in ADVERSE_ACTION context when notice is required
        if not (
            context.query_context == QueryContext.ADVERSE_ACTION
            and context.adverse_action_notice_required
        ):
            return None

        # Denial and counter-offer documents must have specific factors listed
        if doc.category in (
            MortgageDocumentCategory.DENIAL_NOTICE,
            MortgageDocumentCategory.COUNTER_OFFER,
        ):
            if not doc.adverse_action_factors:
                return (
                    "12 CFR 1002.9 — adverse action document has no specific credit "
                    "factors listed; cannot support explainable adverse action notice "
                    "(CFPB Circular 2022-03)"
                )
            # Check for protected class factors
            for factor in doc.adverse_action_factors:
                factor_lower = factor.lower()
                for protected_term in self._PROTECTED_CLASS_TERMS:
                    if protected_term in factor_lower:
                        return (
                            f"12 CFR 1002.9 / 15 U.S.C. § 1691 — adverse action factor "
                            f"'{factor}' references protected class '{protected_term}'; "
                            f"ECOA prohibits protected class as adverse action reason"
                        )

        # NEIGHBORHOOD_DEMOGRAPHIC and HMDA_DEMOGRAPHIC never valid for adverse action basis
        if doc.category in (
            MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC,
            MortgageDocumentCategory.CENSUS_TRACT_DATA,
            MortgageDocumentCategory.HMDA_DEMOGRAPHIC,
        ):
            return (
                "12 CFR 1002.9 — demographic/neighborhood document cannot serve as "
                "basis for adverse action; would constitute disparate treatment (§3604)"
            )

        return None


# ---------------------------------------------------------------------------
# Filter layer 4 — RESPA / SAFE Act state licensing filter
# ---------------------------------------------------------------------------


class RESPALicensingFilter:
    """
    Layer 4: RESPA (12 U.S.C. § 2607) + SAFE Act (12 U.S.C. § 5104).

    The SAFE Act requires mortgage loan originators (MLOs) to be licensed in
    the state where the property is located. State licensing authorities
    maintain separate registries; a California license does not permit
    originating a Texas mortgage.

    This filter checks that the requesting loan officer's license_state matches
    the property_state of the document. Cross-state access is blocked.

    Exceptions:
        - Federal employees originating under HUD/VA/USDA programs may have
          federal registration (not modeled here).
        - Compliance audit and HMDA reporting queries are not restricted by
          MLO state licensing (compliance staff may review cross-state files).
        - Publicly disclosed documents are not restricted.
    """

    _LICENSE_EXEMPT_CONTEXTS: frozenset[QueryContext] = frozenset({
        QueryContext.COMPLIANCE_AUDIT,
        QueryContext.HMDA_REPORTING,
    })

    def filter(
        self,
        documents: list[MortgageDocument],
        context: MortgageAccessContext,
    ) -> tuple[list[MortgageDocument], list[str]]:
        permitted: list[MortgageDocument] = []
        reasons: list[str] = []

        for doc in documents:
            rejection = self._evaluate(doc, context)
            if rejection is None:
                permitted.append(doc)
            else:
                reasons.append(f"RESPA/SAFE blocked {doc.doc_id}: {rejection}")

        return permitted, reasons

    def _evaluate(
        self,
        doc: MortgageDocument,
        context: MortgageAccessContext,
    ) -> Optional[str]:
        # Public disclosures (e.g., HMDA public LAR) not license-restricted
        if doc.is_public_disclosure:
            return None

        # Compliance and HMDA reporting contexts exempt from MLO licensing requirement
        if context.query_context in self._LICENSE_EXEMPT_CONTEXTS:
            return None

        # MLO must hold license in property state
        if context.license_state.upper() != doc.property_state.upper():
            return (
                f"12 U.S.C. § 5104 (SAFE Act) — loan officer licensed in "
                f"{context.license_state.upper()} cannot originate/access documents "
                f"for property in {doc.property_state.upper()}; cross-state MLO "
                f"license required"
            )

        return None


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------


@dataclass
class MortgageComplianceAuditRecord:
    """
    Immutable record of a mortgage RAG pipeline execution for regulatory audit.

    Mortgage lenders are required under HMDA, ECOA, and BSA to maintain
    records sufficient to reconstruct lending decisions. This record provides
    the evidence trail for fair lending examinations.
    """
    audit_id: str
    loan_officer_id: str
    query_context: QueryContext
    property_state: str
    license_state: str
    documents_requested: int
    documents_permitted: int
    fha_blocks: list[str]
    hmda_blocks: list[str]
    udaap_blocks: list[str]
    respa_blocks: list[str]
    permitted_doc_ids: list[str]
    adverse_action_notice_required: bool
    hmda_reporting_context: bool

    def to_fair_lending_log(self) -> dict:
        """Return dict suitable for fair lending examination log."""
        return {
            "audit_id": self.audit_id,
            "loan_officer_id": self.loan_officer_id,
            "query_context": self.query_context.value,
            "property_state": self.property_state,
            "license_state": self.license_state,
            "requested": self.documents_requested,
            "permitted": self.documents_permitted,
            "blocked_fha": len(self.fha_blocks),
            "blocked_hmda": len(self.hmda_blocks),
            "blocked_udaap": len(self.udaap_blocks),
            "blocked_respa": len(self.respa_blocks),
            "total_blocked": (
                len(self.fha_blocks)
                + len(self.hmda_blocks)
                + len(self.udaap_blocks)
                + len(self.respa_blocks)
            ),
            "permitted_docs": self.permitted_doc_ids,
            "adverse_action_required": self.adverse_action_notice_required,
            "hmda_reporting": self.hmda_reporting_context,
        }


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


class MortgageRAGPipeline:
    """
    Four-layer compliance pipeline for mortgage lending RAG queries.

    Execution order preserves defense-in-depth: each layer independently
    evaluates the documents passed to it by the prior layer, so a document
    blocked by FHA is never evaluated by HMDA (and cannot be reinstated).

    Layer execution order:
        1. FHADisparateImpactFilter  — removes demographic/protected-class docs
        2. HMDAComplianceFilter      — removes HMDA demographic data in underwriting
        3. CFPBUDAAPFilter           — enforces adverse action explainability
        4. RESPALicensingFilter      — enforces cross-state license requirement

    Returns
    -------
    (permitted_docs, audit_record)
    """

    def __init__(self) -> None:
        self._fha = FHADisparateImpactFilter()
        self._hmda = HMDAComplianceFilter()
        self._udaap = CFPBUDAAPFilter()
        self._respa = RESPALicensingFilter()

    def retrieve(
        self,
        documents: list[MortgageDocument],
        context: MortgageAccessContext,
    ) -> tuple[list[MortgageDocument], MortgageComplianceAuditRecord]:
        total_requested = len(documents)

        after_fha, fha_blocks = self._fha.filter(documents, context)
        after_hmda, hmda_blocks = self._hmda.filter(after_fha, context)
        after_udaap, udaap_blocks = self._udaap.filter(after_hmda, context)
        after_respa, respa_blocks = self._respa.filter(after_udaap, context)

        permitted = after_respa
        audit = MortgageComplianceAuditRecord(
            audit_id=str(uuid.uuid4()),
            loan_officer_id=context.loan_officer_id,
            query_context=context.query_context,
            property_state=context.property_state,
            license_state=context.license_state,
            documents_requested=total_requested,
            documents_permitted=len(permitted),
            fha_blocks=fha_blocks,
            hmda_blocks=hmda_blocks,
            udaap_blocks=udaap_blocks,
            respa_blocks=respa_blocks,
            permitted_doc_ids=[d.doc_id for d in permitted],
            adverse_action_notice_required=context.adverse_action_notice_required,
            hmda_reporting_context=context.hmda_reporting_context,
        )
        return permitted, audit


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------


def _build_mortgage_knowledge_base() -> list[MortgageDocument]:
    """Construct a representative mortgage knowledge base."""
    return [
        # Underwriting credit file
        MortgageDocument(
            doc_id="DOC-CREDIT-001",
            category=MortgageDocumentCategory.CREDIT_REPORT,
            title="TransUnion Credit Report — Applicant",
            property_state="TX",
        ),
        MortgageDocument(
            doc_id="DOC-INCOME-001",
            category=MortgageDocumentCategory.INCOME_VERIFICATION,
            title="W-2 and Paystub Verification — 2 Years",
            property_state="TX",
        ),
        MortgageDocument(
            doc_id="DOC-ASSET-001",
            category=MortgageDocumentCategory.ASSET_STATEMENT,
            title="Bank Statements — 3 Months",
            property_state="TX",
        ),
        MortgageDocument(
            doc_id="DOC-DEBT-001",
            category=MortgageDocumentCategory.DEBT_OBLIGATIONS,
            title="Existing Debt Schedule",
            property_state="TX",
        ),
        # Property / collateral documents
        MortgageDocument(
            doc_id="DOC-APPR-001",
            category=MortgageDocumentCategory.APPRAISAL_REPORT,
            title="URAR Appraisal — 4215 Oak Lane, Austin TX",
            property_state="TX",
        ),
        MortgageDocument(
            doc_id="DOC-COMP-001",
            category=MortgageDocumentCategory.COMPARABLE_SALES,
            title="Comparable Sales Grid — Travis County Q1 2026",
            property_state="TX",
        ),
        MortgageDocument(
            doc_id="DOC-PROP-001",
            category=MortgageDocumentCategory.PROPERTY_ASSESSMENT,
            title="Travis County Tax Assessment 2025",
            property_state="TX",
        ),
        # Demographic / neighborhood data — FHA risk
        MortgageDocument(
            doc_id="DOC-DEMO-001",
            category=MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC,
            title="Census Tract 1820 Demographic Profile — Austin MSA",
            contains_protected_class_data=True,
            property_state="TX",
        ),
        MortgageDocument(
            doc_id="DOC-CENSUS-001",
            category=MortgageDocumentCategory.CENSUS_TRACT_DATA,
            title="ACS 2020 5-Year Estimates — Travis County Race/Ethnicity",
            contains_protected_class_data=True,
            property_state="TX",
        ),
        # HMDA data
        MortgageDocument(
            doc_id="DOC-HMDA-001",
            category=MortgageDocumentCategory.HMDA_DEMOGRAPHIC,
            title="HMDA Race/Ethnicity/Sex Collection — Application #44821",
            contains_hmda_demographic_fields=True,
            property_state="TX",
        ),
        MortgageDocument(
            doc_id="DOC-LAR-001",
            category=MortgageDocumentCategory.HMDA_LAR_DATA,
            title="HMDA LAR Entry — 2025 Annual Submission Data",
            contains_hmda_demographic_fields=True,
            property_state="TX",
            is_public_disclosure=False,
        ),
        # Adverse action document — with proper factors
        MortgageDocument(
            doc_id="DOC-DENIAL-GOOD",
            category=MortgageDocumentCategory.DENIAL_NOTICE,
            title="Adverse Action Notice — Credit Score Below Minimum",
            adverse_action_factors=(
                "Credit score below minimum threshold (640)",
                "Debt-to-income ratio exceeds guidelines (52%)",
                "Insufficient reserves (3 months required, 1.2 months documented)",
            ),
            property_state="TX",
        ),
        # Adverse action document — missing factors (UDAAP violation)
        MortgageDocument(
            doc_id="DOC-DENIAL-BAD",
            category=MortgageDocumentCategory.DENIAL_NOTICE,
            title="Adverse Action Notice — No Reasons Listed",
            adverse_action_factors=(),
            property_state="TX",
        ),
        # Counter-offer with protected class factor (ECOA violation)
        MortgageDocument(
            doc_id="DOC-COUNTER-BAD",
            category=MortgageDocumentCategory.COUNTER_OFFER,
            title="Counter-Offer — Alternative Product",
            adverse_action_factors=(
                "National origin — foreign income not counted",
            ),
            property_state="TX",
        ),
        # Internal policy
        MortgageDocument(
            doc_id="DOC-UW-GUIDE",
            category=MortgageDocumentCategory.UNDERWRITING_GUIDELINES,
            title="Credit Policy Manual — Conventional Conforming",
            property_state="TX",
        ),
        # Cross-state document
        MortgageDocument(
            doc_id="DOC-APPR-CA",
            category=MortgageDocumentCategory.APPRAISAL_REPORT,
            title="URAR Appraisal — 890 Sunset Blvd, Los Angeles CA",
            property_state="CA",
        ),
    ]


def run_scenario_a_appraisal_review() -> None:
    """
    Scenario A: Loan officer (TX licensed) queries for appraisal review.

    Expected:
    - FHA blocks DOC-DEMO-001 (neighborhood demographics) and DOC-CENSUS-001
    - FHA blocks DOC-DEMO-001 and DOC-CENSUS-001 (protected_class_data)
    - HMDA blocks DOC-HMDA-001 and DOC-LAR-001 (underwriting context)
    - CFPB UDAAP: APPRAISAL_REVIEW not adverse action — pass-through
    - RESPA: DOC-APPR-CA blocked (CA property, TX license)
    - Permitted: credit file, property docs, policy docs (TX only)
    """
    print("\n" + "=" * 70)
    print("SCENARIO A: Loan Officer — Appraisal Review Query (TX Licensed)")
    print("=" * 70)

    context = MortgageAccessContext(
        loan_officer_id="LO-TX-4471",
        license_state="TX",
        property_state="TX",
        query_context=QueryContext.APPRAISAL_REVIEW,
        adverse_action_notice_required=False,
        hmda_reporting_context=False,
        loan_purpose=LoanPurpose.HOME_PURCHASE,
    )

    kb = _build_mortgage_knowledge_base()
    pipeline = MortgageRAGPipeline()
    permitted, audit = pipeline.retrieve(kb, context)

    print(f"\nDocuments requested : {audit.documents_requested}")
    print(f"Documents permitted : {audit.documents_permitted}")
    print(f"\nFHA blocks ({len(audit.fha_blocks)}):")
    for r in audit.fha_blocks:
        print(f"  {r}")
    print(f"\nHMDA blocks ({len(audit.hmda_blocks)}):")
    for r in audit.hmda_blocks:
        print(f"  {r}")
    print(f"\nCFPB UDAAP blocks ({len(audit.udaap_blocks)}):")
    for r in audit.udaap_blocks:
        print(f"  {r}")
    print(f"\nRESPA/SAFE blocks ({len(audit.respa_blocks)}):")
    for r in audit.respa_blocks:
        print(f"  {r}")
    print(f"\nPermitted documents ({len(permitted)}):")
    for d in permitted:
        print(f"  [{d.category.value}] {d.doc_id}: {d.title}")


def run_scenario_b_hmda_reporting() -> None:
    """
    Scenario B: Compliance analyst queries HMDA data for annual LAR submission.

    Expected:
    - FHA still blocks direct protected class docs in certain contexts,
      but hmda_reporting_context=True allows HMDA data access
    - HMDA filter: hmda_reporting_context=True → HMDA data permitted
    - RESPA: compliance context exempt from license requirement
    - Permitted: HMDA LAR data, demographic collection data
    """
    print("\n" + "=" * 70)
    print("SCENARIO B: Compliance Analyst — HMDA Annual Reporting Query")
    print("=" * 70)

    context = MortgageAccessContext(
        loan_officer_id="CMP-ANALYST-12",
        license_state="WA",
        property_state="TX",
        query_context=QueryContext.HMDA_REPORTING,
        adverse_action_notice_required=False,
        hmda_reporting_context=True,
        loan_purpose=LoanPurpose.HOME_PURCHASE,
    )

    kb = _build_mortgage_knowledge_base()
    pipeline = MortgageRAGPipeline()
    permitted, audit = pipeline.retrieve(kb, context)

    print(f"\nDocuments requested : {audit.documents_requested}")
    print(f"Documents permitted : {audit.documents_permitted}")
    print(f"\nFHA blocks ({len(audit.fha_blocks)}):")
    for r in audit.fha_blocks:
        print(f"  {r}")
    print(f"\nHMDA blocks ({len(audit.hmda_blocks)}):")
    for r in audit.hmda_blocks:
        print(f"  {r}")
    print(f"\nRESPA/SAFE blocks ({len(audit.respa_blocks)}):")
    for r in audit.respa_blocks:
        print(f"  {r}")
    print(f"\nPermitted documents ({len(permitted)}):")
    for d in permitted:
        print(f"  [{d.category.value}] {d.doc_id}: {d.title}")


def run_scenario_c_cross_state_block() -> None:
    """
    Scenario C: Unlicensed cross-state query.

    Loan officer licensed in CA tries to access TX mortgage documents.

    Expected:
    - RESPA/SAFE Act blocks all non-public TX documents
    - Only CA-property documents permitted (if license_state=CA)
    """
    print("\n" + "=" * 70)
    print("SCENARIO C: Cross-State Access — CA Loan Officer, TX Property")
    print("=" * 70)

    context = MortgageAccessContext(
        loan_officer_id="LO-CA-9901",
        license_state="CA",
        property_state="TX",
        query_context=QueryContext.UNDERWRITING_DECISION,
        adverse_action_notice_required=False,
        hmda_reporting_context=False,
        loan_purpose=LoanPurpose.HOME_PURCHASE,
    )

    kb = _build_mortgage_knowledge_base()
    pipeline = MortgageRAGPipeline()
    permitted, audit = pipeline.retrieve(kb, context)

    print(f"\nDocuments requested : {audit.documents_requested}")
    print(f"Documents permitted : {audit.documents_permitted}")
    print(f"\nRESPA/SAFE blocks ({len(audit.respa_blocks)}):")
    for r in audit.respa_blocks[:5]:
        print(f"  {r}")
    if len(audit.respa_blocks) > 5:
        print(f"  ... and {len(audit.respa_blocks) - 5} more")
    print(f"\nPermitted documents ({len(permitted)}):")
    for d in permitted:
        print(f"  [{d.category.value}] {d.doc_id}: {d.title}")


def run_scenario_d_adverse_action() -> None:
    """
    Scenario D: Adverse action notice — CFPB UDAAP explainability gate.

    Expected:
    - DOC-DENIAL-GOOD permitted (has specific credit factors, no protected class)
    - DOC-DENIAL-BAD blocked (no factors — unexplainable adverse action)
    - DOC-COUNTER-BAD blocked (factor references national origin — ECOA violation)
    - DOC-DEMO-001, DOC-CENSUS-001 blocked by FHA and CFPB UDAAP
    """
    print("\n" + "=" * 70)
    print("SCENARIO D: Adverse Action — CFPB UDAAP Explainability Gate")
    print("=" * 70)

    context = MortgageAccessContext(
        loan_officer_id="LO-TX-4471",
        license_state="TX",
        property_state="TX",
        query_context=QueryContext.ADVERSE_ACTION,
        adverse_action_notice_required=True,
        hmda_reporting_context=False,
        loan_purpose=LoanPurpose.HOME_PURCHASE,
    )

    kb = _build_mortgage_knowledge_base()
    pipeline = MortgageRAGPipeline()
    permitted, audit = pipeline.retrieve(kb, context)

    print(f"\nDocuments requested : {audit.documents_requested}")
    print(f"Documents permitted : {audit.documents_permitted}")
    print(f"\nFHA blocks ({len(audit.fha_blocks)}):")
    for r in audit.fha_blocks:
        print(f"  {r}")
    print(f"\nHMDA blocks ({len(audit.hmda_blocks)}):")
    for r in audit.hmda_blocks:
        print(f"  {r}")
    print(f"\nCFPB UDAAP blocks ({len(audit.udaap_blocks)}):")
    for r in audit.udaap_blocks:
        print(f"  {r}")
    print(f"\nRESPA/SAFE blocks ({len(audit.respa_blocks)}):")
    for r in audit.respa_blocks:
        print(f"  {r}")
    print(f"\nPermitted documents ({len(permitted)}):")
    for d in permitted:
        print(f"  [{d.category.value}] {d.doc_id}: {d.title}")


if __name__ == "__main__":
    print("Mortgage Lending RAG — FHA + HMDA + CFPB UDAAP + RESPA Compliance")
    print("Four-layer defense-in-depth pipeline")

    run_scenario_a_appraisal_review()
    run_scenario_b_hmda_reporting()
    run_scenario_c_cross_state_block()
    run_scenario_d_adverse_action()

    print("\n" + "=" * 70)
    print("All scenarios complete.")
    print("=" * 70)
