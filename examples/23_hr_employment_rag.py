"""
23_hr_employment_rag.py — NYC Local Law 144 AEDT + EEOC AI Hiring Guidance +
Illinois AI Video Interview Act compliance for an HR/talent acquisition
knowledge base assistant.

Demonstrates defense-in-depth RAG retrieval where three overlapping regulatory
frameworks each impose independent access control obligations on an employer's
automated employment decision tool (AEDT) and supporting knowledge base:

    Layer 1  — NYC Local Law 144 (Automated Employment Decision Tools,
               effective July 5, 2023):
               New York City employers and employment agencies that use
               AEDT in hiring or promotion decisions must: (a) conduct an
               independent bias audit within the prior year; (b) publish the
               audit summary and AEDT usage policy on their website; (c)
               notify candidates at least 10 business days before the AEDT
               is used. Employers who have not completed a bias audit, or
               whose audit reveals disparate impact without remediation, may
               not use the AEDT for NYC-based candidates.

    Layer 2  — EEOC AI Guidance (May 2023) + Title VII (42 U.S.C. §2000e)
               + ADEA (29 U.S.C. §623):
               Employers that use AI-assisted hiring tools bear liability for
               Title VII disparate impact if the tool selects candidates at a
               significantly different rate based on race, color, religion,
               sex, or national origin. The EEOC's 4/5 rule applies: if the
               selection rate for a protected class is less than 80% of the
               highest-selecting group, disparate impact is presumed. The
               ADEA independently prohibits age-correlated features for
               workers 40+.

    Layer 3  — Illinois AI Video Interview Act (AIVIA, 820 ILCS 42/1,
               effective January 1, 2020):
               Employers that use AI to analyze video interviews must: (a)
               notify all applicants before the interview that AI will be
               used to evaluate responses; (b) explain how the AI works and
               what attributes it evaluates; (c) obtain written consent;
               (d) not share video interviews with third parties except for
               vendors necessary to evaluate the applicant; (e) destroy
               video recordings within 14 days of candidate request.

Scenarios
---------

  A. NYC employer with completed bias audit queries candidate assessment docs:
     NYC LL 144: Audit complete + impact ratio OK + notice given — permit.
     EEOC: 4/5 rule satisfied — permit.
     AIVIA: Consent obtained — permit.
     Result: Candidate scoring rubrics and assessment docs returned.

  B. NYC employer with no bias audit queries the same docs:
     NYC LL 144: No audit — blocked.
     Result: Only publicly releasable policy docs returned.

  C. Employer queries AI video analysis data without consent:
     AIVIA: No candidate consent — video analysis blocked.
     Result: Non-video assessment materials permitted.

  D. Tool exhibiting EEOC disparate impact queries protected-class data:
     EEOC: Selection rate ratio below 4/5 threshold — remediation required.
     Result: Protected-class demographic data blocked.

No external dependencies required.

Run:
    python examples/23_hr_employment_rag.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Optional


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class HRDocumentCategory(str, Enum):
    """Categories of documents in an HR/talent acquisition knowledge base."""

    # Candidate assessment / AEDT outputs
    CANDIDATE_SCORING_RUBRIC = "CANDIDATE_SCORING_RUBRIC"
    RESUME_SCREENING_CRITERIA = "RESUME_SCREENING_CRITERIA"
    SKILL_ASSESSMENT_RESULT = "SKILL_ASSESSMENT_RESULT"
    AUTOMATED_RANKING = "AUTOMATED_RANKING"

    # Video interview data
    VIDEO_INTERVIEW_RECORDING = "VIDEO_INTERVIEW_RECORDING"
    VIDEO_AI_ANALYSIS_REPORT = "VIDEO_AI_ANALYSIS_REPORT"
    VIDEO_TRANSCRIPT = "VIDEO_TRANSCRIPT"

    # Demographic / protected class data
    EEO_DEMOGRAPHIC_DATA = "EEO_DEMOGRAPHIC_DATA"
    IMPACT_RATIO_BY_PROTECTED_CLASS = "IMPACT_RATIO_BY_PROTECTED_CLASS"
    AGE_CORRELATED_FEATURE_WEIGHTS = "AGE_CORRELATED_FEATURE_WEIGHTS"

    # Administrative / policy
    AEDT_BIAS_AUDIT_SUMMARY = "AEDT_BIAS_AUDIT_SUMMARY"
    AEDT_USAGE_POLICY = "AEDT_USAGE_POLICY"
    AIVIA_CONSENT_FORM = "AIVIA_CONSENT_FORM"
    JOB_DESCRIPTION = "JOB_DESCRIPTION"
    HR_POLICY_DOCUMENT = "HR_POLICY_DOCUMENT"


# Document categories that are NYC LL 144 AEDT outputs — require audit clearance
_AEDT_OUTPUT_CATEGORIES: FrozenSet[HRDocumentCategory] = frozenset({
    HRDocumentCategory.CANDIDATE_SCORING_RUBRIC,
    HRDocumentCategory.RESUME_SCREENING_CRITERIA,
    HRDocumentCategory.SKILL_ASSESSMENT_RESULT,
    HRDocumentCategory.AUTOMATED_RANKING,
})

# Video data categories — require AIVIA consent
_VIDEO_CATEGORIES: FrozenSet[HRDocumentCategory] = frozenset({
    HRDocumentCategory.VIDEO_INTERVIEW_RECORDING,
    HRDocumentCategory.VIDEO_AI_ANALYSIS_REPORT,
    HRDocumentCategory.VIDEO_TRANSCRIPT,
})

# Protected class demographic categories — gated on EEOC disparate impact check
_PROTECTED_CLASS_CATEGORIES: FrozenSet[HRDocumentCategory] = frozenset({
    HRDocumentCategory.EEO_DEMOGRAPHIC_DATA,
    HRDocumentCategory.IMPACT_RATIO_BY_PROTECTED_CLASS,
    HRDocumentCategory.AGE_CORRELATED_FEATURE_WEIGHTS,
})


# ---------------------------------------------------------------------------
# Context and document dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidateAccessContext:
    """
    Runtime context for an HR system user accessing the knowledge base.

    Attributes
    ----------
    user_id : str
        Unique identifier for the HR system user.
    employer_jurisdiction : FrozenSet[str]
        Set of US city/state codes where the employer operates and uses
        AEDT (e.g., frozenset({"NYC", "NY", "IL"})). NYC Local Law 144
        applies when "NYC" is present.
    aedt_bias_audit_completed : bool
        True if an independent bias audit has been completed within the
        prior 12 months per NYC Local Law 144.
    aedt_audit_impact_ratios_acceptable : bool
        True if the bias audit's impact ratios are within acceptable bounds,
        or if remediation has been applied to bring ratios into compliance.
    aedt_candidate_notice_given : bool
        True if the required 10-business-day advance notice has been given
        to the candidate before AEDT is applied.
    eeoc_selection_rate_ratio : Optional[float]
        Most recent 4/5 rule measurement: lowest group selection rate /
        highest group selection rate. None means not yet measured.
    eeoc_testing_sample_adequate : bool
        True if the testing sample is large enough for a valid 4/5 analysis
        (EEOC guidance requires at least 30 applicants per group).
    aivia_candidate_consented : bool
        True if the candidate has provided written consent for AI-based
        video interview analysis per 820 ILCS 42/15.
    aivia_disclosure_provided : bool
        True if the employer has notified the candidate that AI will be used
        and explained how it evaluates responses.
    candidate_requested_video_deletion : bool
        True if the candidate has requested deletion of their video. If True,
        all video data must be destroyed within 14 days — access blocked.
    """

    user_id: str
    employer_jurisdiction: FrozenSet[str]
    aedt_bias_audit_completed: bool
    aedt_audit_impact_ratios_acceptable: bool
    aedt_candidate_notice_given: bool
    eeoc_selection_rate_ratio: Optional[float]
    eeoc_testing_sample_adequate: bool
    aivia_candidate_consented: bool
    aivia_disclosure_provided: bool
    candidate_requested_video_deletion: bool = False


@dataclass(frozen=True)
class HRDocument:
    """
    A document in the HR/talent acquisition knowledge base.

    Attributes
    ----------
    document_id : str
        Unique document identifier.
    title : str
        Document title.
    category : HRDocumentCategory
        Document classification for regulatory routing.
    candidate_id : Optional[str]
        If this document is specific to a candidate, their identifier.
        None for generic policy/rubric documents.
    is_publicly_releasable : bool
        True if this document is published on the employer's public website
        (e.g., AEDT bias audit summaries, usage policies).
    """

    document_id: str
    title: str
    category: HRDocumentCategory
    candidate_id: Optional[str] = None
    is_publicly_releasable: bool = False


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------


@dataclass
class HRComplianceAuditRecord:
    """
    Audit record for an HR knowledge base retrieval event.
    """

    query_id: str
    user_id: str
    total_candidates: int = 0
    nyc_ll144_permitted: int = 0
    nyc_ll144_blocked: int = 0
    eeoc_permitted: int = 0
    eeoc_blocked: int = 0
    aivia_permitted: int = 0
    aivia_blocked: int = 0
    final_permitted: int = 0
    final_blocked: int = 0
    block_reasons: list = field(default_factory=list)

    def to_audit_log(self) -> dict:
        return {
            "query_id": self.query_id,
            "user_id": self.user_id,
            "total_candidates": self.total_candidates,
            "layers": {
                "nyc_ll144": {
                    "permitted": self.nyc_ll144_permitted,
                    "blocked": self.nyc_ll144_blocked,
                },
                "eeoc": {
                    "permitted": self.eeoc_permitted,
                    "blocked": self.eeoc_blocked,
                },
                "aivia": {
                    "permitted": self.aivia_permitted,
                    "blocked": self.aivia_blocked,
                },
            },
            "final": {
                "permitted": self.final_permitted,
                "blocked": self.final_blocked,
            },
            "block_reasons": self.block_reasons,
        }


# ---------------------------------------------------------------------------
# Layer 1 — NYC Local Law 144
# ---------------------------------------------------------------------------


class NYCLL144Filter:
    """
    Layer 1: NYC Local Law 144 — Automated Employment Decision Tools.

    For NYC-jurisdiction employers using AEDT:
    - Bias audit must be completed within the prior 12 months
    - Audit impact ratios must be acceptable (or remediation applied)
    - Candidate must have received ≥10 business days' advance notice

    Documents in _AEDT_OUTPUT_CATEGORIES are blocked if any NYC LL 144
    condition is not satisfied. Publicly releasable documents (audit
    summaries, usage policies) pass regardless.

    References
    ----------
    NYC Local Law 144 of 2021 — Int. No. 1894-A
    NYC DCWP Final Rules (April 2023)
    """

    def _nyc_applies(self, ctx: CandidateAccessContext) -> bool:
        return "NYC" in ctx.employer_jurisdiction

    def _evaluate(
        self,
        doc: HRDocument,
        ctx: CandidateAccessContext,
    ) -> Optional[str]:
        if doc.is_publicly_releasable:
            return None

        # Only applies to AEDT outputs and NYC employers
        if doc.category not in _AEDT_OUTPUT_CATEGORIES:
            return None

        if not self._nyc_applies(ctx):
            return None

        if not ctx.aedt_bias_audit_completed:
            return (
                "NYC LL 144: Independent bias audit not completed within prior "
                "12 months — AEDT may not be used for NYC candidates "
                "[NYC Admin. Code §20-871(c)]"
            )

        if not ctx.aedt_audit_impact_ratios_acceptable:
            return (
                "NYC LL 144: Bias audit impact ratios exceed acceptable bounds "
                "without remediation — AEDT outputs blocked pending audit remediation "
                "[NYC Admin. Code §20-871(b)]"
            )

        if not ctx.aedt_candidate_notice_given:
            return (
                "NYC LL 144: Candidate has not received required 10-business-day "
                "advance notice before AEDT application "
                "[NYC Admin. Code §20-871(d)]"
            )

        return None

    def filter(
        self,
        documents: list[HRDocument],
        context: CandidateAccessContext,
        audit: HRComplianceAuditRecord,
    ) -> list[HRDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
                audit.nyc_ll144_permitted += 1
            else:
                audit.nyc_ll144_blocked += 1
                audit.block_reasons.append(
                    {"document_id": doc.document_id, "layer": "NYC_LL144", "reason": reason}
                )
        return permitted


# ---------------------------------------------------------------------------
# Layer 2 — EEOC AI Guidance + Title VII / ADEA
# ---------------------------------------------------------------------------

_EEOC_4_5_THRESHOLD: float = 0.80


class EEOCFilter:
    """
    Layer 2: EEOC AI Guidance (May 2023) + Title VII / ADEA disparate impact.

    Protected-class demographic data and age-correlated feature weights are
    blocked when the tool's 4/5 rule measurement indicates disparate impact
    without remediation, or when testing data is insufficient to evaluate.

    AEDT outputs are also blocked if the selection rate ratio indicates
    disparate impact — operating the tool in this state violates Title VII.

    References
    ----------
    EEOC Technical Assistance Document: AI and the Americans with Disabilities
    Act (May 2023)
    EEOC Technical Assistance: Assessing Adverse Impact in Software, Algorithms,
    and Artificial Intelligence Used in Employment (May 2023)
    29 CFR Part 1607 — Uniform Guidelines on Employee Selection Procedures
    """

    def _evaluate(
        self,
        doc: HRDocument,
        ctx: CandidateAccessContext,
    ) -> Optional[str]:
        if doc.is_publicly_releasable:
            return None

        # Protected class demographic data: blocked if disparate impact not resolved
        if doc.category in _PROTECTED_CLASS_CATEGORIES:
            if not ctx.eeoc_testing_sample_adequate:
                return (
                    "EEOC: Protected class testing sample inadequate for 4/5 analysis "
                    "(minimum 30 applicants per group required) "
                    "[29 CFR §1607.4(D)]"
                )
            if ctx.eeoc_selection_rate_ratio is None:
                return (
                    "EEOC: Selection rate ratio not calculated — disparate impact "
                    "analysis required before accessing protected class data "
                    "[29 CFR §1607.3(A)]"
                )
            if ctx.eeoc_selection_rate_ratio < _EEOC_4_5_THRESHOLD:
                return (
                    f"EEOC: Tool exhibits disparate impact (selection rate ratio "
                    f"{ctx.eeoc_selection_rate_ratio:.2f} < 0.80 threshold); "
                    f"protected class data access blocked pending remediation "
                    f"[29 CFR §1607.4(D); Title VII 42 U.S.C. §2000e-2]"
                )

        # AEDT outputs: also blocked when disparate impact confirmed and unresolved
        if doc.category in _AEDT_OUTPUT_CATEGORIES:
            if (
                ctx.eeoc_selection_rate_ratio is not None
                and ctx.eeoc_selection_rate_ratio < _EEOC_4_5_THRESHOLD
                and ctx.eeoc_testing_sample_adequate
            ):
                return (
                    f"EEOC: AEDT exhibits disparate impact (ratio "
                    f"{ctx.eeoc_selection_rate_ratio:.2f}); continued use without "
                    f"remediation violates Title VII "
                    f"[42 U.S.C. §2000e-2(k); 29 CFR §1607.3]"
                )

        return None

    def filter(
        self,
        documents: list[HRDocument],
        context: CandidateAccessContext,
        audit: HRComplianceAuditRecord,
    ) -> list[HRDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
                audit.eeoc_permitted += 1
            else:
                audit.eeoc_blocked += 1
                audit.block_reasons.append(
                    {"document_id": doc.document_id, "layer": "EEOC", "reason": reason}
                )
        return permitted


# ---------------------------------------------------------------------------
# Layer 3 — Illinois AI Video Interview Act (AIVIA)
# ---------------------------------------------------------------------------


class AIVIAFilter:
    """
    Layer 3: Illinois AI Video Interview Act (AIVIA, 820 ILCS 42).

    Video interview recordings, AI analysis reports, and transcripts are
    blocked unless:
    - Employer has provided disclosure about AI use and what it evaluates
    - Candidate has provided written consent

    If the candidate has requested video deletion, all video data is
    blocked (must be destroyed within 14 days).

    References
    ----------
    820 ILCS 42/1 — AI Video Interview Act (effective January 1, 2020)
    820 ILCS 42/15 — Consent requirements
    820 ILCS 42/25 — Data destruction
    """

    def _evaluate(
        self,
        doc: HRDocument,
        ctx: CandidateAccessContext,
    ) -> Optional[str]:
        if doc.is_publicly_releasable:
            return None

        if doc.category not in _VIDEO_CATEGORIES:
            return None

        # Deletion request overrides all — data must be destroyed
        if ctx.candidate_requested_video_deletion:
            return (
                "AIVIA: Candidate has requested video deletion; all video data "
                "must be destroyed within 14 days and may not be accessed "
                "[820 ILCS 42/25]"
            )

        # Disclosure must precede consent
        if not ctx.aivia_disclosure_provided:
            return (
                "AIVIA: Employer has not provided required disclosure explaining "
                "AI video analysis before the interview "
                "[820 ILCS 42/15(1)]"
            )

        # Consent required before AI analysis
        if not ctx.aivia_candidate_consented:
            return (
                "AIVIA: Candidate written consent for AI video analysis not obtained "
                "[820 ILCS 42/15(2)]"
            )

        return None

    def filter(
        self,
        documents: list[HRDocument],
        context: CandidateAccessContext,
        audit: HRComplianceAuditRecord,
    ) -> list[HRDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
                audit.aivia_permitted += 1
            else:
                audit.aivia_blocked += 1
                audit.block_reasons.append(
                    {"document_id": doc.document_id, "layer": "AIVIA", "reason": reason}
                )
        return permitted


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


class HRRAGPipeline:
    """
    Three-layer defense-in-depth RAG pipeline for HR/talent acquisition
    knowledge base systems.

    Retrieval order:
        NYC LL 144 AEDT  →  EEOC / Title VII / ADEA  →  AIVIA

    All three layers must permit a document before it is returned.
    """

    def __init__(self) -> None:
        self._nyc = NYCLL144Filter()
        self._eeoc = EEOCFilter()
        self._aivia = AIVIAFilter()

    def retrieve(
        self,
        candidates: list[HRDocument],
        context: CandidateAccessContext,
    ) -> tuple[list[HRDocument], HRComplianceAuditRecord]:
        audit = HRComplianceAuditRecord(
            query_id=str(uuid.uuid4()),
            user_id=context.user_id,
            total_candidates=len(candidates),
        )

        after_nyc = self._nyc.filter(candidates, context, audit)
        after_eeoc = self._eeoc.filter(after_nyc, context, audit)
        final = self._aivia.filter(after_eeoc, context, audit)

        audit.final_permitted = len(final)
        audit.final_blocked = len(candidates) - len(final)

        return final, audit


# ---------------------------------------------------------------------------
# Scenario demonstrations
# ---------------------------------------------------------------------------


def _make_corpus() -> list[HRDocument]:
    return [
        HRDocument(
            document_id="D-001",
            title="Resume Screening Criteria v3",
            category=HRDocumentCategory.RESUME_SCREENING_CRITERIA,
        ),
        HRDocument(
            document_id="D-002",
            title="Candidate Automated Ranking — Candidate A",
            category=HRDocumentCategory.AUTOMATED_RANKING,
            candidate_id="CAND-A",
        ),
        HRDocument(
            document_id="D-003",
            title="Video Interview AI Analysis — Candidate A",
            category=HRDocumentCategory.VIDEO_AI_ANALYSIS_REPORT,
            candidate_id="CAND-A",
        ),
        HRDocument(
            document_id="D-004",
            title="EEO Demographic Impact Report Q1 2024",
            category=HRDocumentCategory.EEO_DEMOGRAPHIC_DATA,
        ),
        HRDocument(
            document_id="D-005",
            title="AEDT Bias Audit Summary — Published",
            category=HRDocumentCategory.AEDT_BIAS_AUDIT_SUMMARY,
            is_publicly_releasable=True,
        ),
        HRDocument(
            document_id="D-006",
            title="Job Description — Software Engineer",
            category=HRDocumentCategory.JOB_DESCRIPTION,
        ),
    ]


def scenario_a_compliant_nyc_employer() -> None:
    """NYC employer with audit, notice, consent — all docs permitted."""
    print("\n--- Scenario A: Compliant NYC Employer (Audit + Notice + Consent) ---")
    pipeline = HRRAGPipeline()
    ctx = CandidateAccessContext(
        user_id="HR-001",
        employer_jurisdiction=frozenset({"NYC", "NY"}),
        aedt_bias_audit_completed=True,
        aedt_audit_impact_ratios_acceptable=True,
        aedt_candidate_notice_given=True,
        eeoc_selection_rate_ratio=0.88,
        eeoc_testing_sample_adequate=True,
        aivia_candidate_consented=True,
        aivia_disclosure_provided=True,
    )
    docs, audit = pipeline.retrieve(_make_corpus(), ctx)
    print(f"  Permitted: {[d.document_id for d in docs]}")
    print(f"  Blocked: {audit.final_blocked}")


def scenario_b_no_bias_audit() -> None:
    """NYC employer without completed bias audit — AEDT outputs blocked."""
    print("\n--- Scenario B: NYC Employer — No Bias Audit (AEDT Blocked) ---")
    pipeline = HRRAGPipeline()
    ctx = CandidateAccessContext(
        user_id="HR-002",
        employer_jurisdiction=frozenset({"NYC", "NY"}),
        aedt_bias_audit_completed=False,
        aedt_audit_impact_ratios_acceptable=False,
        aedt_candidate_notice_given=True,
        eeoc_selection_rate_ratio=0.88,
        eeoc_testing_sample_adequate=True,
        aivia_candidate_consented=True,
        aivia_disclosure_provided=True,
    )
    docs, audit = pipeline.retrieve(_make_corpus(), ctx)
    print(f"  Permitted: {[d.document_id for d in docs]}")
    print(f"  NYC LL 144 blocked: {audit.nyc_ll144_blocked}")


def scenario_c_no_video_consent() -> None:
    """Employer without video consent — video analysis blocked."""
    print("\n--- Scenario C: No Video Interview Consent (AIVIA Block) ---")
    pipeline = HRRAGPipeline()
    ctx = CandidateAccessContext(
        user_id="HR-003",
        employer_jurisdiction=frozenset({"IL"}),
        aedt_bias_audit_completed=True,
        aedt_audit_impact_ratios_acceptable=True,
        aedt_candidate_notice_given=True,
        eeoc_selection_rate_ratio=0.90,
        eeoc_testing_sample_adequate=True,
        aivia_candidate_consented=False,
        aivia_disclosure_provided=True,
    )
    docs, audit = pipeline.retrieve(_make_corpus(), ctx)
    print(f"  Permitted: {[d.document_id for d in docs]}")
    print(f"  AIVIA blocked: {audit.aivia_blocked}")


def scenario_d_disparate_impact() -> None:
    """Tool exhibits disparate impact — protected class data blocked."""
    print("\n--- Scenario D: Disparate Impact (EEOC 4/5 Rule Violation) ---")
    pipeline = HRRAGPipeline()
    ctx = CandidateAccessContext(
        user_id="HR-004",
        employer_jurisdiction=frozenset({"TX"}),
        aedt_bias_audit_completed=True,
        aedt_audit_impact_ratios_acceptable=True,
        aedt_candidate_notice_given=True,
        eeoc_selection_rate_ratio=0.68,  # Below 0.80 threshold
        eeoc_testing_sample_adequate=True,
        aivia_candidate_consented=True,
        aivia_disclosure_provided=True,
    )
    docs, audit = pipeline.retrieve(_make_corpus(), ctx)
    print(f"  Permitted: {[d.document_id for d in docs]}")
    print(f"  EEOC blocked: {audit.eeoc_blocked}")


if __name__ == "__main__":
    scenario_a_compliant_nyc_employer()
    scenario_b_no_bias_audit()
    scenario_c_no_video_consent()
    scenario_d_disparate_impact()
    print("\nAll scenarios complete.")
