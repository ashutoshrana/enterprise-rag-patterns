"""
19_pharma_clinical_rag.py — FDA 21 CFR Part 11 + ICH E6(R3) GCP + HIPAA compliance
for a pharmaceutical company's clinical trial data knowledge base assistant.

Demonstrates defense-in-depth RAG retrieval where three overlapping regulatory
frameworks each impose independent access control obligations on a clinical trial
information system:

    Layer 1  — FDA 21 CFR Part 11 (Electronic Records; Electronic Signatures):
               Any computer system that creates, modifies, maintains, archives,
               retrieves, or transmits records required under FDA regulations must
               meet Part 11's technical controls. This includes: access controls
               (§11.10(d)), audit trails (§11.10(e)), system validation (§11.10(a)),
               and authority checks (§11.10(g)). Only personnel with valid GxP
               credentials may access controlled records.

    Layer 2  — ICH E6(R3) Good Clinical Practice (GCP):
               The international standard for clinical trial conduct. Investigators,
               sponsors, and monitors have specific access rights based on their
               trial role. Blinding is a critical GCP requirement — unblinded data
               (randomization codes, treatment assignments, interim analyses) may
               only be accessed by designated unblinded personnel. Unauthorized
               unblinding is a serious GCP violation.

    Layer 3  — HIPAA Privacy Rule (45 CFR Part 164):
               Clinical trial participants are research subjects. Their individually
               identifiable health information (PHI) requires minimum necessary
               access, authorization, and accounting of disclosures. Subject
               participant records are PHI; de-identified aggregate data is not.

Scenarios
---------

  A. Blinded statistician queries interim analysis data:
     ICH GCP blocks unblinded interim analysis documents (blinding violation).
     Non-blinded aggregate efficacy summaries permitted. PHI not returned.

  B. Clinical Research Associate (CRA) conducts site audit:
     21 CFR Part 11 permits access with valid credentials. GCP permits
     monitor access to source documents. HIPAA permits minimum-necessary
     subject data for audit purposes. Full access to audit-scope documents.

  C. Unauthorized external query (no GxP credentials):
     21 CFR Part 11 blocks all controlled electronic records (§11.10(d)).
     No clinical documents returned.

  D. Principal Investigator queries adverse event records:
     21 CFR Part 11 permits. GCP permits (PI is responsible for AEs at site).
     HIPAA minimum necessary applies — full AE records returned, unblinded
     subject identifiers permitted for PI at enrolled site.

No external dependencies required.

Run:
    python examples/19_pharma_clinical_rag.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------

class ClinicalRecordCategory(str, Enum):
    """
    Categories of clinical trial records by regulatory classification.
    Determines which regulatory layers apply.
    """
    # GCP/ICH source documents and trial data
    PROTOCOL = "PROTOCOL"                             # Trial protocol and amendments
    PATIENT_DATA_IDENTIFIABLE = "PATIENT_DATA_ID"     # PHI — identifiable subject records
    PATIENT_DATA_DEIDENTIFIED = "PATIENT_DATA_DEID"   # De-identified subject data
    ADVERSE_EVENT = "ADVERSE_EVENT"                   # SAE/AE reports (may contain PHI)
    SERIOUS_ADVERSE_EVENT = "SAE"                     # SAE — expedited reporting required
    LAB_RESULT = "LAB_RESULT"                         # Clinical laboratory data
    INVESTIGATOR_BROCHURE = "INV_BROCHURE"            # Investigational product summary
    # Blinding-controlled documents
    RANDOMIZATION_CODE = "RANDOMIZATION_CODE"         # Treatment allocation key — UNBLINDED
    INTERIM_ANALYSIS = "INTERIM_ANALYSIS"             # Unblinded interim efficacy data
    BLIND_BREAK_LOG = "BLIND_BREAK_LOG"               # Emergency unblinding records
    # Regulatory/quality records
    REGULATORY_SUBMISSION = "REG_SUBMISSION"          # IND/NDA/BLA submission documents
    CLINICAL_STUDY_REPORT = "CSR"                     # Final study report
    QUALITY_SYSTEM_RECORD = "QSR"                     # 21 CFR Part 820 quality records
    # Public / non-controlled
    PUBLIC_SUMMARY = "PUBLIC_SUMMARY"                 # ClinicalTrials.gov-level information


class TrialPhase(str, Enum):
    """Clinical trial phases with associated regulatory requirements."""
    PRECLINICAL = "PRECLINICAL"     # Pre-IND studies
    PHASE_I = "PHASE_I"             # First-in-human, safety/tolerability
    PHASE_II = "PHASE_II"           # Dose-finding, preliminary efficacy
    PHASE_III = "PHASE_III"         # Pivotal trials for marketing authorization
    PHASE_IV = "PHASE_IV"           # Post-marketing commitment studies
    POST_MARKET = "POST_MARKET"     # Post-authorization pharmacovigilance


class GCPRole(str, Enum):
    """
    Clinical trial personnel roles under ICH E6(R3).
    Each role has distinct data access rights and responsibilities.
    """
    PRINCIPAL_INVESTIGATOR = "PI"           # Site physician responsible for trial conduct
    SUB_INVESTIGATOR = "SUB_I"              # Delegated investigator at site
    CLINICAL_RESEARCH_ASSOCIATE = "CRA"     # Sponsor's monitor at site
    DATA_MANAGER = "DM"                     # Electronic data capture and cleaning
    REGULATORY_AFFAIRS = "RA"               # IND/NDA/BLA submissions
    BLINDED_STATISTICIAN = "BLIND_STAT"     # Maintains blinding during analysis
    UNBLINDED_STATISTICIAN = "UNBLIND_STAT" # Authorized for interim analysis
    PHARMACOVIGILANCE = "PV"                # Safety officer / DSMB liaison
    SPONSOR_MEDICAL_MONITOR = "MED_MON"     # Clinical oversight from sponsor
    QUALITY_ASSURANCE = "QA"                # GCP compliance auditor
    EXTERNAL_AUDITOR = "EXT_AUDIT"          # Regulatory authority inspector (e.g. FDA)


# ---------------------------------------------------------------------------
# Access context
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClinicalAccessContext:
    """
    Regulatory access context for a clinical trial knowledge base query.

    Attributes
    ----------
    role:
        GCP role of the requesting personnel.
    gxp_credentials_valid:
        True if the user has current, validated GxP system credentials
        meeting 21 CFR Part 11 §11.10(d) access control requirements.
    gcp_training_current:
        True if GCP training (ICH E6 training certificate) is current
        (typically annual renewal required).
    authorized_trial_ids:
        Set of trial identifiers the user is authorized to access.
        Empty set means no trial-specific access.
    is_blinded:
        True if the user must maintain blinding (e.g. BLINDED_STATISTICIAN,
        most investigators during active trial). Blinded users cannot access
        randomization codes, interim analyses, or blind-break logs.
    authorized_trial_phases:
        Trial phases the user may access. Preclinical data restricted to
        sponsor personnel; Phase III pivotal data subject to tighter controls.
    phi_authorized:
        True if the user has a signed IRB/ethics committee authorization
        to access individually identifiable subject PHI.
    minimum_necessary_scope:
        The HIPAA minimum necessary scope for this request — used to
        block access to PHI beyond what is needed for the stated purpose.
    site_id:
        Site identifier. PIs/CRAs may only access records from their enrolled site.
    user_id:
        Pseudonymous identifier for 21 CFR Part 11 audit trail.
    """
    role: GCPRole
    gxp_credentials_valid: bool
    gcp_training_current: bool
    authorized_trial_ids: frozenset[str]
    is_blinded: bool
    authorized_trial_phases: frozenset[TrialPhase]
    phi_authorized: bool
    site_id: Optional[str] = None
    minimum_necessary_scope: frozenset[ClinicalRecordCategory] = field(
        default_factory=frozenset
    )
    user_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# Document metadata
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClinicalDocument:
    """A clinical trial knowledge base document with regulatory metadata."""
    doc_id: str
    content: str
    category: ClinicalRecordCategory
    trial_id: str
    trial_phase: TrialPhase
    is_unblinded_data: bool = False   # True = randomization code, interim analysis
    contains_phi: bool = False        # True = individually identifiable subject data
    site_id: Optional[str] = None     # Non-None = site-specific document
    is_controlled_record: bool = True # 21 CFR Part 11 applies (False = public only)


# ---------------------------------------------------------------------------
# Layer 1 — FDA 21 CFR Part 11 Filter
# ---------------------------------------------------------------------------

class FDA21CFRPart11Filter:
    """
    Enforces FDA 21 CFR Part 11 electronic records access controls.

    21 CFR Part 11 §11.10(d): "Limiting system access to authorized individuals."
    §11.10(g): "Use of authority checks to ensure that only authorized
    individuals can use the system, electronically sign a record, access the
    operation or computer system input or output device, alter a record, or
    perform the operation at hand."

    Practically: any system that creates, modifies, or retrieves GxP-regulated
    electronic records must enforce validated access controls. Retrieval from a
    RAG system that surfaces controlled clinical records falls under Part 11.
    """

    # Roles that require explicit GxP credentials validation
    _CONTROLLED_ROLES: frozenset[GCPRole] = frozenset({
        GCPRole.PRINCIPAL_INVESTIGATOR,
        GCPRole.SUB_INVESTIGATOR,
        GCPRole.CLINICAL_RESEARCH_ASSOCIATE,
        GCPRole.DATA_MANAGER,
        GCPRole.REGULATORY_AFFAIRS,
        GCPRole.BLINDED_STATISTICIAN,
        GCPRole.UNBLINDED_STATISTICIAN,
        GCPRole.PHARMACOVIGILANCE,
        GCPRole.SPONSOR_MEDICAL_MONITOR,
        GCPRole.QUALITY_ASSURANCE,
        GCPRole.EXTERNAL_AUDITOR,
    })

    def filter(
        self,
        documents: list[ClinicalDocument],
        ctx: ClinicalAccessContext,
    ) -> tuple[list[ClinicalDocument], list[str]]:
        """Return (permitted_docs, blocked_reasons)."""
        permitted: list[ClinicalDocument] = []
        blocked_reasons: list[str] = []

        for doc in documents:
            reason = self._evaluate(doc, ctx)
            if reason:
                blocked_reasons.append(f"21 CFR Part 11 blocked {doc.doc_id}: {reason}")
            else:
                permitted.append(doc)

        return permitted, blocked_reasons

    def _evaluate(self, doc: ClinicalDocument, ctx: ClinicalAccessContext) -> str | None:
        # Public records do not require Part 11 access controls
        if not doc.is_controlled_record:
            return None

        # §11.10(d): access limited to authorized individuals
        if not ctx.gxp_credentials_valid:
            return (
                "GxP system credentials required to access controlled electronic "
                "records (§11.10(d)); valid credentials not on file"
            )

        # §11.10(g): authority check — must have trial-specific authorization
        if doc.trial_id not in ctx.authorized_trial_ids:
            return (
                f"trial {doc.trial_id} not in authorized trial list (§11.10(g)); "
                "trial-specific authorization required"
            )

        # Trial phase authorization
        if doc.trial_phase not in ctx.authorized_trial_phases:
            return (
                f"trial phase {doc.trial_phase.value} not in authorized phases; "
                "§11.10(d) authority check failed"
            )

        return None


# ---------------------------------------------------------------------------
# Layer 2 — ICH E6(R3) GCP Filter
# ---------------------------------------------------------------------------

class ICHGCPFilter:
    """
    Enforces ICH E6(R3) Good Clinical Practice blinding and role-based controls.

    Key GCP obligations:
    - Blinding integrity (Section 5.7): unblinded data must not be disclosed to
      blinded personnel; randomization codes accessible only to authorized
      unblinded team members
    - Investigator access (Section 4.9): investigators may access source documents
      and subject records at their enrolled site; cross-site access is prohibited
    - Monitor access (Section 5.18): CRA/monitors may access source documents for
      verification but not for purposes beyond monitoring
    - GCP training (Section 5.1): all trial personnel must have current GCP
      training certificates
    """

    # Roles that must be blinded to unblinded trial data
    _MUST_REMAIN_BLINDED: frozenset[GCPRole] = frozenset({
        GCPRole.PRINCIPAL_INVESTIGATOR,
        GCPRole.SUB_INVESTIGATOR,
        GCPRole.CLINICAL_RESEARCH_ASSOCIATE,
        GCPRole.DATA_MANAGER,
        GCPRole.BLINDED_STATISTICIAN,
        GCPRole.PHARMACOVIGILANCE,
    })

    # Categories that contain unblinded data
    _UNBLINDED_CATEGORIES: frozenset[ClinicalRecordCategory] = frozenset({
        ClinicalRecordCategory.RANDOMIZATION_CODE,
        ClinicalRecordCategory.INTERIM_ANALYSIS,
        ClinicalRecordCategory.BLIND_BREAK_LOG,
    })

    # Roles with site-specific access (may only access records from their site)
    _SITE_RESTRICTED_ROLES: frozenset[GCPRole] = frozenset({
        GCPRole.PRINCIPAL_INVESTIGATOR,
        GCPRole.SUB_INVESTIGATOR,
        GCPRole.CLINICAL_RESEARCH_ASSOCIATE,
    })

    def filter(
        self,
        documents: list[ClinicalDocument],
        ctx: ClinicalAccessContext,
    ) -> tuple[list[ClinicalDocument], list[str]]:
        permitted: list[ClinicalDocument] = []
        blocked_reasons: list[str] = []

        for doc in documents:
            reason = self._evaluate(doc, ctx)
            if reason:
                blocked_reasons.append(f"ICH GCP blocked {doc.doc_id}: {reason}")
            else:
                permitted.append(doc)

        return permitted, blocked_reasons

    def _evaluate(self, doc: ClinicalDocument, ctx: ClinicalAccessContext) -> str | None:
        # Non-controlled records (public summaries, registry entries) are not
        # subject to GCP access restrictions — they are publicly available by design.
        if not doc.is_controlled_record:
            return None

        # GCP training currency check (Section 5.1)
        if not ctx.gcp_training_current:
            return "current GCP training certificate required (ICH E6(R3) Section 5.1)"

        # Blinding integrity enforcement (Section 5.7)
        if doc.category in self._UNBLINDED_CATEGORIES or doc.is_unblinded_data:
            if ctx.role in self._MUST_REMAIN_BLINDED or ctx.is_blinded:
                return (
                    f"blinding violation: {ctx.role.value} must not access "
                    f"unblinded data ({doc.category.value}); "
                    "ICH E6(R3) Section 5.7 blinding integrity requirement"
                )

        # Site-restricted access for investigators and monitors
        if ctx.role in self._SITE_RESTRICTED_ROLES:
            if doc.site_id is not None and doc.site_id != ctx.site_id:
                return (
                    f"cross-site access prohibited: document belongs to site "
                    f"{doc.site_id}, user authorized at site {ctx.site_id} only "
                    "(ICH E6(R3) Section 4.9)"
                )

        return None


# ---------------------------------------------------------------------------
# Layer 3 — HIPAA Minimum Necessary Filter
# ---------------------------------------------------------------------------

class HIPAAMinimumNecessaryFilter:
    """
    Enforces HIPAA Privacy Rule minimum necessary standard for PHI access
    in clinical trial contexts (45 CFR §164.502(b), §164.514).

    Clinical trial participants are research subjects whose health information
    is PHI when they are identifiable. The minimum necessary standard requires
    that only the PHI categories essential for the stated purpose are disclosed.
    """

    # Categories that require HIPAA authorization
    _PHI_CATEGORIES: frozenset[ClinicalRecordCategory] = frozenset({
        ClinicalRecordCategory.PATIENT_DATA_IDENTIFIABLE,
        ClinicalRecordCategory.ADVERSE_EVENT,
        ClinicalRecordCategory.SERIOUS_ADVERSE_EVENT,
        ClinicalRecordCategory.LAB_RESULT,
    })

    def filter(
        self,
        documents: list[ClinicalDocument],
        ctx: ClinicalAccessContext,
    ) -> tuple[list[ClinicalDocument], list[str]]:
        permitted: list[ClinicalDocument] = []
        blocked_reasons: list[str] = []

        for doc in documents:
            reason = self._evaluate(doc, ctx)
            if reason:
                blocked_reasons.append(f"HIPAA blocked {doc.doc_id}: {reason}")
            else:
                permitted.append(doc)

        return permitted, blocked_reasons

    def _evaluate(self, doc: ClinicalDocument, ctx: ClinicalAccessContext) -> str | None:
        if not doc.contains_phi:
            return None

        # PHI requires authorization
        if not ctx.phi_authorized:
            return (
                "individually identifiable PHI requires IRB/ethics committee "
                "authorization (45 CFR §164.502(b)); authorization not on file"
            )

        # Minimum necessary: only categories in scope
        if (
            ctx.minimum_necessary_scope
            and doc.category in self._PHI_CATEGORIES
            and doc.category not in ctx.minimum_necessary_scope
        ):
            return (
                f"category {doc.category.value} outside minimum necessary scope "
                "for stated request purpose (45 CFR §164.502(b))"
            )

        return None


# ---------------------------------------------------------------------------
# Clinical Compliance Pipeline
# ---------------------------------------------------------------------------

@dataclass
class ClinicalComplianceAuditRecord:
    """
    21 CFR Part 11 compliant audit record for a clinical trial RAG retrieval.

    Fields required per 21 CFR Part 11 §11.10(e):
    - Date/time of access (captured as request_id timestamp)
    - System entry (system_name)
    - Operator identification (user_id)
    - Action performed (query)
    - Records accessed (permitted_count, blocked_count)
    """
    request_id: str
    user_id: str
    role: str
    trial_ids: list[str]
    query_purpose: str
    total_candidates: int
    permitted_count: int
    blocked_count: int
    per_regulation_blocked: dict[str, list[str]]
    most_restrictive: str
    phi_accessed: bool
    unblinded_access_attempted: bool
    blinding_violation_blocked: bool


class ClinicalRAGPipeline:
    """
    Defense-in-depth clinical trial RAG pipeline applying three regulatory
    layers independently. A document is returned only if all three permit it.
    """

    def __init__(self) -> None:
        self._part11 = FDA21CFRPart11Filter()
        self._gcp = ICHGCPFilter()
        self._hipaa = HIPAAMinimumNecessaryFilter()

    def retrieve(
        self,
        candidates: list[ClinicalDocument],
        ctx: ClinicalAccessContext,
        query_purpose: str = "unspecified",
    ) -> tuple[list[ClinicalDocument], ClinicalComplianceAuditRecord]:
        per_reg_blocked: dict[str, list[str]] = {}
        blocked_ids: dict[str, set[str]] = {}

        _, part11_blocked = self._part11.filter(candidates, ctx)
        _, gcp_blocked = self._gcp.filter(candidates, ctx)
        _, hipaa_blocked = self._hipaa.filter(candidates, ctx)

        reg_results = {
            "21 CFR Part 11": part11_blocked,
            "ICH GCP": gcp_blocked,
            "HIPAA": hipaa_blocked,
        }

        for reg, reasons in reg_results.items():
            if reasons:
                per_reg_blocked[reg] = reasons
                # Extract doc_id: every reason has the form "<PREFIX> blocked <DOC-ID>: <text>"
                # Split on " blocked " is safe because doc_ids never contain that substring.
                blocked_ids[reg] = {r.split(" blocked ")[1].split(":")[0] for r in reasons}

        all_blocked: set[str] = set()
        for ids in blocked_ids.values():
            all_blocked |= ids

        permitted = [d for d in candidates if d.doc_id not in all_blocked]

        most_restrictive = max(
            blocked_ids,
            key=lambda k: len(blocked_ids[k]),
            default="none",
        )

        phi_accessed = any(d.contains_phi for d in permitted)
        unblinded_attempted = any(
            d.is_unblinded_data or d.category in ICHGCPFilter._UNBLINDED_CATEGORIES
            for d in candidates
        )
        blinding_violation_blocked = any(
            "blinding violation" in r
            for reasons in per_reg_blocked.values()
            for r in reasons
        )

        audit = ClinicalComplianceAuditRecord(
            request_id=str(uuid.uuid4()),
            user_id=ctx.user_id,
            role=ctx.role.value,
            trial_ids=list(ctx.authorized_trial_ids),
            query_purpose=query_purpose,
            total_candidates=len(candidates),
            permitted_count=len(permitted),
            blocked_count=len(all_blocked),
            per_regulation_blocked=per_reg_blocked,
            most_restrictive=most_restrictive,
            phi_accessed=phi_accessed,
            unblinded_access_attempted=unblinded_attempted,
            blinding_violation_blocked=blinding_violation_blocked,
        )

        return permitted, audit


# ---------------------------------------------------------------------------
# Sample document corpus
# ---------------------------------------------------------------------------

TRIAL_ID = "TRIAL-2024-PHASE3-ONCOLOGY"
SITE_A = "SITE-001-BOSTON"
SITE_B = "SITE-002-CHICAGO"

SAMPLE_DOCUMENTS: list[ClinicalDocument] = [
    ClinicalDocument(
        doc_id="DOC-PROTOCOL",
        content="Phase III oncology trial protocol v3.1 — study design, dosing schedule, endpoints.",
        category=ClinicalRecordCategory.PROTOCOL,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=False,
        site_id=None,
        is_controlled_record=True,
    ),
    ClinicalDocument(
        doc_id="DOC-PATIENT-PHI",
        content="Subject 007 enrollment record: demographics, baseline assessments, medical history.",
        category=ClinicalRecordCategory.PATIENT_DATA_IDENTIFIABLE,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=True,
        site_id=SITE_A,
        is_controlled_record=True,
    ),
    ClinicalDocument(
        doc_id="DOC-AE-SITE-A",
        content="Adverse event log — Site 001: nausea grade 2, fatigue grade 1 (n=12).",
        category=ClinicalRecordCategory.ADVERSE_EVENT,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=True,
        site_id=SITE_A,
        is_controlled_record=True,
    ),
    ClinicalDocument(
        doc_id="DOC-RANDOMIZATION-CODE",
        content="Randomization code list: subject-to-treatment arm assignment for all 240 enrolled subjects.",
        category=ClinicalRecordCategory.RANDOMIZATION_CODE,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=True,
        contains_phi=False,
        site_id=None,
        is_controlled_record=True,
    ),
    ClinicalDocument(
        doc_id="DOC-INTERIM-ANALYSIS",
        content="Pre-specified interim analysis: unblinded efficacy data at 50% information fraction.",
        category=ClinicalRecordCategory.INTERIM_ANALYSIS,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=True,
        contains_phi=False,
        site_id=None,
        is_controlled_record=True,
    ),
    ClinicalDocument(
        doc_id="DOC-LAB-SITE-A",
        content="Central laboratory results for Site 001 subjects — CBC, CMP, biomarkers.",
        category=ClinicalRecordCategory.LAB_RESULT,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=True,
        site_id=SITE_A,
        is_controlled_record=True,
    ),
    ClinicalDocument(
        doc_id="DOC-INV-BROCHURE",
        content="Investigator Brochure v8: non-clinical and clinical data summary for investigational compound.",
        category=ClinicalRecordCategory.INVESTIGATOR_BROCHURE,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=False,
        site_id=None,
        is_controlled_record=True,
    ),
    ClinicalDocument(
        doc_id="DOC-PUBLIC-SUMMARY",
        content="ClinicalTrials.gov public listing — trial registry entry with inclusion/exclusion criteria.",
        category=ClinicalRecordCategory.PUBLIC_SUMMARY,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=False,
        site_id=None,
        is_controlled_record=False,  # Public record — not subject to Part 11
    ),
    ClinicalDocument(
        doc_id="DOC-AE-SITE-B",
        content="Adverse event log — Site 002 (Chicago): alopecia grade 1, peripheral neuropathy grade 2.",
        category=ClinicalRecordCategory.ADVERSE_EVENT,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=True,
        site_id=SITE_B,
        is_controlled_record=True,
    ),
    ClinicalDocument(
        doc_id="DOC-CSR-DRAFT",
        content="Clinical Study Report draft (unblinded): primary endpoint results, subgroup analyses.",
        category=ClinicalRecordCategory.CLINICAL_STUDY_REPORT,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=True,
        contains_phi=False,
        site_id=None,
        is_controlled_record=True,
    ),
]


# ---------------------------------------------------------------------------
# Scenario helpers
# ---------------------------------------------------------------------------

def _print_result(
    label: str,
    permitted: list[ClinicalDocument],
    audit: ClinicalComplianceAuditRecord,
) -> None:
    print(f"\n{'='*72}")
    print(f"  {label}")
    print(f"{'='*72}")
    print(f"  Role         : {audit.role}")
    print(f"  Purpose      : {audit.query_purpose}")
    print(f"  Candidates   : {audit.total_candidates}")
    print(f"  Permitted    : {audit.permitted_count}  ✓")
    print(f"  Blocked      : {audit.blocked_count}  ✗  (most restrictive: {audit.most_restrictive})")
    print(f"  PHI accessed : {audit.phi_accessed}")
    print(f"  Blinding viol: {audit.blinding_violation_blocked}")
    print()
    if audit.per_regulation_blocked:
        print("  Block details:")
        for reg, reasons in audit.per_regulation_blocked.items():
            for r in reasons:
                print(f"    [{reg}] {r}")
    print()
    print("  Permitted documents:")
    for doc in permitted:
        flag = "⚠ PHI" if doc.contains_phi else ("🔓 UNBLINDED" if doc.is_unblinded_data else "")
        print(f"    ✓  {doc.doc_id:<30}  [{doc.category.value}]  {flag}")
    if not permitted:
        print("    (none)")


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def scenario_a_blinded_statistician() -> None:
    """
    Blinded statistician queries interim analysis data.
    GCP blocks unblinded interim analysis and randomization code.
    """
    ctx = ClinicalAccessContext(
        role=GCPRole.BLINDED_STATISTICIAN,
        gxp_credentials_valid=True,
        gcp_training_current=True,
        authorized_trial_ids=frozenset({TRIAL_ID}),
        is_blinded=True,
        authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
        phi_authorized=False,
        minimum_necessary_scope=frozenset(),
    )
    pipeline = ClinicalRAGPipeline()
    permitted, audit = pipeline.retrieve(
        SAMPLE_DOCUMENTS, ctx, query_purpose="statistical analysis planning"
    )
    _print_result("Scenario A — Blinded statistician: unblinded data blocked", permitted, audit)
    assert audit.blinding_violation_blocked
    assert all(not d.is_unblinded_data for d in permitted)


def scenario_b_cra_site_audit() -> None:
    """
    Clinical Research Associate conducting site audit at Site A.
    Full access to Site A documents; Site B blocked by GCP site restriction.
    PHI authorized for monitoring purposes.
    """
    ctx = ClinicalAccessContext(
        role=GCPRole.CLINICAL_RESEARCH_ASSOCIATE,
        gxp_credentials_valid=True,
        gcp_training_current=True,
        authorized_trial_ids=frozenset({TRIAL_ID}),
        is_blinded=True,
        authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
        phi_authorized=True,
        site_id=SITE_A,
        minimum_necessary_scope=frozenset({
            ClinicalRecordCategory.PATIENT_DATA_IDENTIFIABLE,
            ClinicalRecordCategory.ADVERSE_EVENT,
            ClinicalRecordCategory.LAB_RESULT,
        }),
    )
    pipeline = ClinicalRAGPipeline()
    permitted, audit = pipeline.retrieve(
        SAMPLE_DOCUMENTS, ctx, query_purpose="site monitoring visit source document verification"
    )
    _print_result("Scenario B — CRA site audit: Site A access, Site B blocked", permitted, audit)
    # Site B adverse event should be blocked
    assert not any(d.doc_id == "DOC-AE-SITE-B" for d in permitted)
    # Site A documents should be accessible
    assert any(d.doc_id == "DOC-AE-SITE-A" for d in permitted)


def scenario_c_unauthorized_external() -> None:
    """
    External user with no GxP credentials.
    21 CFR Part 11 blocks all controlled records. Only public summary returned.
    """
    ctx = ClinicalAccessContext(
        role=GCPRole.EXTERNAL_AUDITOR,
        gxp_credentials_valid=False,    # No valid credentials
        gcp_training_current=False,
        authorized_trial_ids=frozenset(),
        is_blinded=False,
        authorized_trial_phases=frozenset(),
        phi_authorized=False,
    )
    pipeline = ClinicalRAGPipeline()
    permitted, audit = pipeline.retrieve(
        SAMPLE_DOCUMENTS, ctx, query_purpose="unauthorized access attempt"
    )
    _print_result("Scenario C — Unauthorized external: only public record returned", permitted, audit)
    assert all(not d.is_controlled_record for d in permitted)
    assert any(d.doc_id == "DOC-PUBLIC-SUMMARY" for d in permitted)


def scenario_d_principal_investigator_aes() -> None:
    """
    Principal Investigator at Site A queries adverse events for safety review.
    Full access to Site A AEs. Site B AEs blocked (cross-site). Unblinded data blocked.
    """
    ctx = ClinicalAccessContext(
        role=GCPRole.PRINCIPAL_INVESTIGATOR,
        gxp_credentials_valid=True,
        gcp_training_current=True,
        authorized_trial_ids=frozenset({TRIAL_ID}),
        is_blinded=True,
        authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
        phi_authorized=True,
        site_id=SITE_A,
        minimum_necessary_scope=frozenset({
            ClinicalRecordCategory.ADVERSE_EVENT,
            ClinicalRecordCategory.SERIOUS_ADVERSE_EVENT,
            ClinicalRecordCategory.LAB_RESULT,
        }),
    )
    pipeline = ClinicalRAGPipeline()
    permitted, audit = pipeline.retrieve(
        SAMPLE_DOCUMENTS, ctx, query_purpose="safety review — adverse event assessment"
    )
    _print_result("Scenario D — PI safety review: Site A AEs, no unblinded data", permitted, audit)
    # PI should not see unblinded data
    assert not any(d.is_unblinded_data for d in permitted)
    # PI should see Site A AE
    assert any(d.doc_id == "DOC-AE-SITE-A" for d in permitted)
    # PI should not see Site B AE
    assert not any(d.doc_id == "DOC-AE-SITE-B" for d in permitted)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Pharmaceutical Clinical Trial RAG Pipeline")
    print("FDA 21 CFR Part 11 · ICH E6(R3) GCP · HIPAA Privacy Rule")
    print("Defense-in-depth: all three regulatory layers enforced independently")

    scenario_a_blinded_statistician()
    scenario_b_cra_site_audit()
    scenario_c_unauthorized_external()
    scenario_d_principal_investigator_aes()

    print("\n" + "="*72)
    print("  All four scenarios complete.")
    print("  Key invariants verified:")
    print("    • Blinding integrity: unblinded data blocked for blinded personnel")
    print("    • Site isolation: investigators access only enrolled-site records")
    print("    • Credential gate: 21 CFR Part 11 blocks all controlled records without GxP auth")
    print("    • HIPAA minimum necessary: PHI scoped to stated purpose")
    print("="*72)
