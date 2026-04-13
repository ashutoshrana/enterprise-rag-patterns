"""
24_clinical_trials_rag.py — Four-layer RAG pipeline for pharmaceutical and
clinical trial data management systems.

Demonstrates a multi-layer defense-in-depth retrieval architecture where four
overlapping regulatory frameworks each independently enforce access control on
clinical and pharmaceutical document retrieval:

    Layer 1  — FDA 21 CFR Part 11 (Electronic Records / Electronic Signatures):
               All electronic records in FDA-regulated systems must be created,
               modified, maintained, archived, retrieved, and transmitted under
               a validated system with audit trail, access control, and system
               validation documentation. IQ/OQ/PQ validation is required before
               any data access in production. Closed systems require operational
               system checks; open systems require additional encryption.

    Layer 2  — GxP Document Control (GMP / GLP / GCP / GDP):
               Good Practice (GxP) regulations define document access controls
               by document type. GMP batch records and deviation reports (21 CFR
               Part 211) are restricted to manufacturing personnel and QA. GLP
               study data (21 CFR Part 58) is restricted to the study director
               and authorized personnel during active studies. GCP protocols are
               subject to blinding enforcement. GDP distribution records (WHO
               TRS 957) require distributor authorization.

    Layer 3  — ICH E6(R3) GCP — Clinical Trial Blinding and Site Access:
               Clinical trial data access is controlled by role and site
               assignment. Trial monitors may only access data for their
               assigned sites. Investigators may only access their own site's
               data. Sponsors may access unblinded data only after Database Lock
               (DBL) unless accessing through an authorized DSMB. Blinded data
               cannot be released to sponsor roles before DBL.

    Layer 4  — HIPAA / HITECH (45 CFR Parts 160–164):
               Clinical subject data containing Protected Health Information
               (PHI) requires minimum necessary access. PHI may be retrieved
               only by personnel with a valid treatment/operations/research
               purpose and an IRB/Privacy Board waiver for research use.
               De-identified data (Safe Harbor: 18 identifiers removed) or
               Limited Datasets (direct identifiers removed, dates retained) are
               accessible with appropriate data use agreements.

No external dependencies required.

Run:
    python examples/24_clinical_trials_rag.py
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class ClinicalTrialRole(str, Enum):
    """
    Personnel roles in a clinical trial with distinct data access privileges.

    SPONSOR         — Trial funder; restricted from unblinded data before DBL
    MONITOR         — CRO/sponsor monitor; access only to assigned sites
    INVESTIGATOR    — Site PI/sub-investigator; own site data only
    DSMB            — Data Safety Monitoring Board; unblinded access authorized
    REGULATORY      — FDA/EMA inspector; full read access under inspection
    BIOSTATISTICIAN — Unblinded statistician; access after DBL or via DSMB charter
    QA              — Quality assurance; GxP document access
    PHARMACIST      — Dispensing records only
    """

    SPONSOR = "SPONSOR"
    MONITOR = "MONITOR"
    INVESTIGATOR = "INVESTIGATOR"
    DSMB = "DSMB"
    REGULATORY = "REGULATORY"
    BIOSTATISTICIAN = "BIOSTATISTICIAN"
    QA = "QA"
    PHARMACIST = "PHARMACIST"


class GxPTier(str, Enum):
    """
    Good Practice tier governing a document's creation and access requirements.

    GMP — Good Manufacturing Practice (21 CFR Part 211)
    GLP — Good Laboratory Practice (21 CFR Part 58)
    GCP — Good Clinical Practice (ICH E6 R2/R3)
    GDP — Good Distribution Practice (WHO TRS 957)
    NON_GXP — Administrative or non-regulated document
    """

    GMP = "GMP"
    GLP = "GLP"
    GCP = "GCP"
    GDP = "GDP"
    NON_GXP = "NON_GXP"


class ClinicalDocumentType(str, Enum):
    """Classification of clinical trial and pharmaceutical documents."""

    # GMP documents (21 CFR Part 211)
    BATCH_RECORD = "BATCH_RECORD"
    DEVIATION_REPORT = "DEVIATION_REPORT"
    CAPA_RECORD = "CAPA_RECORD"

    # GLP documents (21 CFR Part 58)
    NONCLINICAL_STUDY_REPORT = "NONCLINICAL_STUDY_REPORT"
    RAW_STUDY_DATA = "RAW_STUDY_DATA"

    # GCP documents (ICH E6)
    PROTOCOL = "PROTOCOL"
    INVESTIGATOR_BROCHURE = "INVESTIGATOR_BROCHURE"
    CASE_REPORT_FORM = "CASE_REPORT_FORM"
    INTERIM_ANALYSIS = "INTERIM_ANALYSIS"
    FINAL_CLINICAL_STUDY_REPORT = "FINAL_CLINICAL_STUDY_REPORT"
    SAE_REPORT = "SAE_REPORT"

    # GDP documents
    DISTRIBUTION_RECORD = "DISTRIBUTION_RECORD"
    CHAIN_OF_CUSTODY = "CHAIN_OF_CUSTODY"

    # Administrative
    INFORMED_CONSENT_TEMPLATE = "INFORMED_CONSENT_TEMPLATE"
    REGULATORY_SUBMISSION = "REGULATORY_SUBMISSION"
    IRB_APPROVAL = "IRB_APPROVAL"


class PHIClassification(str, Enum):
    """
    HIPAA PHI classification for clinical documents.

    IDENTIFIED      — Contains one or more of the 18 HIPAA direct identifiers
    LIMITED_DATASET — Direct identifiers removed; date elements retained (DUA required)
    DE_IDENTIFIED   — All 18 identifiers removed via Safe Harbor or Expert Determination
    NO_PHI          — No subject-level health information
    """

    IDENTIFIED = "IDENTIFIED"
    LIMITED_DATASET = "LIMITED_DATASET"
    DE_IDENTIFIED = "DE_IDENTIFIED"
    NO_PHI = "NO_PHI"


class ClinicalGovernanceDecision(str, Enum):
    PERMITTED = "PERMITTED"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# GxP document access sets
# ---------------------------------------------------------------------------

_GMP_DOCUMENT_TYPES: FrozenSet[ClinicalDocumentType] = frozenset({
    ClinicalDocumentType.BATCH_RECORD,
    ClinicalDocumentType.DEVIATION_REPORT,
    ClinicalDocumentType.CAPA_RECORD,
})

_GLP_DOCUMENT_TYPES: FrozenSet[ClinicalDocumentType] = frozenset({
    ClinicalDocumentType.NONCLINICAL_STUDY_REPORT,
    ClinicalDocumentType.RAW_STUDY_DATA,
})

_GCP_BLINDED_TYPES: FrozenSet[ClinicalDocumentType] = frozenset({
    ClinicalDocumentType.INTERIM_ANALYSIS,
    # CRFs and SAE reports are NOT inherently blinded — only the treatment
    # arm allocation field is blinded. Use the is_blinded flag on ClinicalDocument
    # to indicate documents with embedded treatment-allocation data.
})

_ROLES_WITH_GMP_ACCESS: FrozenSet[ClinicalTrialRole] = frozenset({
    ClinicalTrialRole.QA,
    ClinicalTrialRole.REGULATORY,
})

_ROLES_WITH_GDP_ACCESS: FrozenSet[ClinicalTrialRole] = frozenset({
    ClinicalTrialRole.PHARMACIST,
    ClinicalTrialRole.QA,
    ClinicalTrialRole.REGULATORY,
})

_ROLES_WITH_UNBLINDED_ACCESS: FrozenSet[ClinicalTrialRole] = frozenset({
    ClinicalTrialRole.DSMB,
    ClinicalTrialRole.BIOSTATISTICIAN,
    ClinicalTrialRole.REGULATORY,
})

_PHI_AUTHORIZED_ROLES: FrozenSet[ClinicalTrialRole] = frozenset({
    ClinicalTrialRole.INVESTIGATOR,
    ClinicalTrialRole.MONITOR,        # Site monitors perform source data verification
    ClinicalTrialRole.DSMB,
    ClinicalTrialRole.REGULATORY,
    ClinicalTrialRole.QA,
})


# ---------------------------------------------------------------------------
# Context and document dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClinicalAccessContext:
    """
    Access context for a clinical trial data retrieval request.

    Attributes
    ----------
    user_id : str
        Unique identifier of the requesting user.
    user_role : ClinicalTrialRole
        The user's clinical trial role.
    assigned_site_ids : FrozenSet[str]
        Site IDs this user is authorized to access (relevant for MONITOR and
        INVESTIGATOR roles — empty set means no site-level restriction).
    system_validated : bool
        True if the 21 CFR Part 11 system has completed IQ/OQ/PQ validation.
    audit_trail_active : bool
        True if the system's audit trail is enabled and functioning.
    electronic_signature_bound : bool
        True if electronic signatures are bound to their respective records.
    database_locked : bool
        True if the clinical database has been locked (DBL completed). Unlocks
        sponsor access to unblinded clinical data.
    dsmb_authorized_access : bool
        True if the user has been granted unblinded access under a DSMB charter
        (overrides blinding restriction before DBL for DSMB members).
    irb_waiver_active : bool
        True if an IRB/Privacy Board waiver authorizing research use of PHI is
        in effect for this access context.
    data_use_agreement_signed : bool
        True if a valid Data Use Agreement (DUA) covering Limited Datasets is
        in place.
    """

    user_id: str
    user_role: ClinicalTrialRole
    assigned_site_ids: FrozenSet[str]
    system_validated: bool
    audit_trail_active: bool
    electronic_signature_bound: bool
    database_locked: bool
    dsmb_authorized_access: bool
    irb_waiver_active: bool
    data_use_agreement_signed: bool


@dataclass(frozen=True)
class ClinicalDocument:
    """
    A clinical trial or pharmaceutical document for regulated retrieval.

    Attributes
    ----------
    document_id : str
        Unique document identifier.
    document_type : ClinicalDocumentType
        Type classification driving access control logic.
    gxp_tier : GxPTier
        Good Practice regulatory tier governing this document.
    phi_classification : PHIClassification
        HIPAA PHI content classification.
    site_id : Optional[str]
        Clinical site identifier. Required for site-restricted documents
        (GCP case report forms, SAE reports). None for multi-site documents.
    is_blinded : bool
        True if the document contains treatment-arm allocation data subject to
        ICH E6 blinding requirements.
    is_public : bool
        True if the document is publicly available (e.g., published CSR).
        Public documents are always retrievable regardless of access controls.
    metadata : Dict[str, str]
        Additional metadata for filtering and audit logging.
    """

    document_id: str
    document_type: ClinicalDocumentType
    gxp_tier: GxPTier
    phi_classification: PHIClassification
    site_id: Optional[str] = None
    is_blinded: bool = False
    is_public: bool = False
    metadata: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Per-layer audit record
# ---------------------------------------------------------------------------


@dataclass
class ClinicalAccessAuditRecord:
    """Audit record for a retrieval request, as required by 21 CFR Part 11."""

    user_id: str
    user_role: str
    timestamp: float = field(default_factory=time.time)
    total_documents: int = 0
    permitted_documents: int = 0
    blocked_by_21cfr11: int = 0
    blocked_by_gxp: int = 0
    blocked_by_ich_e6: int = 0
    blocked_by_hipaa: int = 0

    def to_audit_log(self) -> Dict[str, object]:
        return {
            "event": "RAG_RETRIEVAL",
            "user_id": self.user_id,
            "user_role": self.user_role,
            "timestamp_utc": self.timestamp,
            "documents": {
                "total": self.total_documents,
                "permitted": self.permitted_documents,
                "blocked_21cfr11": self.blocked_by_21cfr11,
                "blocked_gxp": self.blocked_by_gxp,
                "blocked_ich_e6": self.blocked_by_ich_e6,
                "blocked_hipaa": self.blocked_by_hipaa,
            },
        }


# ---------------------------------------------------------------------------
# Layer 1 — FDA 21 CFR Part 11
# ---------------------------------------------------------------------------


class FDA21CFR11Filter:
    """
    Layer 1: FDA 21 CFR Part 11 — Electronic Records / Electronic Signatures.

    Baseline validation requirements that must be met before any document
    can be retrieved from the regulated system.

    - System validation (IQ/OQ/PQ) must be complete [§11.10(a)]
    - Audit trail must be active [§11.10(e)]
    - Electronic signatures must be bound to records [§11.70]

    Public documents bypass these requirements (no FDA jurisdiction).

    References
    ----------
    21 CFR Part 11 — Electronic Records; Electronic Signatures (1997)
    FDA Guidance: Part 11, Electronic Records; Electronic Signatures —
        Scope and Application (August 2003)
    """

    def _evaluate(
        self, doc: ClinicalDocument, ctx: ClinicalAccessContext
    ) -> Optional[str]:
        if doc.is_public:
            return None

        if not ctx.system_validated:
            return (
                "21 CFR Part 11 §11.10(a): System has not completed IQ/OQ/PQ "
                "validation — electronic records cannot be retrieved from an "
                "unvalidated system"
            )
        if not ctx.audit_trail_active:
            return (
                "21 CFR Part 11 §11.10(e): Audit trail is not active — all "
                "access, creation, and modification of electronic records must "
                "be captured in a secure, computer-generated audit trail"
            )
        if not ctx.electronic_signature_bound:
            return (
                "21 CFR Part 11 §11.70: Electronic signatures are not bound to "
                "their respective records — retrieval blocked until signature "
                "binding is verified"
            )
        return None

    def filter(
        self,
        documents: List[ClinicalDocument],
        context: ClinicalAccessContext,
        audit: ClinicalAccessAuditRecord,
    ) -> List[ClinicalDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
            else:
                audit.blocked_by_21cfr11 += 1
        return permitted


# ---------------------------------------------------------------------------
# Layer 2 — GxP Document Control
# ---------------------------------------------------------------------------


class GxPDocumentFilter:
    """
    Layer 2: GxP Document Control — GMP / GLP / GCP / GDP.

    GMP batch records and deviation reports are accessible only to QA and
    REGULATORY roles. GLP study data is accessible only to REGULATORY role
    (study director access is modeled outside retrieval scope). GDP
    distribution records require PHARMACIST, QA, or REGULATORY role. GCP
    and NON_GXP documents pass this layer (ICH E6 rules apply in Layer 3).

    References
    ----------
    21 CFR Part 211 — Current Good Manufacturing Practice (GMP)
    21 CFR Part 58 — Good Laboratory Practice for Nonclinical Laboratory Studies
    ICH E6(R3) — Guideline for Good Clinical Practice (2023)
    WHO Technical Report Series No. 957 Annex 5 — GDP
    """

    def _evaluate(
        self, doc: ClinicalDocument, ctx: ClinicalAccessContext
    ) -> Optional[str]:
        if doc.is_public:
            return None

        if doc.gxp_tier == GxPTier.GMP or doc.document_type in _GMP_DOCUMENT_TYPES:
            if ctx.user_role not in _ROLES_WITH_GMP_ACCESS:
                return (
                    f"GMP 21 CFR Part 211: Document type {doc.document_type.value} "
                    f"is a GMP controlled record — access restricted to QA and "
                    f"REGULATORY roles; user role {ctx.user_role.value} is not authorized"
                )

        elif doc.gxp_tier == GxPTier.GLP or doc.document_type in _GLP_DOCUMENT_TYPES:
            if ctx.user_role not in (ClinicalTrialRole.REGULATORY,):
                return (
                    f"GLP 21 CFR Part 58: Document type {doc.document_type.value} is "
                    f"GLP study data — retrieval access restricted to REGULATORY "
                    f"inspectors; user role {ctx.user_role.value} is not authorized"
                )

        elif doc.gxp_tier == GxPTier.GDP or doc.document_type in (
            ClinicalDocumentType.DISTRIBUTION_RECORD,
            ClinicalDocumentType.CHAIN_OF_CUSTODY,
        ):
            if ctx.user_role not in _ROLES_WITH_GDP_ACCESS:
                return (
                    f"GDP WHO TRS 957: Distribution record {doc.document_id} "
                    f"requires PHARMACIST, QA, or REGULATORY role; "
                    f"user role {ctx.user_role.value} is not authorized"
                )

        return None

    def filter(
        self,
        documents: List[ClinicalDocument],
        context: ClinicalAccessContext,
        audit: ClinicalAccessAuditRecord,
    ) -> List[ClinicalDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
            else:
                audit.blocked_by_gxp += 1
        return permitted


# ---------------------------------------------------------------------------
# Layer 3 — ICH E6(R3) GCP Blinding and Site Access
# ---------------------------------------------------------------------------


class ICHE6GCPFilter:
    """
    Layer 3: ICH E6(R3) — Good Clinical Practice Blinding and Site Access.

    Blinded documents (treatment-arm allocations, interim analyses, unblinded
    CRF data) may not be accessed by SPONSOR or unblinded-unauthorized roles
    before Database Lock (DBL) unless via DSMB authorization.

    Site-specific documents may only be accessed by MONITORs and INVESTIGATORs
    assigned to that specific site. Sponsors and DSMB have cross-site access
    after DBL; REGULATORY has full access.

    References
    ----------
    ICH E6(R3) — Guideline for Good Clinical Practice (June 2023)
    ICH E9(R1) — Statistical Principles for Clinical Trials
    ICH E8(R1) — General Considerations for Clinical Studies
    """

    def _evaluate(
        self, doc: ClinicalDocument, ctx: ClinicalAccessContext
    ) -> Optional[str]:
        if doc.is_public:
            return None

        # REGULATORY inspectors have unrestricted access
        if ctx.user_role == ClinicalTrialRole.REGULATORY:
            return None

        # Blinding check
        if doc.is_blinded or doc.document_type in _GCP_BLINDED_TYPES:
            has_unblinded_access = (
                ctx.user_role in _ROLES_WITH_UNBLINDED_ACCESS
                or ctx.database_locked
                or (ctx.user_role == ClinicalTrialRole.DSMB and ctx.dsmb_authorized_access)
            )
            if not has_unblinded_access:
                return (
                    f"ICH E6(R3) §8.3: Document {doc.document_id} contains blinded "
                    f"clinical data — access restricted until Database Lock or DSMB "
                    f"authorization; user role {ctx.user_role.value} is not authorized "
                    f"for unblinded access before DBL"
                )

        # Site-level access control
        if doc.site_id is not None:
            if ctx.user_role == ClinicalTrialRole.MONITOR:
                if doc.site_id not in ctx.assigned_site_ids:
                    return (
                        f"ICH E6(R3) §5.18: Monitor {ctx.user_id} is not assigned "
                        f"to site {doc.site_id} — cross-site data access not authorized"
                    )
            elif ctx.user_role == ClinicalTrialRole.INVESTIGATOR:
                if doc.site_id not in ctx.assigned_site_ids:
                    return (
                        f"ICH E6(R3) §4.1.3: Investigator {ctx.user_id} may only "
                        f"access data from their own site — site {doc.site_id} is not "
                        f"in their authorized site list"
                    )

        return None

    def filter(
        self,
        documents: List[ClinicalDocument],
        context: ClinicalAccessContext,
        audit: ClinicalAccessAuditRecord,
    ) -> List[ClinicalDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
            else:
                audit.blocked_by_ich_e6 += 1
        return permitted


# ---------------------------------------------------------------------------
# Layer 4 — HIPAA / HITECH
# ---------------------------------------------------------------------------


class HIPAAFilter:
    """
    Layer 4: HIPAA / HITECH — Protected Health Information Access Control.

    Documents containing IDENTIFIED PHI require that the accessing role be in
    the authorized set and that a valid IRB/Privacy Board waiver be in effect
    for research use of PHI. Limited Datasets require a signed Data Use
    Agreement. De-identified data and non-PHI documents are accessible to all
    roles.

    Minimum necessary standard: even authorized roles should only access PHI
    required for their specific function. This filter enforces role-level
    minimum necessary by restricting identified PHI to clinical roles.

    References
    ----------
    45 CFR §164.514 — De-identification of PHI
    45 CFR §164.514(e) — Limited Dataset
    45 CFR §164.512(i) — Research exception with IRB/Privacy Board waiver
    45 CFR §164.502(b) — Minimum necessary standard
    """

    def _evaluate(
        self, doc: ClinicalDocument, ctx: ClinicalAccessContext
    ) -> Optional[str]:
        if doc.is_public:
            return None

        if doc.phi_classification == PHIClassification.IDENTIFIED:
            if ctx.user_role not in _PHI_AUTHORIZED_ROLES:
                return (
                    f"HIPAA 45 CFR §164.502(b): Document {doc.document_id} contains "
                    f"identified PHI — minimum necessary standard restricts access to "
                    f"clinical roles; user role {ctx.user_role.value} is not authorized"
                )
            if not ctx.irb_waiver_active:
                return (
                    f"HIPAA 45 CFR §164.512(i): Research access to identified PHI in "
                    f"document {doc.document_id} requires an active IRB or Privacy Board "
                    f"waiver — no waiver is in effect for this access context"
                )

        elif doc.phi_classification == PHIClassification.LIMITED_DATASET:
            if not ctx.data_use_agreement_signed:
                return (
                    f"HIPAA 45 CFR §164.514(e): Document {doc.document_id} is a Limited "
                    f"Dataset — a signed Data Use Agreement (DUA) is required before "
                    f"access; no DUA is on file for user {ctx.user_id}"
                )

        return None

    def filter(
        self,
        documents: List[ClinicalDocument],
        context: ClinicalAccessContext,
        audit: ClinicalAccessAuditRecord,
    ) -> List[ClinicalDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
            else:
                audit.blocked_by_hipaa += 1
        return permitted


# ---------------------------------------------------------------------------
# Four-layer pipeline
# ---------------------------------------------------------------------------


@dataclass
class ClinicalRetrievalResult:
    """Result of a four-layer clinical RAG retrieval."""

    permitted_documents: List[ClinicalDocument]
    audit: ClinicalAccessAuditRecord
    block_reasons: Dict[str, str]

    def summary(self) -> Dict[str, object]:
        return {
            "permitted": len(self.permitted_documents),
            "blocked": self.audit.total_documents - self.audit.permitted_documents,
            "audit_log": self.audit.to_audit_log(),
        }


class ClinicalTrialRAGPipeline:
    """
    Four-layer clinical trial RAG pipeline.

    Evaluation order:
        FDA 21 CFR Part 11  →  GxP Document Control  →
        ICH E6(R3) GCP  →  HIPAA / HITECH

    A document must pass all four layers to be included in the retrieval result.
    Each layer operates independently. All four are evaluated in sequence.

    Example
    -------
    >>> pipeline = ClinicalTrialRAGPipeline()
    >>> ctx = ClinicalAccessContext(
    ...     user_id="MONITOR-001",
    ...     user_role=ClinicalTrialRole.MONITOR,
    ...     assigned_site_ids=frozenset({"SITE-A"}),
    ...     system_validated=True,
    ...     audit_trail_active=True,
    ...     electronic_signature_bound=True,
    ...     database_locked=False,
    ...     dsmb_authorized_access=False,
    ...     irb_waiver_active=True,
    ...     data_use_agreement_signed=True,
    ... )
    """

    def __init__(self) -> None:
        self._cfr11 = FDA21CFR11Filter()
        self._gxp = GxPDocumentFilter()
        self._gcp = ICHE6GCPFilter()
        self._hipaa = HIPAAFilter()

    def retrieve(
        self,
        documents: List[ClinicalDocument],
        context: ClinicalAccessContext,
    ) -> ClinicalRetrievalResult:
        """
        Run the four-layer filter pipeline.

        Parameters
        ----------
        documents : List[ClinicalDocument]
            Candidate documents from the vector store retrieval.
        context : ClinicalAccessContext
            Access context for the requesting user.

        Returns
        -------
        ClinicalRetrievalResult
            Permitted documents and a full 21 CFR Part 11 audit log.
        """
        audit = ClinicalAccessAuditRecord(
            user_id=context.user_id,
            user_role=context.user_role.value,
            total_documents=len(documents),
        )
        block_reasons: Dict[str, str] = {}

        # Layer 1
        after_cfr11 = []
        for doc in documents:
            reason = self._cfr11._evaluate(doc, context)
            if reason is None:
                after_cfr11.append(doc)
            else:
                audit.blocked_by_21cfr11 += 1
                block_reasons[doc.document_id] = reason

        # Layer 2
        after_gxp = []
        for doc in after_cfr11:
            reason = self._gxp._evaluate(doc, context)
            if reason is None:
                after_gxp.append(doc)
            else:
                audit.blocked_by_gxp += 1
                block_reasons[doc.document_id] = reason

        # Layer 3
        after_gcp = []
        for doc in after_gxp:
            reason = self._gcp._evaluate(doc, context)
            if reason is None:
                after_gcp.append(doc)
            else:
                audit.blocked_by_ich_e6 += 1
                block_reasons[doc.document_id] = reason

        # Layer 4
        permitted = []
        for doc in after_gcp:
            reason = self._hipaa._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
            else:
                audit.blocked_by_hipaa += 1
                block_reasons[doc.document_id] = reason

        audit.permitted_documents = len(permitted)
        return ClinicalRetrievalResult(
            permitted_documents=permitted,
            audit=audit,
            block_reasons=block_reasons,
        )


# ---------------------------------------------------------------------------
# Scenario demonstrations
# ---------------------------------------------------------------------------


def _validated_ctx(**kwargs) -> ClinicalAccessContext:
    defaults = dict(
        user_id="USER-001",
        user_role=ClinicalTrialRole.INVESTIGATOR,
        assigned_site_ids=frozenset({"SITE-A"}),
        system_validated=True,
        audit_trail_active=True,
        electronic_signature_bound=True,
        database_locked=False,
        dsmb_authorized_access=False,
        irb_waiver_active=True,
        data_use_agreement_signed=True,
    )
    defaults.update(kwargs)
    return ClinicalAccessContext(**defaults)


def scenario_a_monitor_site_restricted() -> None:
    """Monitor can access assigned-site CRFs; cannot access other sites."""
    print("\n--- Scenario A: Monitor Site-Restricted Access ---")
    pipeline = ClinicalTrialRAGPipeline()
    ctx = _validated_ctx(
        user_id="MONITOR-001",
        user_role=ClinicalTrialRole.MONITOR,
        assigned_site_ids=frozenset({"SITE-A"}),
    )
    docs = [
        ClinicalDocument("CRF-SITE-A", ClinicalDocumentType.CASE_REPORT_FORM,
                         GxPTier.GCP, PHIClassification.IDENTIFIED, site_id="SITE-A"),
        ClinicalDocument("CRF-SITE-B", ClinicalDocumentType.CASE_REPORT_FORM,
                         GxPTier.GCP, PHIClassification.IDENTIFIED, site_id="SITE-B"),
    ]
    result = pipeline.retrieve(docs, ctx)
    print(f"  Permitted: {[d.document_id for d in result.permitted_documents]}")
    print(f"  Blocked: {list(result.block_reasons.keys())}")


def scenario_b_sponsor_blinding_block() -> None:
    """Sponsor cannot access blinded interim analysis before DBL."""
    print("\n--- Scenario B: Sponsor Blocked from Blinded Interim Analysis ---")
    pipeline = ClinicalTrialRAGPipeline()
    ctx = _validated_ctx(
        user_id="SPONSOR-001",
        user_role=ClinicalTrialRole.SPONSOR,
        database_locked=False,
    )
    docs = [
        ClinicalDocument("IA-001", ClinicalDocumentType.INTERIM_ANALYSIS,
                         GxPTier.GCP, PHIClassification.DE_IDENTIFIED, is_blinded=True),
        ClinicalDocument("IB-001", ClinicalDocumentType.INVESTIGATOR_BROCHURE,
                         GxPTier.GCP, PHIClassification.NO_PHI),
    ]
    result = pipeline.retrieve(docs, ctx)
    print(f"  Permitted: {[d.document_id for d in result.permitted_documents]}")
    for doc_id, reason in result.block_reasons.items():
        print(f"  Blocked {doc_id}: {reason[:80]}...")


def scenario_c_regulatory_full_access() -> None:
    """REGULATORY inspectors have full access to all documents."""
    print("\n--- Scenario C: Regulatory Inspector — Full Access ---")
    pipeline = ClinicalTrialRAGPipeline()
    ctx = _validated_ctx(
        user_id="FDA-001",
        user_role=ClinicalTrialRole.REGULATORY,
    )
    docs = [
        ClinicalDocument("BATCH-001", ClinicalDocumentType.BATCH_RECORD,
                         GxPTier.GMP, PHIClassification.NO_PHI),
        ClinicalDocument("RAW-001", ClinicalDocumentType.RAW_STUDY_DATA,
                         GxPTier.GLP, PHIClassification.NO_PHI),
        ClinicalDocument("IA-002", ClinicalDocumentType.INTERIM_ANALYSIS,
                         GxPTier.GCP, PHIClassification.IDENTIFIED, is_blinded=True),
    ]
    result = pipeline.retrieve(docs, ctx)
    print(f"  Permitted: {[d.document_id for d in result.permitted_documents]}")
    print(f"  Blocked: {list(result.block_reasons.keys())}")


def scenario_d_unvalidated_system() -> None:
    """All documents blocked when system validation is not complete."""
    print("\n--- Scenario D: Unvalidated System — All Documents Blocked ---")
    pipeline = ClinicalTrialRAGPipeline()
    ctx = _validated_ctx(system_validated=False)
    docs = [
        ClinicalDocument("PROTO-001", ClinicalDocumentType.PROTOCOL,
                         GxPTier.GCP, PHIClassification.NO_PHI),
        ClinicalDocument("PUB-001", ClinicalDocumentType.REGULATORY_SUBMISSION,
                         GxPTier.NON_GXP, PHIClassification.NO_PHI, is_public=True),
    ]
    result = pipeline.retrieve(docs, ctx)
    print(f"  Permitted: {[d.document_id for d in result.permitted_documents]}")
    print(f"  Blocked by 21 CFR Part 11: {result.audit.blocked_by_21cfr11}")
    print(f"  (Public docs bypass 21 CFR Part 11)")


if __name__ == "__main__":
    scenario_a_monitor_site_restricted()
    scenario_b_sponsor_blinding_block()
    scenario_c_regulatory_full_access()
    scenario_d_unvalidated_system()
