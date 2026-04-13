"""
25_digital_health_rag.py — Four-layer RAG pipeline for digital health and
telehealth platforms handling patient-generated and clinical health data.

Demonstrates a multi-layer defense-in-depth retrieval architecture where four
overlapping regulatory frameworks each independently enforce access control on
health document retrieval in a telehealth or digital health context:

    Layer 1  — FDA Software as a Medical Device (SaMD) Classification:
               The FDA's Digital Health Center of Excellence classifies SaMD
               into three risk tiers (Class I / II / III) based on the
               intended use and the risk posed to patients. Class III devices
               (e.g., AI-driven diagnostic tools) require 510(k) clearance or
               PMA approval before use; the intended use must be documented.
               Class II devices require documented intended use. Class I
               devices are exempt from pre-market controls. Public documents
               (e.g., published labeling) bypass SaMD restrictions.
               References: FDA 21 CFR Parts 860–892; FDA Guidance "Software as
               a Medical Device: Possible Framework" (2014); FDA Digital Health
               Center of Excellence.

    Layer 2  — 42 CFR Part 2 (SAMHSA Substance Use Disorder Records):
               Records relating to the treatment of substance use disorders
               (SUD) are subject to stricter confidentiality protections than
               HIPAA. Unlike standard HIPAA Treatment/Payment/Operations (TPO)
               exceptions, 42 CFR Part 2 prohibits disclosure without explicit
               written patient consent to a specific recipient — or unless the
               requester is part of the same SUD treatment program. References:
               42 CFR Part 2 (2020 revised rule); SAMHSA Guidance on Part 2
               Applicability.

    Layer 3  — HIPAA Special Categories (45 CFR Part 164):
               Certain health information categories carry heightened
               protections beyond standard HIPAA minimum-necessary rules:
               psychotherapy notes (45 CFR 164.524(a)(1)(i)) may not be
               disclosed even to the patient; HIV status records require
               explicit authorization or clinical need; genetic information
               (GINA, 45 CFR 164.514(f)) may not be used for non-clinical
               analytics or research without authorization; domestic violence
               records require treating provider role for access.

    Layer 4  — ONC 21st Century Cures Act / Information Blocking Rule
               (45 CFR Part 171):
               The 21st Century Cures Act (Pub. L. 114-255) and ONC
               Information Blocking Rule prohibit actors — including health IT
               developers, HINs, and health care providers — from engaging in
               practices that interfere with the access, exchange, or use of
               electronic health information (EHI) for patient-directed access.
               Blocking patient or patient advocate access without a valid
               regulatory exception constitutes a federal civil violation
               subject to civil monetary penalties up to $1 million per
               violation (42 U.S.C. §300jj-52). Other layers may still
               restrict access for clinical roles; this layer enforces
               pro-access for patient-directed requests.

No external dependencies required.

Run:
    python examples/25_digital_health_rag.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class DigitalHealthRole(str, Enum):
    """
    User roles in a digital health / telehealth platform.

    PRESCRIBER             — Licensed clinician authorized to prescribe; clinical
                             access to patient records under TPO.
    CARE_MANAGER           — Care coordination role; limited clinical access.
    PATIENT                — Patient accessing their own records (patient-directed).
    PATIENT_ADVOCATE       — Authorized representative or caregiver acting for patient.
    SUD_COUNSELOR          — Substance use disorder counselor within the same program.
    MENTAL_HEALTH_PROVIDER — Licensed mental health professional; sole role that
                             may access psychotherapy notes.
    DATA_ANALYST           — Business intelligence or operational analytics role;
                             no clinical access privilege.
    RESEARCHER             — Academic or industry researcher; requires explicit
                             authorization for protected categories.
    ADMIN                  — Platform administrator; limited to operational records.
    """

    PRESCRIBER = "PRESCRIBER"
    CARE_MANAGER = "CARE_MANAGER"
    PATIENT = "PATIENT"
    PATIENT_ADVOCATE = "PATIENT_ADVOCATE"
    SUD_COUNSELOR = "SUD_COUNSELOR"
    MENTAL_HEALTH_PROVIDER = "MENTAL_HEALTH_PROVIDER"
    DATA_ANALYST = "DATA_ANALYST"
    RESEARCHER = "RESEARCHER"
    ADMIN = "ADMIN"


class SaMDClass(str, Enum):
    """
    FDA Software as a Medical Device risk classification.

    CLASS_I   — Lowest risk; general controls only; 510(k) exempt.
    CLASS_II  — Moderate risk; 510(k) clearance usually required;
                intended use must be documented.
    CLASS_III — Highest risk (e.g., AI diagnostic, life-support decisions);
                PMA or 510(k) clearance required; device must be cleared AND
                intended use must be documented before access is permitted.
    """

    CLASS_I = "CLASS_I"
    CLASS_II = "CLASS_II"
    CLASS_III = "CLASS_III"


class SpecialCategory(str, Enum):
    """
    HIPAA/statutory special category classifications for heightened protections.

    PSYCHOTHERAPY_NOTES — 45 CFR 164.524(a)(1)(i): psychotherapist's process
                          notes; excluded from standard HIPAA access rights;
                          accessible only to the treating MENTAL_HEALTH_PROVIDER.
    HIV_STATUS          — State laws + 45 CFR 164.502: HIV/AIDS diagnosis and
                          treatment status; requires authorization or designated
                          clinical role.
    GENETIC_INFO        — GINA + 45 CFR 164.514(f): genetic test results and
                          family history; may not be used for non-clinical
                          purposes without explicit authorization.
    DOMESTIC_VIOLENCE   — VAWA + state statutes: domestic violence, sexual
                          assault, stalking records; restricted to treating
                          providers to protect patient safety.
    NONE                — No special category restrictions; standard HIPAA rules
                          apply (handled by other layers).
    """

    PSYCHOTHERAPY_NOTES = "PSYCHOTHERAPY_NOTES"
    HIV_STATUS = "HIV_STATUS"
    GENETIC_INFO = "GENETIC_INFO"
    DOMESTIC_VIOLENCE = "DOMESTIC_VIOLENCE"
    NONE = "NONE"


# ---------------------------------------------------------------------------
# Role sets for special category access
# ---------------------------------------------------------------------------

_HIV_AUTHORIZED_ROLES = frozenset({
    DigitalHealthRole.PRESCRIBER,
    DigitalHealthRole.CARE_MANAGER,
    DigitalHealthRole.MENTAL_HEALTH_PROVIDER,
})

_NON_CLINICAL_ROLES = frozenset({
    DigitalHealthRole.DATA_ANALYST,
    DigitalHealthRole.RESEARCHER,
})

_PATIENT_DIRECTED_ROLES = frozenset({
    DigitalHealthRole.PATIENT,
    DigitalHealthRole.PATIENT_ADVOCATE,
})


# ---------------------------------------------------------------------------
# Context and document dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DigitalHealthContext:
    """
    Access context for a digital health RAG retrieval request.

    Attributes
    ----------
    user_id : str
        Unique identifier of the requesting user.
    user_role : DigitalHealthRole
        The user's platform role, determining access privileges.
    device_cleared : bool
        True if the SaMD has received 510(k) clearance or PMA approval from
        the FDA. Required for CLASS_III access.
    intended_use_documented : bool
        True if the SaMD's intended use is formally documented per FDA SaMD
        guidance. Required for CLASS_II and CLASS_III access.
    explicit_part2_consent : bool
        True if the patient has provided explicit written consent authorizing
        disclosure of 42 CFR Part 2 SUD records to this specific requester.
    is_same_sud_program : bool
        True if the requester is part of the same SUD treatment program that
        created the record (internal program communication exemption under
        42 CFR Part 2).
    hipaa_authorization_obtained : bool
        True if an explicit HIPAA authorization form has been obtained from
        the patient for the specific special-category use (e.g., sharing
        genetic info for research, HIV status disclosure).
    information_blocking_exception_applies : bool
        True if a valid ONC information blocking exception applies to this
        request (e.g., Privacy Exception under 45 CFR 171.202, Preventing
        Harm Exception under 45 CFR 171.201). If False, patient-directed
        access must be granted.
    is_patient_self_access : bool
        True if the request is patient-directed (PATIENT or PATIENT_ADVOCATE
        accessing the patient's own health information). Triggers ONC
        information blocking pro-access obligations.
    """

    user_id: str
    user_role: DigitalHealthRole
    device_cleared: bool
    intended_use_documented: bool
    explicit_part2_consent: bool
    is_same_sud_program: bool
    hipaa_authorization_obtained: bool
    information_blocking_exception_applies: bool
    is_patient_self_access: bool


@dataclass(frozen=True)
class DigitalHealthDocument:
    """
    A digital health document subject to four-layer access control.

    Attributes
    ----------
    document_id : str
        Unique document identifier.
    samd_class : SaMDClass
        FDA SaMD risk classification for this document's associated device/tool.
    is_sud_record : bool
        True if this document contains 42 CFR Part 2 substance use disorder
        treatment records.
    special_category : SpecialCategory
        HIPAA/statutory special category classification. NONE means no
        heightened protections apply at the special-category layer.
    is_public : bool
        True if the document is publicly available (e.g., FDA labeling,
        published guidance). Public documents bypass SaMD access controls.
    """

    document_id: str
    samd_class: SaMDClass
    is_sud_record: bool
    special_category: SpecialCategory
    is_public: bool = False


# ---------------------------------------------------------------------------
# Per-layer access result
# ---------------------------------------------------------------------------


@dataclass
class DigitalHealthAccessResult:
    """
    Result of a single filter layer's evaluation of one document.

    Attributes
    ----------
    layer : str
        Name of the filter layer that produced this result.
    permitted : bool
        True if access is permitted at this layer; False if blocked.
    reason : str
        Human-readable explanation of the blocking decision. Empty string
        when permitted.
    """

    layer: str
    permitted: bool = True
    reason: str = ""


# ---------------------------------------------------------------------------
# Pipeline output dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DigitalHealthRetrievalResult:
    """
    Result of a four-layer digital health RAG retrieval.

    Attributes
    ----------
    user_id : str
        Requesting user's identifier.
    user_role : str
        String value of the requesting user's role.
    permitted_documents : List[DigitalHealthDocument]
        Documents that passed all four layers.
    blocked_documents : List[DigitalHealthDocument]
        Documents blocked by at least one layer.
    block_reasons : Dict[str, str]
        Mapping from document_id to the reason string for the first blocking
        layer encountered. Documents that were not blocked are absent from
        this mapping.
    """

    user_id: str
    user_role: str
    permitted_documents: List[DigitalHealthDocument]
    blocked_documents: List[DigitalHealthDocument]
    block_reasons: Dict[str, str]

    def summary(self) -> Dict[str, object]:
        """Return a compact summary dict for logging."""
        return {
            "user_id": self.user_id,
            "user_role": self.user_role,
            "permitted": len(self.permitted_documents),
            "blocked": len(self.blocked_documents),
        }


@dataclass
class DigitalHealthAuditRecord:
    """
    Audit record for a digital health retrieval, required for SaMD audit trails
    and HIPAA accountability obligations.

    Attributes
    ----------
    user_id : str
        Requesting user's identifier.
    user_role : str
        String value of the requesting user's role.
    total_requested : int
        Total number of documents submitted to the pipeline.
    total_permitted : int
        Number of documents that passed all four layers.
    total_blocked : int
        Number of documents blocked by at least one layer.
    """

    user_id: str
    user_role: str
    total_requested: int
    total_permitted: int
    total_blocked: int

    def to_audit_log(self) -> dict:
        """Serialize to a structured audit log dict."""
        return {
            "event": "DIGITAL_HEALTH_RAG_RETRIEVAL",
            "user_id": self.user_id,
            "user_role": self.user_role,
            "total_requested": self.total_requested,
            "total_permitted": self.total_permitted,
            "total_blocked": self.total_blocked,
        }


# ---------------------------------------------------------------------------
# Layer 1 — FDA SaMD Classification Filter
# ---------------------------------------------------------------------------


class FDASaMDFilter:
    """
    Layer 1: FDA Software as a Medical Device (SaMD) Classification.

    Risk-tiered access control based on the FDA's SaMD classification
    framework:

    - CLASS_III documents (highest risk, e.g., AI diagnostics, life-support
      decision support) require both 510(k) clearance / PMA approval AND
      documented intended use before retrieval is permitted.
    - CLASS_II documents require documented intended use.
    - CLASS_I documents carry no SaMD retrieval restrictions.
    - Public documents (is_public=True) bypass all SaMD controls — they are
      already publicly accessible (e.g., FDA-cleared device labeling,
      published software documentation).

    References
    ----------
    FDA 21 CFR Parts 860–892 — Medical Device Classification
    FDA Guidance: "Software as a Medical Device (SaMD): Possible Framework
        for Risk Categorization and Corresponding Considerations" (2014)
    FDA Digital Health Center of Excellence — SaMD Action Plan (2021)
    """

    def _evaluate(
        self, ctx: DigitalHealthContext, doc: DigitalHealthDocument
    ) -> DigitalHealthAccessResult:
        """
        Evaluate a single document against the SaMD classification rules.

        Parameters
        ----------
        ctx : DigitalHealthContext
            Access context for the requesting user.
        doc : DigitalHealthDocument
            Document being evaluated.

        Returns
        -------
        DigitalHealthAccessResult
            Permitted if the device/document passes SaMD controls; blocked
            with a regulatory citation otherwise.
        """
        if doc.is_public:
            return DigitalHealthAccessResult(layer="FDA_SaMD", permitted=True)

        if doc.samd_class == SaMDClass.CLASS_III:
            if not ctx.device_cleared:
                return DigitalHealthAccessResult(
                    layer="FDA_SaMD",
                    permitted=False,
                    reason=(
                        "FDA SaMD Class III (21 CFR Part 860): Device has not received "
                        "510(k) clearance or PMA approval — retrieval from an uncleared "
                        "Class III SaMD system is not permitted"
                    ),
                )
            if not ctx.intended_use_documented:
                return DigitalHealthAccessResult(
                    layer="FDA_SaMD",
                    permitted=False,
                    reason=(
                        "FDA SaMD Class III: Intended use is not documented — FDA SaMD "
                        "guidance requires a clearly specified intended use statement "
                        "before a Class III device may be used in clinical workflows"
                    ),
                )

        elif doc.samd_class == SaMDClass.CLASS_II:
            if not ctx.intended_use_documented:
                return DigitalHealthAccessResult(
                    layer="FDA_SaMD",
                    permitted=False,
                    reason=(
                        "FDA SaMD Class II: Intended use is not documented — Class II "
                        "SaMD devices must have their intended use on file before "
                        "clinical deployment (FDA SaMD Guidance, 2014)"
                    ),
                )

        # CLASS_I: no SaMD retrieval restrictions
        return DigitalHealthAccessResult(layer="FDA_SaMD", permitted=True)

    def filter_documents(
        self,
        ctx: DigitalHealthContext,
        docs: List[DigitalHealthDocument],
    ) -> List[DigitalHealthDocument]:
        """Return only documents that pass the SaMD classification filter."""
        return [doc for doc in docs if self._evaluate(ctx, doc).permitted]


# ---------------------------------------------------------------------------
# Layer 2 — 42 CFR Part 2 SUD Records Filter
# ---------------------------------------------------------------------------


class Part2SUDFilter:
    """
    Layer 2: 42 CFR Part 2 — Substance Use Disorder Treatment Records.

    Records relating to the identity, diagnosis, prognosis, or treatment of
    a patient's substance use disorder (SUD) are subject to federal
    confidentiality protections that are stricter than HIPAA. Unlike HIPAA,
    the Part 2 rule does not permit disclosure under standard TPO exceptions.

    Disclosure of Part 2 records is permitted only when:
      (a) The patient has provided explicit written consent authorizing
          disclosure to the specific recipient (explicit_part2_consent=True);
          OR
      (b) The requester is a workforce member of the same Part 2 program that
          created the record — i.e., an internal communication within the
          treating SUD program (is_same_sud_program=True).

    Non-SUD documents pass this layer without restriction.

    References
    ----------
    42 CFR Part 2 — Confidentiality of Substance Use Disorder Patient Records
        (2020 revised final rule, effective March 21, 2020)
    SAMHSA Guidance: "Applying the Substance Abuse Confidentiality
        Regulations to Health Information Exchanges" (2010)
    42 U.S.C. §290dd-2 — Confidentiality of records
    """

    def _evaluate(
        self, ctx: DigitalHealthContext, doc: DigitalHealthDocument
    ) -> DigitalHealthAccessResult:
        """
        Evaluate a single document against 42 CFR Part 2 controls.

        Parameters
        ----------
        ctx : DigitalHealthContext
            Access context for the requesting user.
        doc : DigitalHealthDocument
            Document being evaluated.

        Returns
        -------
        DigitalHealthAccessResult
            Permitted if the document is not a Part 2 SUD record, or if
            explicit consent or same-program conditions are met; blocked
            with a regulatory citation otherwise.
        """
        if not doc.is_sud_record:
            return DigitalHealthAccessResult(layer="42_CFR_Part2", permitted=True)

        # Part 2 SUD record: require explicit consent OR same-program access
        if ctx.explicit_part2_consent:
            return DigitalHealthAccessResult(layer="42_CFR_Part2", permitted=True)

        if ctx.is_same_sud_program:
            return DigitalHealthAccessResult(layer="42_CFR_Part2", permitted=True)

        return DigitalHealthAccessResult(
            layer="42_CFR_Part2",
            permitted=False,
            reason=(
                "42 CFR Part 2 §2.31: Document contains substance use disorder "
                "treatment records — disclosure requires explicit written patient "
                "consent to this specific recipient, or requester must be within the "
                "same SUD treatment program; neither condition is met"
            ),
        )

    def filter_documents(
        self,
        ctx: DigitalHealthContext,
        docs: List[DigitalHealthDocument],
    ) -> List[DigitalHealthDocument]:
        """Return only documents that pass the 42 CFR Part 2 filter."""
        return [doc for doc in docs if self._evaluate(ctx, doc).permitted]


# ---------------------------------------------------------------------------
# Layer 3 — HIPAA Special Categories Filter
# ---------------------------------------------------------------------------


class HIPAASpecialCategoryFilter:
    """
    Layer 3: HIPAA Special Categories — Heightened Protections.

    Certain health information categories carry statutory or regulatory
    protections beyond HIPAA's standard minimum-necessary and TPO exceptions:

    PSYCHOTHERAPY_NOTES
        Psychotherapist process notes are excluded from the HIPAA right of
        access (45 CFR 164.524(a)(1)(i)) and require separate authorization
        for disclosure. Only the treating MENTAL_HEALTH_PROVIDER may retrieve
        these notes — not other clinical roles, not the patient.

    HIV_STATUS
        HIV/AIDS diagnosis and treatment status requires explicit HIPAA
        authorization OR the requesting role must be one of: PRESCRIBER,
        CARE_MANAGER, or MENTAL_HEALTH_PROVIDER (treating clinical roles
        with a legitimate TPO basis).

    GENETIC_INFO
        Genetic test results and family history information may not be used
        for underwriting, employment, or non-clinical analytics (GINA,
        45 CFR 164.514(f)). DATA_ANALYST and RESEARCHER roles are blocked
        unless an explicit HIPAA authorization covering the genetic information
        use has been obtained.

    DOMESTIC_VIOLENCE
        Domestic violence, sexual assault, and stalking records require a
        treating provider role (MENTAL_HEALTH_PROVIDER or PRESCRIBER) to
        protect patient safety and confidentiality per VAWA and state statutes.

    NONE
        No special-category restrictions — document passes this layer.

    References
    ----------
    45 CFR 164.524(a)(1)(i) — Psychotherapy notes exclusion from access right
    45 CFR 164.514(f) — Prohibition on use of genetic information for
        underwriting
    GINA (Genetic Information Nondiscrimination Act, Pub. L. 110-233)
    VAWA (Violence Against Women Act) — confidentiality provisions
    45 CFR 164.502 — Uses and disclosures of PHI
    """

    def _evaluate(
        self, ctx: DigitalHealthContext, doc: DigitalHealthDocument
    ) -> DigitalHealthAccessResult:
        """
        Evaluate a single document against HIPAA special category rules.

        Parameters
        ----------
        ctx : DigitalHealthContext
            Access context for the requesting user.
        doc : DigitalHealthDocument
            Document being evaluated.

        Returns
        -------
        DigitalHealthAccessResult
            Permitted if the special category rules are satisfied; blocked
            with a regulatory citation otherwise.
        """
        cat = doc.special_category

        if cat == SpecialCategory.NONE:
            return DigitalHealthAccessResult(
                layer="HIPAA_Special_Category", permitted=True
            )

        if cat == SpecialCategory.PSYCHOTHERAPY_NOTES:
            # 45 CFR 164.524(a)(1)(i): excluded from standard access right.
            # Only the treating mental health provider may retrieve these notes.
            if ctx.user_role != DigitalHealthRole.MENTAL_HEALTH_PROVIDER:
                return DigitalHealthAccessResult(
                    layer="HIPAA_Special_Category",
                    permitted=False,
                    reason=(
                        "HIPAA 45 CFR 164.524(a)(1)(i): Psychotherapy notes are excluded "
                        "from the standard right of access and from TPO disclosures — "
                        "retrieval is restricted to the treating MENTAL_HEALTH_PROVIDER; "
                        f"role {ctx.user_role.value} is not authorized"
                    ),
                )

        elif cat == SpecialCategory.HIV_STATUS:
            # HIV status requires authorization or designated clinical role
            has_clinical_access = ctx.user_role in _HIV_AUTHORIZED_ROLES
            if not has_clinical_access and not ctx.hipaa_authorization_obtained:
                return DigitalHealthAccessResult(
                    layer="HIPAA_Special_Category",
                    permitted=False,
                    reason=(
                        "HIPAA 45 CFR 164.502: HIV/AIDS status records require explicit "
                        "HIPAA authorization or a designated clinical role (PRESCRIBER, "
                        "CARE_MANAGER, MENTAL_HEALTH_PROVIDER); "
                        f"role {ctx.user_role.value} does not meet either condition"
                    ),
                )

        elif cat == SpecialCategory.GENETIC_INFO:
            # GINA + 45 CFR 164.514(f): non-clinical roles blocked without authorization
            if ctx.user_role in _NON_CLINICAL_ROLES and not ctx.hipaa_authorization_obtained:
                return DigitalHealthAccessResult(
                    layer="HIPAA_Special_Category",
                    permitted=False,
                    reason=(
                        "GINA / HIPAA 45 CFR 164.514(f): Genetic information may not be "
                        "used for non-clinical analytics or research without explicit "
                        "HIPAA authorization; "
                        f"role {ctx.user_role.value} is blocked without authorization"
                    ),
                )

        elif cat == SpecialCategory.DOMESTIC_VIOLENCE:
            # Treating provider roles only — protect patient safety
            dv_authorized = ctx.user_role in (
                DigitalHealthRole.MENTAL_HEALTH_PROVIDER,
                DigitalHealthRole.PRESCRIBER,
            )
            if not dv_authorized:
                return DigitalHealthAccessResult(
                    layer="HIPAA_Special_Category",
                    permitted=False,
                    reason=(
                        "VAWA / HIPAA special categories: Domestic violence, sexual "
                        "assault, and stalking records are restricted to treating "
                        "providers (MENTAL_HEALTH_PROVIDER, PRESCRIBER) to protect "
                        "patient safety; "
                        f"role {ctx.user_role.value} is not authorized"
                    ),
                )

        return DigitalHealthAccessResult(
            layer="HIPAA_Special_Category", permitted=True
        )

    def filter_documents(
        self,
        ctx: DigitalHealthContext,
        docs: List[DigitalHealthDocument],
    ) -> List[DigitalHealthDocument]:
        """Return only documents that pass the HIPAA special category filter."""
        return [doc for doc in docs if self._evaluate(ctx, doc).permitted]


# ---------------------------------------------------------------------------
# Layer 4 — ONC/21st Century Cures Interoperability Filter
# ---------------------------------------------------------------------------


class ONCInteroperabilityFilter:
    """
    Layer 4: ONC Information Blocking Rule (45 CFR Part 171).

    The 21st Century Cures Act (Pub. L. 114-255, §4004) and the ONC
    Information Blocking Rule prohibit health IT actors from engaging in
    practices that unreasonably limit the access, exchange, or use of
    electronic health information (EHI).

    For patient-directed access (is_patient_self_access=True, or role is
    PATIENT or PATIENT_ADVOCATE), access MUST be granted unless a valid
    regulatory exception applies (information_blocking_exception_applies=True).
    Blocking patient access to their own EHI without a qualifying exception
    is a federal civil violation subject to civil monetary penalties of up to
    $1,000,000 per violation (42 U.S.C. §300jj-52).

    Valid ONC exceptions include (45 CFR Part 171, Subpart B):
      - Preventing Harm Exception (§171.201)
      - Privacy Exception (§171.202)
      - Security Exception (§171.203)
      - Infeasibility Exception (§171.204)
      - Health IT Performance Exception (§171.205)
      - Content and Manner Exception (§171.301–171.303)

    For clinical roles (non-patient-directed requests): other layers already
    enforce appropriate restrictions; this layer passes through without adding
    further restrictions, preserving the pro-access intent of the Rule for
    clinical information exchange.

    References
    ----------
    21st Century Cures Act, Pub. L. 114-255 §4004 (2016)
    45 CFR Part 171 — Information Blocking (ONC Final Rule, 2020)
    42 U.S.C. §300jj-52 — Penalties for information blocking
    ONC Fact Sheet: "Information Blocking and the ONC Health IT Certification
        Program Final Rule" (May 2020)
    """

    def _evaluate(
        self, ctx: DigitalHealthContext, doc: DigitalHealthDocument
    ) -> DigitalHealthAccessResult:
        """
        Evaluate a single document against the ONC information blocking rule.

        Parameters
        ----------
        ctx : DigitalHealthContext
            Access context for the requesting user.
        doc : DigitalHealthDocument
            Document being evaluated.

        Returns
        -------
        DigitalHealthAccessResult
            For patient-directed access: permitted unless a valid exception
            applies; for clinical roles: passes through.
        """
        is_patient_directed = (
            ctx.is_patient_self_access
            or ctx.user_role in _PATIENT_DIRECTED_ROLES
        )

        if not is_patient_directed:
            # Clinical roles: ONC layer passes through — other layers handle
            # clinical access restrictions.
            return DigitalHealthAccessResult(
                layer="ONC_Interoperability", permitted=True
            )

        # Patient-directed access: must permit unless a valid exception applies
        if ctx.information_blocking_exception_applies:
            return DigitalHealthAccessResult(
                layer="ONC_Interoperability",
                permitted=False,
                reason=(
                    "ONC Information Blocking Rule 45 CFR Part 171: Patient-directed "
                    "access is restricted under an applicable regulatory exception "
                    "(e.g., Privacy Exception §171.202 or Preventing Harm Exception "
                    "§171.201) — access denied for document "
                    f"{doc.document_id}"
                ),
            )

        # No valid exception: blocking patient access would be information
        # blocking under 45 CFR §171.103 — access must be granted.
        return DigitalHealthAccessResult(
            layer="ONC_Interoperability", permitted=True
        )

    def filter_documents(
        self,
        ctx: DigitalHealthContext,
        docs: List[DigitalHealthDocument],
    ) -> List[DigitalHealthDocument]:
        """Return only documents that pass the ONC interoperability filter."""
        return [doc for doc in docs if self._evaluate(ctx, doc).permitted]


# ---------------------------------------------------------------------------
# Four-layer pipeline
# ---------------------------------------------------------------------------


class DigitalHealthRAGPipeline:
    """
    Four-layer digital health RAG retrieval pipeline.

    Evaluation order:
        FDA SaMD Classification  →  42 CFR Part 2 SUD  →
        HIPAA Special Categories  →  ONC Interoperability

    A document must pass all four layers to be included in the retrieval
    result. Each layer operates independently. If a document is blocked at
    any layer, the block reason from that layer is recorded and the document
    is not passed to subsequent layers.

    Example
    -------
    >>> pipeline = DigitalHealthRAGPipeline()
    >>> ctx = DigitalHealthContext(
    ...     user_id="PRESCRIBER-001",
    ...     user_role=DigitalHealthRole.PRESCRIBER,
    ...     device_cleared=True,
    ...     intended_use_documented=True,
    ...     explicit_part2_consent=False,
    ...     is_same_sud_program=False,
    ...     hipaa_authorization_obtained=False,
    ...     information_blocking_exception_applies=False,
    ...     is_patient_self_access=False,
    ... )
    """

    def __init__(self) -> None:
        self._samd = FDASaMDFilter()
        self._part2 = Part2SUDFilter()
        self._hipaa = HIPAASpecialCategoryFilter()
        self._onc = ONCInteroperabilityFilter()

    def retrieve(
        self,
        context: DigitalHealthContext,
        documents: List[DigitalHealthDocument],
    ) -> DigitalHealthRetrievalResult:
        """
        Apply all four layers sequentially to the candidate document list.

        Each document is evaluated through:
          1. FDA SaMD Classification
          2. 42 CFR Part 2 SUD
          3. HIPAA Special Categories
          4. ONC Interoperability

        The first blocking layer wins for each document; the block reason is
        recorded and the document is excluded from further evaluation.

        Parameters
        ----------
        context : DigitalHealthContext
            Access context for the requesting user.
        documents : List[DigitalHealthDocument]
            Candidate documents from the vector store retrieval step.

        Returns
        -------
        DigitalHealthRetrievalResult
            Permitted and blocked document lists with per-document block
            reasons and a summary-level audit record.
        """
        permitted_docs: List[DigitalHealthDocument] = []
        blocked_docs: List[DigitalHealthDocument] = []
        block_reasons: Dict[str, str] = {}

        layers = [
            ("FDA_SaMD", self._samd._evaluate),
            ("42_CFR_Part2", self._part2._evaluate),
            ("HIPAA_Special_Category", self._hipaa._evaluate),
            ("ONC_Interoperability", self._onc._evaluate),
        ]

        for doc in documents:
            blocked = False
            for _layer_name, evaluate_fn in layers:
                result = evaluate_fn(context, doc)
                if not result.permitted:
                    blocked_docs.append(doc)
                    block_reasons[doc.document_id] = result.reason
                    blocked = True
                    break
            if not blocked:
                permitted_docs.append(doc)

        return DigitalHealthRetrievalResult(
            user_id=context.user_id,
            user_role=context.user_role.value,
            permitted_documents=permitted_docs,
            blocked_documents=blocked_docs,
            block_reasons=block_reasons,
        )


# ---------------------------------------------------------------------------
# Scenario demonstrations
# ---------------------------------------------------------------------------


def _print_result(result: DigitalHealthRetrievalResult) -> None:
    """Pretty-print a retrieval result for scenario output."""
    permitted_ids = [d.document_id for d in result.permitted_documents]
    print(f"  Permitted ({len(permitted_ids)}): {permitted_ids}")
    if result.block_reasons:
        for doc_id, reason in result.block_reasons.items():
            # Truncate long reasons for readability
            short = reason if len(reason) <= 110 else reason[:107] + "..."
            print(f"  Blocked  {doc_id}: {short}")
    else:
        print("  Blocked (0): []")

    audit = DigitalHealthAuditRecord(
        user_id=result.user_id,
        user_role=result.user_role,
        total_requested=len(result.permitted_documents) + len(result.blocked_documents),
        total_permitted=len(result.permitted_documents),
        total_blocked=len(result.blocked_documents),
    )
    print(f"  Audit log: {audit.to_audit_log()}")


def scenario_a_prescriber_patient_records() -> None:
    """
    Scenario A: Prescriber accessing a patient's clinical records.

    A licensed prescriber with a fully cleared and documented Class III SaMD
    accesses records for a patient they are treating. The records contain
    standard clinical information (no SUD records, no special categories).
    All four layers permit access.
    """
    print("\n--- Scenario A: Prescriber Accessing Patient Clinical Records ---")
    pipeline = DigitalHealthRAGPipeline()

    ctx = DigitalHealthContext(
        user_id="PRESCRIBER-001",
        user_role=DigitalHealthRole.PRESCRIBER,
        device_cleared=True,
        intended_use_documented=True,
        explicit_part2_consent=False,
        is_same_sud_program=False,
        hipaa_authorization_obtained=False,
        information_blocking_exception_applies=False,
        is_patient_self_access=False,
    )

    docs = [
        DigitalHealthDocument(
            document_id="MED-HIST-001",
            samd_class=SaMDClass.CLASS_III,
            is_sud_record=False,
            special_category=SpecialCategory.NONE,
            is_public=False,
        ),
        DigitalHealthDocument(
            document_id="LAB-RESULTS-002",
            samd_class=SaMDClass.CLASS_II,
            is_sud_record=False,
            special_category=SpecialCategory.HIV_STATUS,
            is_public=False,
        ),
        DigitalHealthDocument(
            document_id="CARE-PLAN-003",
            samd_class=SaMDClass.CLASS_I,
            is_sud_record=False,
            special_category=SpecialCategory.NONE,
            is_public=False,
        ),
    ]

    result = pipeline.retrieve(ctx, docs)
    _print_result(result)
    assert len(result.permitted_documents) == 3, (
        f"Expected all 3 documents permitted; got {len(result.permitted_documents)}"
    )
    print("  [PASS] All documents permitted for PRESCRIBER with cleared Class III SaMD.")


def scenario_b_analyst_sud_blocked() -> None:
    """
    Scenario B: Data analyst attempting to access SUD records without consent.

    A data analyst queries a knowledge base that includes 42 CFR Part 2 SUD
    treatment records. No explicit patient consent has been obtained and the
    analyst is not in the same SUD program. Layer 2 (42 CFR Part 2) blocks
    the SUD records; non-SUD documents pass through (subject to other layers).
    """
    print("\n--- Scenario B: Data Analyst Blocked from SUD Records (42 CFR Part 2) ---")
    pipeline = DigitalHealthRAGPipeline()

    ctx = DigitalHealthContext(
        user_id="ANALYST-007",
        user_role=DigitalHealthRole.DATA_ANALYST,
        device_cleared=True,
        intended_use_documented=True,
        explicit_part2_consent=False,    # No patient consent
        is_same_sud_program=False,        # Not in same SUD program
        hipaa_authorization_obtained=False,
        information_blocking_exception_applies=False,
        is_patient_self_access=False,
    )

    docs = [
        DigitalHealthDocument(
            document_id="SUD-RECORD-001",
            samd_class=SaMDClass.CLASS_I,
            is_sud_record=True,           # 42 CFR Part 2 record
            special_category=SpecialCategory.NONE,
            is_public=False,
        ),
        DigitalHealthDocument(
            document_id="SUD-TREATMENT-002",
            samd_class=SaMDClass.CLASS_I,
            is_sud_record=True,           # 42 CFR Part 2 record
            special_category=SpecialCategory.NONE,
            is_public=False,
        ),
        DigitalHealthDocument(
            document_id="AGGREGATE-REPORT-003",
            samd_class=SaMDClass.CLASS_I,
            is_sud_record=False,          # Not a Part 2 record — de-identified aggregate
            special_category=SpecialCategory.NONE,
            is_public=False,
        ),
    ]

    result = pipeline.retrieve(ctx, docs)
    _print_result(result)
    assert len(result.permitted_documents) == 1, (
        f"Expected 1 document permitted; got {len(result.permitted_documents)}"
    )
    assert "SUD-RECORD-001" in result.block_reasons
    assert "SUD-TREATMENT-002" in result.block_reasons
    print("  [PASS] SUD records blocked by 42 CFR Part 2; aggregate report permitted.")


def scenario_c_patient_self_access() -> None:
    """
    Scenario C: Patient accessing their own health records (patient-directed).

    A patient uses a digital health app to access their own electronic health
    information. The ONC Information Blocking Rule requires that patient-directed
    access be permitted unless a valid regulatory exception applies. No exception
    is claimed here, so all documents that pass earlier layers must be released.
    Psychotherapy notes are blocked at Layer 3 (HIPAA special category — not even
    the patient may access these under 45 CFR 164.524(a)(1)(i)).
    """
    print("\n--- Scenario C: Patient-Directed Access to Own Records (ONC Rule) ---")
    pipeline = DigitalHealthRAGPipeline()

    ctx = DigitalHealthContext(
        user_id="PATIENT-042",
        user_role=DigitalHealthRole.PATIENT,
        device_cleared=True,
        intended_use_documented=True,
        explicit_part2_consent=False,
        is_same_sud_program=False,
        hipaa_authorization_obtained=False,
        information_blocking_exception_applies=False,  # No exception — must grant access
        is_patient_self_access=True,
    )

    docs = [
        DigitalHealthDocument(
            document_id="PATIENT-SUMMARY-001",
            samd_class=SaMDClass.CLASS_II,
            is_sud_record=False,
            special_category=SpecialCategory.NONE,
            is_public=False,
        ),
        DigitalHealthDocument(
            document_id="LAB-RESULTS-002",
            samd_class=SaMDClass.CLASS_II,
            is_sud_record=False,
            special_category=SpecialCategory.NONE,
            is_public=False,
        ),
        DigitalHealthDocument(
            document_id="THERAPY-NOTES-003",
            samd_class=SaMDClass.CLASS_I,
            is_sud_record=False,
            special_category=SpecialCategory.PSYCHOTHERAPY_NOTES,  # Layer 3 blocks
            is_public=False,
        ),
    ]

    result = pipeline.retrieve(ctx, docs)
    _print_result(result)
    assert len(result.permitted_documents) == 2, (
        f"Expected 2 documents permitted; got {len(result.permitted_documents)}"
    )
    assert "THERAPY-NOTES-003" in result.block_reasons
    print(
        "  [PASS] Patient receives summary and labs; psychotherapy notes blocked "
        "per 45 CFR 164.524(a)(1)(i)."
    )


def scenario_d_mental_health_provider_psychotherapy() -> None:
    """
    Scenario D: Mental health provider accessing psychotherapy notes.

    A licensed mental health provider accesses a patient's psychotherapy notes
    (their own process notes). Under 45 CFR 164.524(a)(1)(i), psychotherapy
    notes may not be disclosed to the patient or other clinical roles — but the
    treating MENTAL_HEALTH_PROVIDER is the only authorized accessor. All four
    layers permit access for this role.
    """
    print("\n--- Scenario D: Mental Health Provider Accessing Psychotherapy Notes ---")
    pipeline = DigitalHealthRAGPipeline()

    ctx = DigitalHealthContext(
        user_id="MHP-023",
        user_role=DigitalHealthRole.MENTAL_HEALTH_PROVIDER,
        device_cleared=True,
        intended_use_documented=True,
        explicit_part2_consent=False,
        is_same_sud_program=False,
        hipaa_authorization_obtained=False,
        information_blocking_exception_applies=False,
        is_patient_self_access=False,
    )

    docs = [
        DigitalHealthDocument(
            document_id="THERAPY-NOTES-001",
            samd_class=SaMDClass.CLASS_I,
            is_sud_record=False,
            special_category=SpecialCategory.PSYCHOTHERAPY_NOTES,
            is_public=False,
        ),
        DigitalHealthDocument(
            document_id="THERAPY-NOTES-002",
            samd_class=SaMDClass.CLASS_II,
            is_sud_record=False,
            special_category=SpecialCategory.PSYCHOTHERAPY_NOTES,
            is_public=False,
        ),
        DigitalHealthDocument(
            document_id="PATIENT-INTAKE-003",
            samd_class=SaMDClass.CLASS_I,
            is_sud_record=False,
            special_category=SpecialCategory.NONE,
            is_public=False,
        ),
    ]

    result = pipeline.retrieve(ctx, docs)
    _print_result(result)
    assert len(result.permitted_documents) == 3, (
        f"Expected all 3 documents permitted for MENTAL_HEALTH_PROVIDER; "
        f"got {len(result.permitted_documents)}"
    )
    assert len(result.blocked_documents) == 0
    print(
        "  [PASS] Mental health provider permitted full access including "
        "psychotherapy notes."
    )


if __name__ == "__main__":
    print("=" * 70)
    print("Digital Health / Telehealth RAG Pipeline — Four-Layer Compliance")
    print("  Layer 1: FDA SaMD Classification (21 CFR Parts 860-892)")
    print("  Layer 2: 42 CFR Part 2 SUD Records (SAMHSA)")
    print("  Layer 3: HIPAA Special Categories (45 CFR Part 164)")
    print("  Layer 4: ONC Information Blocking Rule (45 CFR Part 171)")
    print("=" * 70)

    scenario_a_prescriber_patient_records()
    scenario_b_analyst_sud_blocked()
    scenario_c_patient_self_access()
    scenario_d_mental_health_provider_psychotherapy()

    print("\n" + "=" * 70)
    print("All scenarios completed successfully.")
    print("=" * 70)
