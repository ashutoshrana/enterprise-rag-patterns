"""
Government and Public Sector RAG Pipeline — Four-Layer Defense-in-Depth

This module implements a compliance-aware RAG retrieval pipeline for government
and public sector platforms. Four independent filter layers run sequentially; a
document must pass all four to be returned to the caller.

Commercial use cases:

  +---------------------------------+----------------------------------------------+
  | Platform / Product              | Applicable Regulation(s)                     |
  +---------------------------------+----------------------------------------------+
  | Federal agency knowledge bases  | FedRAMP, FISMA, NIST SP 800-53               |
  | Contractor document portals     | FAR/DFARS, CUI 32 CFR Part 2002              |
  | Law enforcement data systems    | CUI-LES, Privacy Act 5 USC §552a            |
  | Congressional staff platforms   | Constitutional oversight, 5 USC §552         |
  | Inspector General audit tools   | Inspector General Act 5 USC App. §6          |
  | Export-controlled research      | EAR/ITAR, CUI Export Control category        |
  | State/local government portals  | NIST SP 800-53B (LOW baseline), Privacy Act  |
  | Defense contractor systems      | DFARS 252.204-7012, CUI, FISMA               |
  +---------------------------------+----------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — FedRAMP Authorization
      The Federal Risk and Authorization Management Program (FedRAMP) provides
      a standardized approach to security assessment, authorization, and
      continuous monitoring for cloud products and services used by federal
      agencies.  FedRAMP defines three impact levels — High, Moderate, and Low
      — aligned with FIPS 199 security categorizations.

      FedRAMP Program (https://www.fedramp.gov): Cloud service offerings must
      hold a FedRAMP Authorization at the required impact level before federal
      agency data at that level may be stored or processed.  Accessing High
      impact government data on a system authorized only at the Moderate level
      violates the program requirements and the interconnection security
      agreement (ISA).

      FISMA 44 USC §3554(a)(1)(A): Requires agency heads to implement and
      maintain information security programs for all agency information and
      information systems.  A system that lacks a current Authority To Operate
      (ATO) has not completed the NIST Risk Management Framework (RMF) process
      and may not process federal information.

      FIPS 199 (Standards for Security Categorization): The categorization
      of an information system drives the applicable NIST SP 800-53 control
      baseline.  HIGH categorized systems require the most rigorous control set;
      information from a HIGH categorized system may not flow to a system
      operating at a lower impact level (NIST SP 800-53 AC-4).

  Layer 2 — FISMA / NIST SP 800-53 Security Controls
      The Federal Information Security Modernization Act (FISMA, 44 USC §§3551-
      3558) requires each federal agency to develop, document, and implement an
      agency-wide information security program for all agency information and
      information systems.

      NIST SP 800-53 Rev. 5 (Security and Privacy Controls for Information
      Systems and Organizations): Provides the catalog of security and privacy
      controls from which agencies select baselines per NIST SP 800-53B.  Key
      access controls enforced by this layer:

        AC-3 (Access Enforcement): The information system enforces approved
        authorizations for logical access to information and system resources.
        Access to CUI requires explicit authorization; PUBLIC users may not
        access documents not cleared for public release.

        AC-3(7) (Access Enforcement — Role-Based Access Control): Enforces
        access based on the roles the individual is assigned and the permissions
        associated with those roles.  Need-to-know is established per role and
        document classification.

        AC-4 (Information Flow Enforcement): Controls the flow of information
        between interconnected systems.  HIGH impact documents may not flow to
        systems or users operating at lower categorization levels.

        PS-3 (Personnel Screening): Before authorizing individual access to a
        system or information, the organization screens individuals consistent
        with the security categorization of the system.  Contractor personnel
        must complete OPM background investigations appropriate to the access
        level requested.

  Layer 3 — CUI 32 CFR Part 2002 (Controlled Unclassified Information)
      Executive Order 13556 (November 4, 2010) established a government-wide
      program to standardize the way the executive branch handles unclassified
      information that requires safeguarding or dissemination controls.  The
      implementing regulation is 32 CFR Part 2002, administered by the National
      Archives and Records Administration (NARA).

      32 CFR §2002.14 (Safeguarding): Agencies must establish controls for CUI
      based on the CUI category and applicable laws, regulations, or Government-
      wide policies.  CUI must be marked, handled, and disseminated only to
      authorized recipients with a lawful government purpose and need-to-know.

      Privacy Act 5 USC §552a (Records about Individuals): Restricts agency
      disclosure of records in systems of records to individuals other than the
      subject unless the recipient meets a statutory exception.  Personnel
      accessing Privacy Act records must complete annual Privacy Act training per
      OMB Circular A-130.

      EAR (15 CFR Parts 730-774) / ITAR (22 CFR Parts 120-130): Export control
      laws restrict the transfer of controlled technology, technical data, and
      software to foreign persons (non-US persons), including in the context of
      unclassified government information systems.

      FAR 52.204-21 (Basic Safeguarding of Covered Contractor Information
      Systems): Requires contractors to apply basic safeguarding requirements
      to federal contract information.  CUI access by contractors requires an
      active FAR/DFARS contractor agreement.

  Layer 4 — Government Audit (NIST SP 800-53 AU-9 + Oversight Authorities)
      NIST SP 800-53 AU-9 (Protection of Audit Information): Protects audit
      information and tools from unauthorized access, modification, and deletion.
      For HIGH impact systems, audit records themselves require protection
      commensurate with the data they describe; access to HIGH impact audit
      records requires appropriate clearance.

      Inspector General Act of 1978, 5 USC Appendix §6 (Authority of Inspector
      General): Grants Inspectors General independent authority to access all
      records, reports, audits, reviews, documents, papers, recommendations, or
      other materials of their agency without requiring agency head approval.
      This authority overrides document-level access controls for IG oversight.

      Constitutional oversight authority + 5 USC §552: Congress holds broad
      oversight authority over the executive branch.  Congressional oversight
      requests backed by subpoena authority supersede agency access controls.
      The Freedom of Information Act (5 USC §552) supports this transparency
      framework for documents released to the public.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FedRAMPImpactLevel(Enum):
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    NOT_FEDRAMP = "NOT_FEDRAMP"


class CUICategory(Enum):
    UNCONTROLLED_PUBLIC = "UNCONTROLLED_PUBLIC"
    FOUO = "FOUO"                                        # For Official Use Only
    LAW_ENFORCEMENT_SENSITIVE = "LAW_ENFORCEMENT_SENSITIVE"
    PRIVACY_ACT = "PRIVACY_ACT"                          # 5 USC §552a
    EXPORT_CONTROLLED = "EXPORT_CONTROLLED"              # EAR/ITAR


class GovernmentRole(Enum):
    FEDERAL_EMPLOYEE = "FEDERAL_EMPLOYEE"
    CONTRACTOR = "CONTRACTOR"
    CLEARED_CONTRACTOR = "CLEARED_CONTRACTOR"            # Background check + clearance
    IG_AUDITOR = "IG_AUDITOR"                            # Inspector General
    CONGRESSIONAL_STAFF = "CONGRESSIONAL_STAFF"
    STATE_GOVERNMENT = "STATE_GOVERNMENT"
    PUBLIC = "PUBLIC"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"


class GovernmentDecision(Enum):
    PERMITTED = "PERMITTED"
    DENIED = "DENIED"
    REDACTED = "REDACTED"


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GovernmentRAGContext:
    """
    Carries all per-request attributes needed by the four filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorization state.
    """

    user_id: str
    user_role: GovernmentRole
    agency_id: str
    fedramp_authorization_level: FedRAMPImpactLevel   # What level the user's system is authorized at
    has_background_investigation: bool                # OPM background investigation completed
    has_security_clearance: bool                      # SECRET or above
    is_need_to_know: bool                             # Need-to-know determination made
    is_us_person: bool                                # US citizen/permanent resident (export control)
    has_privacy_act_training: bool                    # Annual Privacy Act training completed
    is_law_enforcement: bool                          # Sworn LEO or designated LE agency staff
    is_on_authorized_system: bool                     # Accessing from FedRAMP-authorized system
    contractor_agreement_active: bool                 # Valid FAR/DFARS contractor agreement
    fisma_system_category: str                        # "HIGH" / "MODERATE" / "LOW" per FIPS 199
    has_ato: bool                                     # Authority To Operate granted
    is_ig_oversight: bool                             # IG/GAO audit access context
    is_congressional_oversight: bool                  # Congressional oversight/subpoena access


@dataclass(frozen=True)
class GovernmentDocument:
    """
    Immutable document descriptor carrying attributes needed for compliance
    evaluation across all four filter layers.
    """

    document_id: str
    fedramp_required_level: FedRAMPImpactLevel        # Minimum authorization level to access
    cui_category: CUICategory
    contains_pii: bool                                # Privacy Act 5 USC §552a applies
    is_law_enforcement_sensitive: bool
    is_export_controlled: bool                        # EAR/ITAR restricted
    is_classified: bool                               # SCI/TS/S (not handled here, just gate)
    is_public_release_approved: bool                  # Cleared for FOIA / public release


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class GovernmentFilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: GovernmentDecision = GovernmentDecision.PERMITTED
    reason: str = ""
    regulation_citation: str = ""

    @property
    def is_denied(self) -> bool:
        return self.decision == GovernmentDecision.DENIED


# ---------------------------------------------------------------------------
# Layer 1: FedRAMPAuthorizationFilter
# ---------------------------------------------------------------------------

class FedRAMPAuthorizationFilter:
    """
    Enforces FedRAMP authorization level requirements and Authority To Operate
    (ATO) validation for federal information systems.

    FedRAMP defines three cloud authorization impact levels aligned with FIPS
    199 security categorizations.  Key enforcement points:

      FedRAMP Program: A cloud system must hold a FedRAMP Authorization at the
      required impact level before federal agency data at that level may be
      processed.  Accessing HIGH impact data on a MODERATE-authorized system
      violates the program boundary and interconnection security agreement.

      FISMA 44 USC §3554(a)(1)(A): Agency heads are responsible for ensuring
      all systems have a current Authority To Operate.  A system without an ATO
      has not completed the NIST RMF process and may not lawfully process
      federal information at any impact level.

      Classified information is outside the FedRAMP/FISMA unclassified boundary.
      Any document marked as classified must be routed to the appropriate
      classified enclave; this pipeline does not handle classified materials.
    """

    LAYER_NAME = "FEDRAMP_AUTHORIZATION"

    def evaluate(
        self, context: GovernmentRAGContext, document: GovernmentDocument
    ) -> GovernmentFilterResult:
        """
        Evaluate whether the requesting context satisfies FedRAMP authorization
        requirements for access to the document.

        Returns a GovernmentFilterResult with PERMITTED or DENIED together with
        the operative FedRAMP / FISMA citation and finding.
        """
        # Classified information is entirely outside the scope of this pipeline.
        if document.is_classified:
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "Classified information not handled by this system "
                    "— route to classified enclave"
                ),
                regulation_citation="FedRAMP Program + FISMA 44 USC §3541",
            )

        # HIGH impact documents require a HIGH-authorized system.
        if (
            document.fedramp_required_level == FedRAMPImpactLevel.HIGH
            and context.fedramp_authorization_level != FedRAMPImpactLevel.HIGH
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "FedRAMP HIGH authorization required — system authorized at "
                    f"{context.fedramp_authorization_level.value} only"
                ),
                regulation_citation="FedRAMP Program + FIPS 199",
            )

        # MODERATE impact documents require at least a MODERATE-authorized system.
        if (
            document.fedramp_required_level == FedRAMPImpactLevel.MODERATE
            and context.fedramp_authorization_level == FedRAMPImpactLevel.LOW
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason="FedRAMP MODERATE authorization required",
                regulation_citation="FedRAMP Program + FIPS 199",
            )

        # Access must originate from a FedRAMP-authorized system for any
        # FedRAMP-controlled document.
        if (
            not context.is_on_authorized_system
            and document.fedramp_required_level != FedRAMPImpactLevel.NOT_FEDRAMP
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "Access must originate from FedRAMP-authorized system "
                    "(FedRAMP Program)"
                ),
                regulation_citation="FedRAMP Program",
            )

        # All federal information systems must have a current ATO.
        if not context.has_ato:
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "System lacks Authority To Operate "
                    "— FISMA 44 USC §3554(a)(1)(A)"
                ),
                regulation_citation="FISMA 44 USC §3554(a)(1)(A)",
            )

        return GovernmentFilterResult(
            layer=self.LAYER_NAME,
            decision=GovernmentDecision.PERMITTED,
            reason=(
                f"FedRAMP authorization level {context.fedramp_authorization_level.value} "
                "— compliant"
            ),
            regulation_citation=(
                "FedRAMP Program + FISMA 44 USC §3541"
            ),
        )


# ---------------------------------------------------------------------------
# Layer 2: FISMASecurityControlFilter
# ---------------------------------------------------------------------------

class FISMASecurityControlFilter:
    """
    Enforces FISMA and NIST SP 800-53 Rev. 5 access control requirements for
    government information systems.

    NIST SP 800-53 Rev. 5 provides the security and privacy control catalog
    from which agencies select control baselines per their FIPS 199 system
    categorization.  This layer enforces the access control family (AC) and
    personnel security (PS) controls most directly relevant to RAG retrieval:

      AC-3 (Access Enforcement): The system enforces approved authorizations
      for logical access to information and system resources in accordance with
      applicable access control policies.  PUBLIC users may only access
      documents that have been explicitly approved for public release.

      AC-3(7) (Access Enforcement — Role-Based Access Control): Enforces
      access to system resources based on the roles assigned to the requesting
      user.  CUI requires an established need-to-know; this determination must
      be recorded and verified.

      AC-4 (Information Flow Enforcement): Controls information flows between
      interconnected systems and domains.  HIGH categorized information may not
      flow into a system operating at a lower categorization level.

      PS-3 (Personnel Screening): Establishes requirements for background
      investigations appropriate to the access level.  Contractor personnel
      must complete OPM background investigations prior to accessing federal
      information systems.
    """

    LAYER_NAME = "FISMA_NIST_SP_800_53"

    def evaluate(
        self, context: GovernmentRAGContext, document: GovernmentDocument
    ) -> GovernmentFilterResult:
        """
        Evaluate whether the requesting context satisfies FISMA / NIST SP 800-53
        access control requirements for the document.

        Returns a GovernmentFilterResult with PERMITTED or DENIED together with
        the operative NIST SP 800-53 control citation and finding.
        """
        # HIGH impact documents may not flow to lower-categorized systems
        # (NIST SP 800-53 AC-4: information flow enforcement).
        if (
            document.fedramp_required_level == FedRAMPImpactLevel.HIGH
            and context.fisma_system_category != "HIGH"
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "NIST SP 800-53 AC-4: Information flow enforcement — HIGH impact "
                    "document requires HIGH categorized system"
                ),
                regulation_citation="NIST SP 800-53 Rev. 5 AC-4",
            )

        # Contractors and cleared contractors must complete a background
        # investigation before accessing federal systems (NIST SP 800-53 PS-3).
        if (
            not context.has_background_investigation
            and context.user_role in {
                GovernmentRole.CONTRACTOR,
                GovernmentRole.CLEARED_CONTRACTOR,
            }
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "NIST SP 800-53 PS-3: Personnel screening — background investigation "
                    "required for contractor access"
                ),
                regulation_citation="NIST SP 800-53 Rev. 5 PS-3",
            )

        # Public users may only access documents approved for public release
        # (NIST SP 800-53 AC-3: access enforcement).
        if (
            context.user_role == GovernmentRole.PUBLIC
            and not document.is_public_release_approved
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "NIST SP 800-53 AC-3: Access enforcement — document not approved "
                    "for public release"
                ),
                regulation_citation="NIST SP 800-53 Rev. 5 AC-3",
            )

        # CUI documents require an established need-to-know
        # (NIST SP 800-53 AC-3(7): role-based access enforcement).
        if (
            not context.is_need_to_know
            and document.cui_category != CUICategory.UNCONTROLLED_PUBLIC
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "NIST SP 800-53 AC-3(7): Access enforcement — need-to-know "
                    "not established for CUI"
                ),
                regulation_citation="NIST SP 800-53 Rev. 5 AC-3(7)",
            )

        return GovernmentFilterResult(
            layer=self.LAYER_NAME,
            decision=GovernmentDecision.PERMITTED,
            reason="NIST SP 800-53 Rev. 5 AC-3/AC-4/PS-3 — compliant",
            regulation_citation="NIST SP 800-53 Rev. 5 AC-3/AC-4/PS-3",
        )


# ---------------------------------------------------------------------------
# Layer 3: CUIMarkingFilter
# ---------------------------------------------------------------------------

class CUIMarkingFilter:
    """
    Enforces CUI category-based access controls under 32 CFR Part 2002 and
    the Privacy Act, export control laws (EAR/ITAR), and FAR contractor
    agreement requirements.

    Executive Order 13556 established the CUI program; 32 CFR Part 2002
    is the implementing regulation administered by NARA.  CUI categories
    relevant to government RAG systems:

      FOUO (For Official Use Only) — 32 CFR §2002.14: Documents marked FOUO
      are restricted to individuals with a lawful government purpose and
      official need-to-know.  Public access is prohibited.

      Law Enforcement Sensitive (LES) — 32 CFR Part 2002 + DOJ/FBI policy:
      LES CUI is restricted to sworn law enforcement officers and designated
      LE agency staff.  Inspector General and Congressional oversight personnel
      may access LES documents under their respective statutory authorities.

      Privacy Act Records — 5 USC §552a: Restricts disclosure of agency records
      about individuals.  All personnel accessing Privacy Act records must
      complete annual Privacy Act training per OMB Circular A-130.

      Export Controlled — EAR 15 CFR Parts 730-774 / ITAR 22 CFR Parts 120-130:
      Technical data, software, and technology subject to export control may
      not be disclosed to foreign persons (non-US persons) without an export
      license or applicable exception, including on government information
      systems.

      FAR 52.204-21: Contractors accessing CUI documents (other than
      UNCONTROLLED_PUBLIC) must have an active FAR/DFARS contractor agreement
      in place covering the handling of federal contract information and CUI.
    """

    LAYER_NAME = "CUI_32_CFR_PART_2002"

    def evaluate(
        self, context: GovernmentRAGContext, document: GovernmentDocument
    ) -> GovernmentFilterResult:
        """
        Evaluate whether the requesting context satisfies CUI category
        handling requirements for the document.

        Returns a GovernmentFilterResult with PERMITTED or DENIED together with
        the operative CUI regulation or statutory citation and finding.
        """
        # Export-controlled CUI requires US person status (EAR/ITAR controls
        # the disclosure of controlled technology to foreign persons).
        if document.is_export_controlled and not context.is_us_person:
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "32 CFR Part 2002 + EAR/ITAR: Export-controlled CUI requires "
                    "US person status"
                ),
                regulation_citation="32 CFR Part 2002 + EAR 15 CFR Parts 730-774 / ITAR 22 CFR Parts 120-130",
            )

        # LES CUI is restricted to LE personnel; IG oversight personnel are
        # also permitted under the Inspector General Act 5 USC App. §6.
        if (
            document.cui_category == CUICategory.LAW_ENFORCEMENT_SENSITIVE
            and not context.is_law_enforcement
            and not context.is_ig_oversight
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "32 CFR Part 2002: Law Enforcement Sensitive CUI restricted "
                    "to LE personnel and IG oversight"
                ),
                regulation_citation="32 CFR Part 2002",
            )

        # Privacy Act records require annual Privacy Act training before access
        # (OMB Circular A-130 and Privacy Act 5 USC §552a).
        if document.contains_pii and not context.has_privacy_act_training:
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "Privacy Act 5 USC §552a: Annual Privacy Act training required "
                    "before accessing Privacy Act records"
                ),
                regulation_citation="Privacy Act 5 USC §552a + OMB Circular A-130",
            )

        # FOUO CUI is for official use only; public access is prohibited.
        if (
            document.cui_category == CUICategory.FOUO
            and context.user_role == GovernmentRole.PUBLIC
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "32 CFR Part 2002: FOUO (For Official Use Only) "
                    "— restricted from public access"
                ),
                regulation_citation="32 CFR Part 2002 §2002.14",
            )

        # Contractors accessing CUI must have an active FAR/DFARS contractor
        # agreement (FAR 52.204-21).
        if (
            context.user_role == GovernmentRole.CONTRACTOR
            and not context.contractor_agreement_active
            and document.cui_category != CUICategory.UNCONTROLLED_PUBLIC
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "32 CFR Part 2002: CUI access requires active contractor agreement "
                    "(FAR 52.204-21)"
                ),
                regulation_citation="32 CFR Part 2002 + FAR 52.204-21",
            )

        return GovernmentFilterResult(
            layer=self.LAYER_NAME,
            decision=GovernmentDecision.PERMITTED,
            reason="32 CFR Part 2002 CUI handling — compliant",
            regulation_citation="32 CFR Part 2002",
        )


# ---------------------------------------------------------------------------
# Layer 4: GovernmentAuditFilter
# ---------------------------------------------------------------------------

class GovernmentAuditFilter:
    """
    Enforces NIST SP 800-53 AU-9 audit information protections and recognizes
    the independent oversight authorities of the Inspector General and Congress.

    NIST SP 800-53 AU-9 (Protection of Audit Information): Requires the
    information system to protect audit information and audit tools from
    unauthorized access, modification, and deletion.  For HIGH impact
    systems, audit records contain data at the highest sensitivity level
    and require access controls commensurate with the underlying data.
    Access to HIGH impact audit records requires a security clearance.

    Inspector General Act of 1978, 5 USC Appendix §6 (Authority of Inspector
    General): Grants each Inspector General the independent authority to access
    all agency records, reports, audits, reviews, documents, papers,
    recommendations, or other materials, including those held in electronic
    systems, without agency head approval or concurrence.  This statutory
    override supersedes document-level access denials for IG oversight.

    Constitutional oversight authority + 5 USC §552: Congress exercises broad
    oversight authority over executive branch agencies.  Congressional oversight
    requests, particularly those backed by subpoena authority, supersede agency
    access controls.  This override is recognized in parallel with the IG
    override and is applied before AU-9 controls are evaluated.
    """

    LAYER_NAME = "GOVERNMENT_AUDIT_AU9"

    def evaluate(
        self, context: GovernmentRAGContext, document: GovernmentDocument
    ) -> GovernmentFilterResult:
        """
        Evaluate whether the requesting context satisfies AU-9 audit protection
        requirements or qualifies for an oversight authority override.

        Inspector General and Congressional oversight overrides are evaluated
        first; if either applies, evaluation stops with PERMITTED.

        Returns a GovernmentFilterResult with PERMITTED or DENIED together with
        the operative NIST SP 800-53 or statutory citation and finding.
        """
        # IG override — Inspector General Act 5 USC App. §6 grants independent
        # access authority that supersedes agency document access controls.
        if context.is_ig_oversight:
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.PERMITTED,
                reason=(
                    "Inspector General Act 5 USC App. §6: IG has independent access "
                    "authority — audit access granted"
                ),
                regulation_citation="Inspector General Act 5 USC App. §6",
            )

        # Congressional override — constitutional oversight authority and 5 USC §552
        # supersede agency access controls for oversight access.
        if context.is_congressional_oversight:
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.PERMITTED,
                reason=(
                    "Constitutional oversight authority + 5 USC §552: Congressional "
                    "oversight access — audit access granted"
                ),
                regulation_citation="Constitutional oversight authority + 5 USC §552",
            )

        # HIGH impact systems: AU-9 requires clearance to access HIGH impact
        # audit records, which describe data at the highest sensitivity level.
        if (
            document.fedramp_required_level == FedRAMPImpactLevel.HIGH
            and not context.has_security_clearance
        ):
            return GovernmentFilterResult(
                layer=self.LAYER_NAME,
                decision=GovernmentDecision.DENIED,
                reason=(
                    "NIST SP 800-53 AU-9: Audit log protection — HIGH impact audit "
                    "records require security clearance"
                ),
                regulation_citation="NIST SP 800-53 Rev. 5 AU-9",
            )

        return GovernmentFilterResult(
            layer=self.LAYER_NAME,
            decision=GovernmentDecision.PERMITTED,
            reason="NIST SP 800-53 AU-9 audit protection — compliant",
            regulation_citation="NIST SP 800-53 Rev. 5 AU-9",
        )


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class GovernmentAuditRecord:
    """
    Captures the full decision trail for a Government RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - FISMA 44 USC §3554: Continuous monitoring and audit reporting.
      - NIST SP 800-53 AU-9: Protection of audit information.
      - 32 CFR Part 2002 §2002.14: CUI access logging requirements.
      - Privacy Act 5 USC §552a: System of records disclosure accounting.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping purposes.
    """

    user_id: str
    agency_id: str
    user_role: GovernmentRole
    documents_evaluated: int
    documents_permitted: int
    documents_denied: int
    filter_results: list          # Per-document list of per-layer result dicts
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": "GOVERNMENT_RAG_RETRIEVAL",
            "user_id": self.user_id,
            "agency_id": self.agency_id,
            "user_role": self.user_role.value,
            "documents_evaluated": self.documents_evaluated,
            "documents_permitted": self.documents_permitted,
            "documents_denied": self.documents_denied,
            "filter_results": self.filter_results,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class GovernmentRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for government and
    public sector systems.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  Only documents that pass all four
    layers are considered permitted.

    Layers in order:
      1. FedRAMPAuthorizationFilter  — FedRAMP impact level + ATO validation
      2. FISMASecurityControlFilter  — NIST SP 800-53 AC/PS control enforcement
      3. CUIMarkingFilter            — 32 CFR Part 2002 CUI category controls
      4. GovernmentAuditFilter       — AU-9 audit protection + oversight overrides

    The IG and Congressional oversight overrides in Layer 4 grant access
    regardless of Layer 1–3 decisions; they are evaluated last so that the
    audit trail of prior-layer denials is fully captured before the override
    is applied.

    Audit records are generated for every document regardless of outcome,
    providing a complete access trail for FISMA continuous monitoring and
    CUI dissemination accounting obligations.
    """

    def __init__(self) -> None:
        self._layers = [
            FedRAMPAuthorizationFilter(),
            FISMASecurityControlFilter(),
            CUIMarkingFilter(),
            GovernmentAuditFilter(),
        ]

    def retrieve(
        self,
        context: GovernmentRAGContext,
        documents: list[GovernmentDocument],
    ) -> list[tuple[GovernmentDocument, list[GovernmentFilterResult]]]:
        """
        Return a list of (document, filter_results) tuples for all documents
        that pass all four filter layers.

        Documents that are denied on any layer are excluded from the result.
        Each returned tuple contains the document and the list of per-layer
        GovernmentFilterResult objects representing the evaluation trail.
        """
        permitted = []
        for doc in documents:
            layer_results: list[GovernmentFilterResult] = []
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
        context: GovernmentRAGContext,
        documents: list[GovernmentDocument],
    ) -> GovernmentAuditRecord:
        """
        Evaluate all documents and return a GovernmentAuditRecord summarising
        the retrieval event.

        All documents are evaluated regardless of outcome; the audit record
        captures per-layer decisions for every document to support FISMA
        continuous monitoring, CUI dissemination accounting, and Privacy Act
        disclosure tracking.
        """
        documents_permitted = 0
        documents_denied = 0
        all_filter_results: list[dict] = []

        for doc in documents:
            layer_results: list[dict] = []
            allow = True
            final_decision = GovernmentDecision.PERMITTED

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
                    final_decision = GovernmentDecision.DENIED
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

        return GovernmentAuditRecord(
            user_id=context.user_id,
            agency_id=context.agency_id,
            user_role=context.user_role,
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
    print("Government and Public Sector RAG Pipeline — Smoke Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Shared documents used across scenarios
    # ------------------------------------------------------------------

    high_fedramp_doc = GovernmentDocument(
        document_id="doc-001-high-fedramp-cui-fouo",
        fedramp_required_level=FedRAMPImpactLevel.HIGH,
        cui_category=CUICategory.FOUO,
        contains_pii=False,
        is_law_enforcement_sensitive=False,
        is_export_controlled=False,
        is_classified=False,
        is_public_release_approved=False,
    )

    les_doc = GovernmentDocument(
        document_id="doc-002-law-enforcement-sensitive",
        fedramp_required_level=FedRAMPImpactLevel.MODERATE,
        cui_category=CUICategory.LAW_ENFORCEMENT_SENSITIVE,
        contains_pii=False,
        is_law_enforcement_sensitive=True,
        is_export_controlled=False,
        is_classified=False,
        is_public_release_approved=False,
    )

    pii_doc = GovernmentDocument(
        document_id="doc-003-privacy-act-records",
        fedramp_required_level=FedRAMPImpactLevel.MODERATE,
        cui_category=CUICategory.PRIVACY_ACT,
        contains_pii=True,
        is_law_enforcement_sensitive=False,
        is_export_controlled=False,
        is_classified=False,
        is_public_release_approved=False,
    )

    public_doc = GovernmentDocument(
        document_id="doc-004-foia-public-release",
        fedramp_required_level=FedRAMPImpactLevel.NOT_FEDRAMP,
        cui_category=CUICategory.UNCONTROLLED_PUBLIC,
        contains_pii=False,
        is_law_enforcement_sensitive=False,
        is_export_controlled=False,
        is_classified=False,
        is_public_release_approved=True,
    )

    export_controlled_doc = GovernmentDocument(
        document_id="doc-005-itar-export-controlled",
        fedramp_required_level=FedRAMPImpactLevel.HIGH,
        cui_category=CUICategory.EXPORT_CONTROLLED,
        contains_pii=False,
        is_law_enforcement_sensitive=False,
        is_export_controlled=True,
        is_classified=False,
        is_public_release_approved=False,
    )

    classified_doc = GovernmentDocument(
        document_id="doc-006-classified-ts",
        fedramp_required_level=FedRAMPImpactLevel.HIGH,
        cui_category=CUICategory.FOUO,
        contains_pii=False,
        is_law_enforcement_sensitive=False,
        is_export_controlled=False,
        is_classified=True,
        is_public_release_approved=False,
    )

    all_documents = [
        high_fedramp_doc,
        les_doc,
        pii_doc,
        public_doc,
        export_controlled_doc,
        classified_doc,
    ]

    pipeline = GovernmentRAGPipeline()

    # ------------------------------------------------------------------
    # Scenario 1: Cleared federal employee with HIGH FedRAMP authorization
    # Expected: high_fedramp_doc permitted; pii_doc permitted; les_doc denied
    #           (not LE); export_controlled_doc denied (not HIGH cleared + ATO,
    #           actually HIGH + no security clearance in AU-9); public_doc
    #           permitted; classified_doc denied (Layer 1 gate).
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: Cleared Federal Employee with HIGH Authorization ---")

    cleared_federal = GovernmentRAGContext(
        user_id="user-federal-employee-patel",
        user_role=GovernmentRole.FEDERAL_EMPLOYEE,
        agency_id="DOD",
        fedramp_authorization_level=FedRAMPImpactLevel.HIGH,
        has_background_investigation=True,
        has_security_clearance=True,
        is_need_to_know=True,
        is_us_person=True,
        has_privacy_act_training=True,
        is_law_enforcement=False,
        is_on_authorized_system=True,
        contractor_agreement_active=False,
        fisma_system_category="HIGH",
        has_ato=True,
        is_ig_oversight=False,
        is_congressional_oversight=False,
    )

    permitted, audit_records = [], []
    for doc in all_documents:
        results = pipeline.retrieve(cleared_federal, [doc])
        if results:
            permitted.append(doc.document_id)
    print(f"  Permitted: {permitted}")
    print(f"  Denied : {[d.document_id for d in all_documents if d.document_id not in permitted]}")

    # Full audit record
    audit = pipeline.retrieve_with_audit(cleared_federal, all_documents)
    print(f"  Summary: {audit.documents_permitted} permitted, {audit.documents_denied} denied")
    print(f"  Audit log keys: {list(audit.to_audit_log().keys())}")

    # ------------------------------------------------------------------
    # Scenario 2: Public user — only public release-approved doc permitted
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Public User ---")

    public_user = GovernmentRAGContext(
        user_id="user-public-citizen",
        user_role=GovernmentRole.PUBLIC,
        agency_id="NONE",
        fedramp_authorization_level=FedRAMPImpactLevel.NOT_FEDRAMP,
        has_background_investigation=False,
        has_security_clearance=False,
        is_need_to_know=False,
        is_us_person=True,
        has_privacy_act_training=False,
        is_law_enforcement=False,
        is_on_authorized_system=False,
        contractor_agreement_active=False,
        fisma_system_category="LOW",
        has_ato=False,
        is_ig_oversight=False,
        is_congressional_oversight=False,
    )

    public_audit = pipeline.retrieve_with_audit(public_user, all_documents)
    print(f"  Summary: {public_audit.documents_permitted} permitted, {public_audit.documents_denied} denied")
    print(f"  Expected 1 permitted (public_doc), got {public_audit.documents_permitted}")
    for r in public_audit.filter_results:
        print(f"    {r['document_id']}: {r['final_decision']}")

    # ------------------------------------------------------------------
    # Scenario 3: IG Auditor — IG override grants access past all denials
    # (except classified docs which are blocked in Layer 1 before IG override)
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: IG Auditor ---")

    ig_auditor = GovernmentRAGContext(
        user_id="user-ig-inspector-lee",
        user_role=GovernmentRole.IG_AUDITOR,
        agency_id="DOJ-OIG",
        fedramp_authorization_level=FedRAMPImpactLevel.HIGH,
        has_background_investigation=True,
        has_security_clearance=True,
        is_need_to_know=True,
        is_us_person=True,
        has_privacy_act_training=True,
        is_law_enforcement=False,
        is_on_authorized_system=True,
        contractor_agreement_active=False,
        fisma_system_category="HIGH",
        has_ato=True,
        is_ig_oversight=True,
        is_congressional_oversight=False,
    )

    ig_audit = pipeline.retrieve_with_audit(ig_auditor, all_documents)
    print(f"  Summary: {ig_audit.documents_permitted} permitted, {ig_audit.documents_denied} denied")
    for r in ig_audit.filter_results:
        print(f"    {r['document_id']}: {r['final_decision']}")

    # ------------------------------------------------------------------
    # Scenario 4: Contractor without active agreement — CUI denied
    # ------------------------------------------------------------------
    print("\n--- Scenario 4: Contractor without active FAR agreement ---")

    contractor_no_agreement = GovernmentRAGContext(
        user_id="user-contractor-james",
        user_role=GovernmentRole.CONTRACTOR,
        agency_id="HHS",
        fedramp_authorization_level=FedRAMPImpactLevel.MODERATE,
        has_background_investigation=True,
        has_security_clearance=False,
        is_need_to_know=True,
        is_us_person=True,
        has_privacy_act_training=True,
        is_law_enforcement=False,
        is_on_authorized_system=True,
        contractor_agreement_active=False,  # No active agreement
        fisma_system_category="MODERATE",
        has_ato=True,
        is_ig_oversight=False,
        is_congressional_oversight=False,
    )

    contractor_audit = pipeline.retrieve_with_audit(contractor_no_agreement, [pii_doc, public_doc])
    print(f"  Summary: {contractor_audit.documents_permitted} permitted, {contractor_audit.documents_denied} denied")
    for r in contractor_audit.filter_results:
        print(f"    {r['document_id']}: {r['final_decision']}")

    # ------------------------------------------------------------------
    # Scenario 5: Non-US person attempting export-controlled document
    # ------------------------------------------------------------------
    print("\n--- Scenario 5: Non-US person and export-controlled document ---")

    non_us_employee = GovernmentRAGContext(
        user_id="user-contractor-foreign-national",
        user_role=GovernmentRole.FEDERAL_EMPLOYEE,
        agency_id="NSF",
        fedramp_authorization_level=FedRAMPImpactLevel.HIGH,
        has_background_investigation=True,
        has_security_clearance=True,
        is_need_to_know=True,
        is_us_person=False,  # Foreign national
        has_privacy_act_training=True,
        is_law_enforcement=False,
        is_on_authorized_system=True,
        contractor_agreement_active=False,
        fisma_system_category="HIGH",
        has_ato=True,
        is_ig_oversight=False,
        is_congressional_oversight=False,
    )

    export_audit = pipeline.retrieve_with_audit(non_us_employee, [export_controlled_doc])
    print(f"  Summary: {export_audit.documents_permitted} permitted, {export_audit.documents_denied} denied")
    for r in export_audit.filter_results:
        for lr in r["layer_results"]:
            print(f"    {lr['layer']}: {lr['decision']} — {lr['reason']}")

    print("\n" + "=" * 70)
    print("Smoke test complete.")
    print("=" * 70)
