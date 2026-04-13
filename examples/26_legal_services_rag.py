"""
Legal Services RAG Pipeline — Four-Layer Defense-in-Depth

This module implements a compliance-aware RAG retrieval pipeline for legal services
platforms. Four independent filter layers run sequentially; a document must pass all
four to be returned to the caller.

Regulatory frameworks enforced:

  Layer 1 — Attorney-Client Privilege (ABA Model Rule 1.6)
      Protects confidential communications between attorney and client. Documents
      covered by privilege may only be accessed by parties with a legitimate need
      on the specific matter, or where privilege has been expressly waived.

  Layer 2 — Conflict of Interest (ABA Model Rules 1.7 / 1.9)
      Prevents access to matter documents where a current or former conflict of
      interest exists and has not been cleared. Rule 1.7 governs current-client
      conflicts; Rule 1.9 governs duties to former clients on substantially related
      matters requiring written informed consent.

  Layer 3 — Work Product Doctrine (FRCP Rule 26(b)(3))
      Protects materials prepared in anticipation of litigation. Ordinary work
      product may be overcome by a showing of substantial need; opinion work
      product (mental impressions, conclusions, legal theories) is absolutely
      protected against opposing counsel.

  Layer 4 — State Bar Ethics / UPL (ABA Model Rules + State Bar Rules)
      Ensures that access by attorneys is limited to jurisdictions in which they
      are admitted (or have obtained pro hac vice admission), that paralegals
      operate only under a supervising attorney, and that administrative staff
      access is limited to formally designated audit purposes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class LegalRole(Enum):
    ATTORNEY = "attorney"
    PARALEGAL = "paralegal"
    CLIENT = "client"
    OPPOSING_COUNSEL = "opposing_counsel"
    EXPERT_WITNESS = "expert_witness"
    ADMIN = "admin"


class WorkProductType(Enum):
    ORDINARY = "ordinary"          # Fact work product
    OPINION = "opinion"            # Mental impressions, conclusions, legal theories
    NOT_WORK_PRODUCT = "not_work_product"


class LegalDecision(Enum):
    PERMITTED = "permitted"
    DENIED = "denied"
    REDACTED = "redacted"


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LegalServicesContext:
    """Carries all per-request attributes needed by the four filter layers."""

    user_id: str
    user_role: LegalRole
    matter_id: str                     # Which matter/case this user is on
    client_id: str                     # Which client this user represents
    bar_number: str                    # Attorney bar admission number (empty if not attorney)
    bar_jurisdiction: str              # e.g. "WA", "CA" (empty if not attorney)
    is_admitted_in_matter_jurisdiction: bool  # Bar admission matches matter jurisdiction
    is_on_matter_team: bool            # User is assigned to this specific matter
    has_conflict_cleared: bool         # Conflicts check has been run and cleared
    adverse_to_former_client: bool     # Rule 1.9 — adverse on same/substantially related matter
    former_client_consented: bool      # Former client gave informed written consent
    privilege_waiver_documented: bool  # Client has expressly waived privilege for this document
    substantial_need_shown: bool       # Substantial need shown to overcome ordinary work product
    is_audit_access: bool              # Access is for compliance/audit purposes only


@dataclass(frozen=True)
class LegalDocument:
    """Immutable document descriptor carrying attributes needed for compliance evaluation."""

    document_id: str
    is_privileged: bool              # Covered by attorney-client privilege
    work_product_type: WorkProductType
    owning_client_id: str            # Which client's matter this belongs to
    matter_jurisdiction: str         # Jurisdiction of the matter ("WA", "CA", etc.)
    is_public: bool                  # Publicly filed court document — not privileged


# ---------------------------------------------------------------------------
# Result and Audit dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LegalFilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: LegalDecision = LegalDecision.PERMITTED
    reason: str = ""
    conditions: list = field(default_factory=list)

    @property
    def is_denied(self) -> bool:
        return self.decision == LegalDecision.DENIED


@dataclass
class LegalAuditRecord:
    """Immutable audit record capturing the full decision trail for one retrieval."""

    user_id: str
    matter_id: str
    client_id: str
    document_id: str
    decision: LegalDecision
    layer_results: list          # List of per-layer result dicts
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": "LEGAL_RAG_RETRIEVAL",
            "user_id": self.user_id,
            "matter_id": self.matter_id,
            "client_id": self.client_id,
            "document_id": self.document_id,
            "decision": self.decision.value,
            "layer_results": self.layer_results,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Layer 1: Attorney-Client Privilege (ABA Model Rule 1.6)
# ---------------------------------------------------------------------------

class AttorneyClientPrivilegeFilter:
    """
    Enforces attorney-client privilege under ABA Model Rule 1.6.

    Rule 1.6 imposes a duty of confidentiality on attorneys with respect to
    information relating to the representation of a client. This layer gates
    access to privileged documents based on the requesting party's role and
    their relationship to the specific matter.

    Public documents (court filings) carry no privilege regardless of other
    attributes and are always permitted at this layer.
    """

    LAYER_NAME = "AttorneyClientPrivilege_ABA_Rule_1.6"

    def evaluate(self, context: LegalServicesContext, document: LegalDocument) -> LegalFilterResult:
        """
        Evaluate whether the context has privilege access to the document.

        Returns a LegalFilterResult with PERMITTED, DENIED, or REDACTED,
        together with the operative ABA Rule 1.6 finding or condition.
        """
        # Public filings have no privilege — always permit at this layer.
        if document.is_public:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Publicly filed court document — no privilege attaches",
            )

        # Non-privileged document — pass through.
        if not document.is_privileged:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Document is not privileged — no Rule 1.6 restriction",
            )

        # From here the document IS privileged.  Evaluate each role.

        # Express privilege waiver by client — permit regardless of role.
        if context.privilege_waiver_documented:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Privilege waiver on file",
                conditions=[
                    "Privilege waived — log access per Rule 1.6 waiver documentation"
                ],
            )

        role = context.user_role

        if role == LegalRole.CLIENT:
            if context.is_on_matter_team:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.PERMITTED,
                    reason="Client accessing own privileged matter",
                )
            # Client not on matter — deny; privilege protects the relationship,
            # and a client unrelated to this matter should not access it.
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason="Rule 1.6: Client not assigned to this matter — access denied",
            )

        if role == LegalRole.ATTORNEY:
            if context.is_on_matter_team:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.PERMITTED,
                    reason="Attorney on matter team",
                    conditions=[
                        "Attorney access — ABA Rule 1.6 confidentiality applies"
                    ],
                )
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason="Rule 1.6: Attorney not assigned to this matter — access denied",
            )

        if role == LegalRole.PARALEGAL:
            if context.is_on_matter_team:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.PERMITTED,
                    reason="Paralegal on matter team under supervising attorney",
                    conditions=[
                        "Paralegal access — supervising attorney Rule 1.6 obligation applies"
                    ],
                )
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason="Rule 1.6: Paralegal not assigned to this matter — access denied",
            )

        if role == LegalRole.ADMIN:
            if context.is_audit_access:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.PERMITTED,
                    reason="Administrative audit access",
                    conditions=[
                        "Audit access only — Rule 1.6 confidentiality maintained"
                    ],
                )
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason="Rule 1.6: Administrative access requires formal audit designation",
            )

        if role == LegalRole.OPPOSING_COUNSEL:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason="Rule 1.6: Privileged document not disclosable to opposing counsel",
            )

        if role == LegalRole.EXPERT_WITNESS:
            if context.is_on_matter_team:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.PERMITTED,
                    reason="Designated expert witness on matter team",
                    conditions=[
                        "Expert witness designated on matter team — Rule 1.6 confidentiality maintained"
                    ],
                )
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason=(
                    "Rule 1.6: Expert witness must be designated on matter team "
                    "before privilege access"
                ),
            )

        # Unrecognized role — deny by default.
        return LegalFilterResult(
            layer=self.LAYER_NAME,
            decision=LegalDecision.DENIED,
            reason="Rule 1.6: Confidentiality obligation — access denied",
        )


# ---------------------------------------------------------------------------
# Layer 2: Conflict of Interest (ABA Model Rules 1.7 / 1.9)
# ---------------------------------------------------------------------------

class ConflictOfInterestFilter:
    """
    Enforces conflict of interest rules under ABA Model Rules 1.7 and 1.9.

    Rule 1.7 addresses current-client conflicts; a matter cannot proceed unless
    a proper conflict screen has been completed and cleared.  Rule 1.9 addresses
    duties to former clients: an attorney may not act adversely to a former
    client in the same or substantially related matter without written informed
    consent from the former client.

    Public documents are exempted because conflict concerns attach to the
    representation, not to publicly available information.
    """

    LAYER_NAME = "ConflictOfInterest_ABA_Rules_1.7_1.9"

    def evaluate(self, context: LegalServicesContext, document: LegalDocument) -> LegalFilterResult:
        """
        Evaluate whether a conflict of interest bars document access.

        The evaluation sequence is:
          1. Public document — permit.
          2. No conflict + conflict cleared — permit.
          3. Conflict check not completed — deny (Rule 1.7).
          4. Adverse to former client without consent — deny (Rule 1.9).
          5. Adverse to former client with consent — permit (Rule 1.9 waiver).
        """
        # Public filings — no conflict concern at the document level.
        if document.is_public:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Public document — conflict rules do not restrict access",
            )

        # Clean bill of health: cleared and no former-client adversity.
        if context.has_conflict_cleared and not context.adverse_to_former_client:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Conflict check cleared with no former-client adversity",
                conditions=[
                    "Conflict check cleared per Rules 1.7/1.9"
                ],
            )

        # Conflict check was never run.
        if not context.has_conflict_cleared:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason=(
                    f"Rule 1.7: Conflict of interest check not completed "
                    f"for matter {document.owning_client_id}"
                ),
            )

        # From here conflict check HAS been cleared, but adversity to former
        # client is flagged (Rule 1.9 issue).

        if context.adverse_to_former_client and not context.former_client_consented:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason=(
                    "Rule 1.9: Adverse to former client on substantially related "
                    "matter — written consent required"
                ),
            )

        if context.adverse_to_former_client and context.former_client_consented:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Rule 1.9 waiver: Former client gave informed written consent",
                conditions=[
                    "Rule 1.9 waiver documented — former client written consent obtained"
                ],
            )

        # Fallback — should not be reached given the above branches, but deny
        # on any unresolved conflict state to err on the side of protection.
        return LegalFilterResult(
            layer=self.LAYER_NAME,
            decision=LegalDecision.DENIED,
            reason="Rule 1.7/1.9: Unresolved conflict state — access denied",
        )


# ---------------------------------------------------------------------------
# Layer 3: Work Product Doctrine (FRCP Rule 26(b)(3))
# ---------------------------------------------------------------------------

class WorkProductDoctrineFilter:
    """
    Enforces the work product doctrine under FRCP Rule 26(b)(3).

    Rule 26(b)(3)(A) protects ordinary (fact) work product from discovery
    unless the requesting party shows substantial need and inability to obtain
    equivalent material without undue hardship.

    Rule 26(b)(3)(B) provides absolute protection for opinion work product —
    an attorney's mental impressions, conclusions, opinions, and legal theories —
    which cannot be overcome by any showing of need.

    Public documents and documents that are not work product pass through
    without restriction at this layer.
    """

    LAYER_NAME = "WorkProductDoctrine_FRCP_Rule_26b3"

    def evaluate(self, context: LegalServicesContext, document: LegalDocument) -> LegalFilterResult:
        """
        Evaluate whether the work product doctrine bars or conditions access.

        Opinion work product is absolutely protected against opposing counsel and
        all non-matter-attorney roles.  Ordinary work product may be obtained
        by opposing counsel on a showing of substantial need.
        """
        # Public filings — no work product concern.
        if document.is_public:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Public document — work product doctrine does not apply",
            )

        # Not work product at all — pass through.
        if document.work_product_type == WorkProductType.NOT_WORK_PRODUCT:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Document is not work product — Rule 26(b)(3) does not apply",
            )

        role = context.user_role

        # ----------------------------------------------------------------
        # Opinion work product — Rule 26(b)(3)(B) absolute protection.
        # ----------------------------------------------------------------
        if document.work_product_type == WorkProductType.OPINION:
            if role == LegalRole.ATTORNEY and context.is_on_matter_team:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.PERMITTED,
                    reason="Matter attorney accessing own opinion work product",
                    conditions=[
                        "Opinion work product — attorney eyes only per Rule 26(b)(3)(B)"
                    ],
                )

            if role == LegalRole.OPPOSING_COUNSEL:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.DENIED,
                    reason=(
                        "FRCP Rule 26(b)(3)(B): Opinion work product is absolutely "
                        "protected — mental impressions and legal theories not discoverable"
                    ),
                )

            # Any other role (paralegal not on team, client, admin, etc.)
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason="FRCP Rule 26(b)(3)(B): Opinion work product restricted to matter attorneys",
            )

        # ----------------------------------------------------------------
        # Ordinary (fact) work product — Rule 26(b)(3)(A).
        # ----------------------------------------------------------------
        if document.work_product_type == WorkProductType.ORDINARY:
            # Matter attorneys and paralegals — permit directly.
            if role in (LegalRole.ATTORNEY, LegalRole.PARALEGAL) and context.is_on_matter_team:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.PERMITTED,
                    reason="Matter team member accessing ordinary work product",
                )

            # Client accessing own matter's ordinary work product.
            if role == LegalRole.CLIENT:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.PERMITTED,
                    reason="Client accessing own matter ordinary work product",
                    conditions=[
                        "Client access to own matter work product"
                    ],
                )

            # Opposing counsel may obtain ordinary work product on substantial need.
            if role == LegalRole.OPPOSING_COUNSEL:
                if context.substantial_need_shown:
                    return LegalFilterResult(
                        layer=self.LAYER_NAME,
                        decision=LegalDecision.PERMITTED,
                        reason="Substantial need exception overcomes ordinary work product",
                        conditions=[
                            "FRCP Rule 26(b)(3)(A): Substantial need exception applied "
                            "— ordinary work product disclosed"
                        ],
                    )
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.DENIED,
                    reason=(
                        "FRCP Rule 26(b)(3)(A): Work product protection — "
                        "substantial need and undue hardship not shown"
                    ),
                )

            # All other roles — deny by default.
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.DENIED,
                reason="FRCP Rule 26(b)(3): Work product protection applies",
            )

        # Unreachable given the enum, but provide a safe fallback.
        return LegalFilterResult(
            layer=self.LAYER_NAME,
            decision=LegalDecision.DENIED,
            reason="FRCP Rule 26(b)(3): Unrecognized work product type — access denied",
        )


# ---------------------------------------------------------------------------
# Layer 4: State Bar Ethics / UPL (ABA Model Rules + State Bar Rules)
# ---------------------------------------------------------------------------

class StateBarEthicsFilter:
    """
    Enforces state bar admission requirements and unauthorized practice of law
    (UPL) restrictions under ABA Model Rules and state bar ethics rules.

    Key constraints:
      - Attorneys must be admitted in the jurisdiction of the matter (or hold
        pro hac vice admission); access without admission constitutes UPL.
      - Paralegals must be operating under a supervising attorney assigned to
        the matter; they may not independently access matter documents.
      - Administrative staff access is restricted to formally designated audit
        purposes to prevent inadvertent UPL exposure.
      - Clients and opposing counsel (already licensed) are not subject to UPL
        restrictions and pass through this layer.
      - Expert witnesses are not practicing law and do not require bar admission
        for document review.
    """

    LAYER_NAME = "StateBarEthics_UPL_Jurisdiction"

    def evaluate(self, context: LegalServicesContext, document: LegalDocument) -> LegalFilterResult:
        """
        Evaluate jurisdiction and UPL compliance for the requesting context.

        Returns PERMITTED for roles and circumstances that satisfy state bar
        requirements, or DENIED with the specific ethics rule finding.
        """
        # Public documents — no bar ethics restriction on access.
        if document.is_public:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Public document — state bar ethics rules do not restrict access",
            )

        role = context.user_role

        # Client accessing own matter — no UPL concern.
        if role == LegalRole.CLIENT:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Client accessing own matter — UPL not applicable",
            )

        # Opposing counsel is licensed — UPL not applicable.
        if role == LegalRole.OPPOSING_COUNSEL:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Opposing counsel is licensed — UPL rules do not apply",
            )

        # Expert witnesses review documents but do not practice law.
        if role == LegalRole.EXPERT_WITNESS:
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Expert witness document review — no bar admission required",
                conditions=[
                    "Expert witness — no bar admission required for document review"
                ],
            )

        # Attorney — must be admitted in the matter's jurisdiction.
        if role == LegalRole.ATTORNEY:
            if not context.is_admitted_in_matter_jurisdiction:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.DENIED,
                    reason=(
                        f"State Bar: Attorney not admitted in matter jurisdiction "
                        f"{document.matter_jurisdiction} — pro hac vice admission required"
                    ),
                )
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason=(
                    f"Attorney bar admission verified in matter jurisdiction "
                    f"{document.matter_jurisdiction}"
                ),
                conditions=[
                    f"Bar admission verified — {context.bar_jurisdiction} admission "
                    f"covers matter jurisdiction"
                ],
            )

        # Paralegal — must be on matter team under supervising attorney.
        if role == LegalRole.PARALEGAL:
            if not context.is_on_matter_team:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.DENIED,
                    reason=(
                        "State Bar: Paralegal must be assigned to matter team "
                        "under supervising attorney"
                    ),
                )
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Paralegal assigned to matter team under supervising attorney",
                conditions=[
                    "Paralegal operating under supervising attorney — ABA Model Guidelines "
                    "for Utilization of Paralegal Services apply"
                ],
            )

        # Admin — must have formal audit designation.
        if role == LegalRole.ADMIN:
            if not context.is_audit_access:
                return LegalFilterResult(
                    layer=self.LAYER_NAME,
                    decision=LegalDecision.DENIED,
                    reason=(
                        "State Bar: Administrative staff access requires "
                        "formal audit designation"
                    ),
                )
            return LegalFilterResult(
                layer=self.LAYER_NAME,
                decision=LegalDecision.PERMITTED,
                reason="Administrative audit access formally authorized",
                conditions=[
                    "Admin audit access authorized"
                ],
            )

        # Unrecognized role.
        return LegalFilterResult(
            layer=self.LAYER_NAME,
            decision=LegalDecision.DENIED,
            reason="State Bar: Access role not recognized for ethics compliance",
        )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class LegalServicesRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for legal services.

    Each layer independently evaluates a document against the requesting
    context.  The pipeline runs layers in sequence; the first DENIED result
    stops evaluation for that document.  Only documents that pass all four
    layers are returned.

    Audit records are generated for every document regardless of outcome,
    providing a complete access trail for compliance review.
    """

    def __init__(self) -> None:
        self._layers = [
            AttorneyClientPrivilegeFilter(),
            ConflictOfInterestFilter(),
            WorkProductDoctrineFilter(),
            StateBarEthicsFilter(),
        ]

    def retrieve(
        self,
        context: LegalServicesContext,
        documents: list[LegalDocument],
    ) -> list[LegalDocument]:
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
                if result.decision == LegalDecision.DENIED:
                    allow = False
                    break
            if allow:
                permitted.append(doc)
        return permitted

    def retrieve_with_audit(
        self,
        context: LegalServicesContext,
        documents: list[LegalDocument],
    ) -> tuple[list[LegalDocument], list[LegalAuditRecord]]:
        """
        Return permitted documents AND a full audit trail for every document.

        The audit trail captures the decision and per-layer results for each
        document regardless of whether it was ultimately permitted or denied.
        This supports compliance reporting and access reviews.
        """
        permitted: list[LegalDocument] = []
        audit_records: list[LegalAuditRecord] = []

        for doc in documents:
            layer_results: list[dict] = []
            allow = True
            final_decision = LegalDecision.PERMITTED

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
                if result.decision == LegalDecision.DENIED:
                    allow = False
                    final_decision = LegalDecision.DENIED
                    break

            if allow:
                permitted.append(doc)

            audit_records.append(
                LegalAuditRecord(
                    user_id=context.user_id,
                    matter_id=context.matter_id,
                    client_id=context.client_id,
                    document_id=doc.document_id,
                    decision=final_decision,
                    layer_results=layer_results,
                )
            )

        return permitted, audit_records


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Legal Services RAG Pipeline — Smoke Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Documents
    # ------------------------------------------------------------------
    privileged_doc = LegalDocument(
        document_id="doc-001-privileged-memo",
        is_privileged=True,
        work_product_type=WorkProductType.NOT_WORK_PRODUCT,
        owning_client_id="client-acme-corp",
        matter_jurisdiction="WA",
        is_public=False,
    )

    opinion_work_product_doc = LegalDocument(
        document_id="doc-002-strategy-memo",
        is_privileged=True,
        work_product_type=WorkProductType.OPINION,
        owning_client_id="client-acme-corp",
        matter_jurisdiction="WA",
        is_public=False,
    )

    public_court_filing = LegalDocument(
        document_id="doc-003-public-motion",
        is_privileged=False,
        work_product_type=WorkProductType.NOT_WORK_PRODUCT,
        owning_client_id="client-acme-corp",
        matter_jurisdiction="WA",
        is_public=True,
    )

    documents = [privileged_doc, opinion_work_product_doc, public_court_filing]

    pipeline = LegalServicesRAGPipeline()

    # ------------------------------------------------------------------
    # Scenario 1: Fully compliant matter attorney
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: Fully Compliant Matter Attorney ---")

    attorney_context = LegalServicesContext(
        user_id="atty-sarah-chen",
        user_role=LegalRole.ATTORNEY,
        matter_id="matter-2026-0042",
        client_id="client-acme-corp",
        bar_number="WA-45892",
        bar_jurisdiction="WA",
        is_admitted_in_matter_jurisdiction=True,
        is_on_matter_team=True,
        has_conflict_cleared=True,
        adverse_to_former_client=False,
        former_client_consented=False,
        privilege_waiver_documented=False,
        substantial_need_shown=False,
        is_audit_access=False,
    )

    permitted_docs, audit_records = pipeline.retrieve_with_audit(attorney_context, documents)

    print(f"  Context:  Attorney Sarah Chen (WA bar, on matter team, conflict cleared)")
    print(f"  Documents submitted: {len(documents)}")
    print(f"  Documents permitted: {len(permitted_docs)}")
    for record in audit_records:
        layers_evaluated = len(record.layer_results)
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id} "
            f"({layers_evaluated} layer(s) evaluated)"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer'].split('_')[0]}: {lr['reason']}")
            for cond in lr.get("conditions", []):
                print(f"                    Condition: {cond}")

    assert len(permitted_docs) == 3, (
        f"Expected 3 permitted for compliant attorney, got {len(permitted_docs)}"
    )
    print("  ASSERTION PASSED: All 3 documents permitted for compliant attorney.")

    # ------------------------------------------------------------------
    # Scenario 2: Opposing counsel — should be denied on privileged and
    #             opinion work product; public filing still permitted.
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Opposing Counsel ---")

    opposing_counsel_context = LegalServicesContext(
        user_id="atty-opposing-jones",
        user_role=LegalRole.OPPOSING_COUNSEL,
        matter_id="matter-2026-0042",
        client_id="client-defendant-ltd",
        bar_number="WA-77310",
        bar_jurisdiction="WA",
        is_admitted_in_matter_jurisdiction=True,
        is_on_matter_team=False,
        has_conflict_cleared=True,
        adverse_to_former_client=False,
        former_client_consented=False,
        privilege_waiver_documented=False,
        substantial_need_shown=False,   # No substantial need — work product stays protected
        is_audit_access=False,
    )

    permitted_docs_opp, audit_records_opp = pipeline.retrieve_with_audit(
        opposing_counsel_context, documents
    )

    print(f"  Context:  Opposing counsel Jones (no substantial need, no privilege waiver)")
    print(f"  Documents submitted: {len(documents)}")
    print(f"  Documents permitted: {len(permitted_docs_opp)}")
    for record in audit_records_opp:
        layers_evaluated = len(record.layer_results)
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id} "
            f"({layers_evaluated} layer(s) evaluated)"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer'].split('_')[0]}: {lr['reason']}")
            for cond in lr.get("conditions", []):
                print(f"                    Condition: {cond}")

    # Opposing counsel must be denied on privileged doc (Layer 1) and on the
    # opinion work product doc (Layer 3 — absolute protection).
    # The public court filing must be permitted.
    assert len(permitted_docs_opp) == 1, (
        f"Expected only public filing permitted for opposing counsel, got {len(permitted_docs_opp)}"
    )
    assert permitted_docs_opp[0].document_id == "doc-003-public-motion", (
        "Expected only the public court filing to be permitted for opposing counsel"
    )
    print("  ASSERTION PASSED: Only public filing permitted for opposing counsel.")

    # ------------------------------------------------------------------
    # Scenario 3: Attorney from wrong jurisdiction — admitted in CA, matter is WA
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: Attorney Admitted in Wrong Jurisdiction (CA, not WA) ---")

    wrong_jurisdiction_attorney = LegalServicesContext(
        user_id="atty-ca-attorney",
        user_role=LegalRole.ATTORNEY,
        matter_id="matter-2026-0042",
        client_id="client-acme-corp",
        bar_number="CA-112233",
        bar_jurisdiction="CA",
        is_admitted_in_matter_jurisdiction=False,  # CA attorney, WA matter
        is_on_matter_team=True,
        has_conflict_cleared=True,
        adverse_to_former_client=False,
        former_client_consented=False,
        privilege_waiver_documented=False,
        substantial_need_shown=False,
        is_audit_access=False,
    )

    permitted_docs_wrong_jx, audit_records_wrong_jx = pipeline.retrieve_with_audit(
        wrong_jurisdiction_attorney, documents
    )

    print(f"  Context:  CA attorney not admitted in WA — matter jurisdiction is WA")
    print(f"  Documents submitted: {len(documents)}")
    print(f"  Documents permitted: {len(permitted_docs_wrong_jx)}")
    for record in audit_records_wrong_jx:
        layers_evaluated = len(record.layer_results)
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id} "
            f"({layers_evaluated} layer(s) evaluated)"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer'].split('_')[0]}: {lr['reason']}")

    # Public filing permitted; privileged and work product docs denied at Layer 4
    # (jurisdiction) — but note that the non-public docs fail at Layer 4 only because
    # Layers 1-3 pass for a matter-team member with cleared conflicts.
    assert len(permitted_docs_wrong_jx) == 1, (
        f"Expected only public filing for out-of-jurisdiction attorney, "
        f"got {len(permitted_docs_wrong_jx)}"
    )
    print("  ASSERTION PASSED: Only public filing permitted for out-of-jurisdiction attorney.")

    # ------------------------------------------------------------------
    # Scenario 4: Audit log output for compliance review
    # ------------------------------------------------------------------
    print("\n--- Scenario 4: Audit Log Output (first record) ---")
    first_record = audit_records[0]
    import json
    print(json.dumps(first_record.to_audit_log(), indent=2))

    print("\n" + "=" * 70)
    print("All smoke tests passed.")
    print("=" * 70)
