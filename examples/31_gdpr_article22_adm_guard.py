"""
examples/31_gdpr_article22_adm_guard.py

GDPR Article 22 Automated Decision-Making Guard for RAG Pipelines

Demonstrates a four-layer compliance guard that intercepts RAG queries
before they reach the LLM whenever the retrieved documents and the
query purpose together constitute a legally-significant automated
decision (ADM) under GDPR Article 22.

Commercial use cases requiring this guard:

  +-------------------------------+------------------------------------------+
  | Platform / Product            | ADM Categories Covered                   |
  +-------------------------------+------------------------------------------+
  | Consumer lending / fintech    | Credit scoring, loan approval            |
  | InsurTech underwriting bots   | Risk classification, premium setting     |
  | HR / ATS screening agents     | Employment shortlisting, scoring         |
  | Healthcare triage AI          | Medical urgency classification           |
  | Government benefits portals   | Eligibility determination                |
  | Educational admissions AI     | Applicant ranking, admission decision    |
  +-------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — ADM Detection (GDPR Art. 22(1))
      GDPR Art. 22(1): "The data subject shall have the right not to be
      subject to a decision based solely on automated processing, including
      profiling, which produces legal effects concerning him or her or
      similarly significantly affects him or her."

      The detection layer classifies whether the RAG query is seeking
      support for a decision in one of five legally-significant categories:
      credit/loan, insurance underwriting, employment screening, medical
      triage, or public benefit eligibility. Classification uses a
      keyword-to-category mapping. Returns ADM_DETECTED or ADM_SAFE.

  Layer 2 — Special Category Data Gate (GDPR Art. 9)
      GDPR Art. 9(1) prohibits processing of special categories of
      personal data (health, biometric, genetic, racial/ethnic origin,
      political opinion, religion, trade union membership, sex life or
      orientation) except under explicit Art. 9(2) exceptions.

      When retrieved context contains special category data AND an ADM
      has been detected, the gate checks for a lawful Art. 9(2) basis.
      Without one, it returns SPECIAL_CATEGORY_BLOCKED and halts the
      pipeline. This prevents the LLM from using, for example, health
      records to score an insurance application without explicit consent.

  Layer 3 — Human Review Gate (GDPR Art. 22(2)-(3))
      GDPR Art. 22(2) lists the three exceptions under which ADM is
      permissible: (a) contract necessity, (b) legal authorisation,
      (c) explicit consent. Art. 22(3) requires that, where ADM is
      permitted, the controller must implement suitable measures to
      safeguard data subject rights, including at minimum "the right to
      obtain human intervention on the part of the controller."

      This layer enforces that requirement: when ADM is detected and
      passes the special category gate, it routes to human review before
      the model call and emits the Art. 22(3) notification record that
      must be communicated to the data subject. Returns
      HUMAN_REVIEW_REQUIRED (halt) or PROCEED (allowed exception present).

  Layer 4 — GDPR Art. 30 Audit Log
      GDPR Art. 30 requires controllers to maintain records of processing
      activities including: purposes, categories of data subjects, data
      categories, recipients, and retention periods. For ADM events this
      log additionally records: the Art. 6 lawful basis, the ADM category,
      whether human review was required, and a pseudonymised data subject
      identifier. Every pipeline run appends one entry regardless of
      outcome, providing a complete processing activity record.

Run:
    python examples/31_gdpr_article22_adm_guard.py
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Shared enums and data types
# ---------------------------------------------------------------------------

class ADMVerdict(str, Enum):
    ADM_DETECTED = "ADM_DETECTED"
    ADM_SAFE = "ADM_SAFE"


class SpecialCategoryVerdict(str, Enum):
    SPECIAL_CATEGORY_BLOCKED = "SPECIAL_CATEGORY_BLOCKED"
    ALLOWED = "ALLOWED"


class HumanReviewVerdict(str, Enum):
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    PROCEED = "PROCEED"


@dataclass
class RAGRequest:
    """Represents a single RAG pipeline invocation."""
    query: str
    retrieved_context: str
    data_subject_id: str              # raw identifier — pseudonymised before logging
    art6_lawful_basis: str            # e.g. "contract", "legal_obligation", "consent"
    art9_basis: Optional[str] = None  # e.g. "explicit_consent" (Art. 9(2)(a))
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class PipelineResult:
    """Outcome of the full four-layer guard evaluation."""
    allowed: bool
    verdict: str
    adm_category: Optional[str]
    citation: str
    human_review_required: bool
    audit_id: str
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Layer 1 — ADM Detection Filter (GDPR Art. 22(1))
# ---------------------------------------------------------------------------

_ADM_CATEGORIES: Dict[str, List[str]] = {
    "credit_loan": [
        "loan application", "credit score", "creditworthiness", "mortgage approval",
        "debt-to-income", "loan eligibility", "credit limit", "lending decision",
        "approve loan", "deny loan", "loan assessment",
    ],
    "insurance_underwriting": [
        "insurance premium", "underwriting", "risk classification", "policy approval",
        "insurance eligibility", "actuarial", "insure applicant", "coverage decision",
        "insurance score", "policy denial",
    ],
    "employment_screening": [
        "job application", "resume screening", "candidate shortlist", "hiring decision",
        "employment eligibility", "background check", "applicant score", "recruit",
        "employee evaluation", "termination decision",
    ],
    "medical_triage": [
        "medical diagnosis", "triage priority", "clinical urgency", "treatment decision",
        "patient risk score", "diagnostic recommendation", "medical eligibility",
        "health assessment", "prognosis", "clinical decision",
        "triage", "clinical triage", "urgent triage", "patient triage",
        "prioritise patient", "prioritize patient",
    ],
    "public_benefit_eligibility": [
        "benefit eligibility", "welfare entitlement", "social assistance",
        "public housing", "subsidy eligibility", "benefits claim", "state aid",
        "disability benefits", "benefits determination",
    ],
}

_ADM_CITATIONS: Dict[str, str] = {
    "credit_loan":              "GDPR Art. 22(1) — credit/lending automated decision",
    "insurance_underwriting":   "GDPR Art. 22(1) — insurance automated decision",
    "employment_screening":     "GDPR Art. 22(1) — employment automated decision",
    "medical_triage":           "GDPR Art. 22(1) — medical automated decision",
    "public_benefit_eligibility": "GDPR Art. 22(1) — public benefit eligibility decision",
}


class ADMDetectionFilter:
    """
    Layer 1: Detect legally-significant automated decision queries.

    Scans the query text against five ADM category keyword dictionaries.
    Returns ADM_DETECTED with the matched category, or ADM_SAFE.
    """

    def evaluate(self, query: str) -> tuple[ADMVerdict, Optional[str]]:
        lower = query.lower()
        for category, keywords in _ADM_CATEGORIES.items():
            if any(kw in lower for kw in keywords):
                return ADMVerdict.ADM_DETECTED, category
        return ADMVerdict.ADM_SAFE, None


# ---------------------------------------------------------------------------
# Layer 2 — Special Category Data Gate (GDPR Art. 9)
# ---------------------------------------------------------------------------

_SPECIAL_CATEGORY_SIGNALS: Dict[str, List[str]] = {
    "health":          ["diagnosis", "medical record", "health condition", "prescription",
                        "patient", "clinical", "disability", "mental health", "medication"],
    "biometric":       ["fingerprint", "facial recognition", "retinal scan", "voice print",
                        "biometric identifier"],
    "genetic":         ["genetic data", "dna", "genome", "hereditary", "chromosom"],
    "racial_ethnic":   ["race", "ethnicity", "national origin", "ethnic background"],
    "political":       ["political opinion", "political affiliation", "political party"],
    "religion":        ["religion", "religious belief", "faith", "denomination"],
    "trade_union":     ["trade union", "union membership", "union affiliation"],
    "sex_life":        ["sexual orientation", "sex life", "gender identity"],
}

# Recognised Art. 9(2) basis tokens that callers may supply
_VALID_ART9_BASES: set[str] = {
    "explicit_consent",          # Art. 9(2)(a)
    "employment_social_law",     # Art. 9(2)(b)
    "vital_interests",           # Art. 9(2)(c)
    "nonprofit_legitimate",      # Art. 9(2)(d)
    "made_public_by_subject",    # Art. 9(2)(e)
    "legal_claims",              # Art. 9(2)(f)
    "substantial_public_interest", # Art. 9(2)(g)
    "preventive_medicine",       # Art. 9(2)(h)
    "public_health",             # Art. 9(2)(i)
    "archiving_research",        # Art. 9(2)(j)
}


class SpecialCategoryFilter:
    """
    Layer 2: Block special category data in ADM contexts without Art. 9(2) basis.

    GDPR Art. 9(1) prohibits processing special categories in automated
    decision-making. Art. 9(2) enumerates permissible exceptions. If the
    retrieved context contains special category signals and no valid Art. 9(2)
    basis is provided, returns SPECIAL_CATEGORY_BLOCKED.
    """

    def evaluate(
        self,
        retrieved_context: str,
        art9_basis: Optional[str],
    ) -> tuple[SpecialCategoryVerdict, Optional[str]]:
        lower = retrieved_context.lower()
        detected: Optional[str] = None
        for category, signals in _SPECIAL_CATEGORY_SIGNALS.items():
            if any(s in lower for s in signals):
                detected = category
                break

        if detected is None:
            return SpecialCategoryVerdict.ALLOWED, None

        if art9_basis and art9_basis in _VALID_ART9_BASES:
            return SpecialCategoryVerdict.ALLOWED, detected

        return SpecialCategoryVerdict.SPECIAL_CATEGORY_BLOCKED, detected


# ---------------------------------------------------------------------------
# Layer 3 — Human Review Gate (GDPR Art. 22(2)-(3))
# ---------------------------------------------------------------------------

# Art. 22(2) permissible exceptions for ADM
_ART22_EXCEPTIONS: set[str] = {
    "contract",          # Art. 22(2)(a) — necessary for contract performance
    "legal_obligation",  # Art. 22(2)(b) — authorised by Union/Member State law
    "explicit_consent",  # Art. 22(2)(c) — data subject has given explicit consent
}


@dataclass
class HumanReviewRecord:
    """Art. 22(3) notification record for the data subject."""
    session_id: str
    adm_category: str
    art22_exception_applied: Optional[str]
    notification_text: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class HumanReviewGate:
    """
    Layer 3: Enforce Art. 22(3) human review before allowing ADM.

    If a valid Art. 22(2) exception (contract, legal obligation, consent)
    is present, the request may PROCEED — but a notification record is still
    created. Without a valid exception the gate returns HUMAN_REVIEW_REQUIRED
    and halts pipeline execution.
    """

    def __init__(self) -> None:
        self._notifications: List[HumanReviewRecord] = []

    def evaluate(
        self,
        session_id: str,
        adm_category: str,
        art6_lawful_basis: str,
        art9_basis: Optional[str],
    ) -> tuple[HumanReviewVerdict, HumanReviewRecord]:
        exception = None
        if art6_lawful_basis in _ART22_EXCEPTIONS:
            exception = art6_lawful_basis
        elif art9_basis == "explicit_consent":
            exception = "explicit_consent"

        if exception:
            verdict = HumanReviewVerdict.PROCEED
            notification_text = (
                f"Your request involves an automated decision in category "
                f"'{adm_category}'. Processing proceeds under Art. 22(2) "
                f"exception '{exception}'. You retain rights under Art. 22(3) "
                f"to request human intervention, to express your point of view, "
                f"and to contest the decision."
            )
        else:
            verdict = HumanReviewVerdict.HUMAN_REVIEW_REQUIRED
            notification_text = (
                f"Your request involves an automated decision in category "
                f"'{adm_category}'. No Art. 22(2) exception applies. "
                f"A human reviewer has been assigned to evaluate this request "
                f"before any decision is made (GDPR Art. 22(1))."
            )

        record = HumanReviewRecord(
            session_id=session_id,
            adm_category=adm_category,
            art22_exception_applied=exception,
            notification_text=notification_text,
        )
        self._notifications.append(record)
        return verdict, record

    @property
    def notifications(self) -> List[HumanReviewRecord]:
        return list(self._notifications)


# ---------------------------------------------------------------------------
# Layer 4 — GDPR Art. 30 Audit Logger
# ---------------------------------------------------------------------------

def _pseudonymise(data_subject_id: str) -> str:
    """SHA-256 pseudonym; real implementations use a keyed HMAC."""
    return "ps-" + hashlib.sha256(data_subject_id.encode()).hexdigest()[:16]


class GDPRAuditLogger:
    """
    Layer 4: Records of processing activities per GDPR Art. 30.

    Every ADM pipeline event is appended with: pseudonymised data subject,
    decision category, Art. 6 lawful basis, whether human review was required,
    timestamp, and the specific GDPR citations triggered.
    """

    def __init__(self) -> None:
        self._log: List[Dict[str, Any]] = []

    def record(
        self,
        request: RAGRequest,
        adm_category: Optional[str],
        special_category_detected: Optional[str],
        human_review_required: bool,
        verdict: str,
        citations: List[str],
    ) -> str:
        audit_id = str(uuid.uuid4())
        self._log.append({
            "audit_id": audit_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data_subject_pseudonym": _pseudonymise(request.data_subject_id),
            "session_id": request.session_id,
            "adm_category": adm_category,
            "special_category_detected": special_category_detected,
            "art6_lawful_basis": request.art6_lawful_basis,
            "art9_basis": request.art9_basis,
            "human_review_required": human_review_required,
            "verdict": verdict,
            "citations": citations,
            "processing_purpose": "RAG-assisted decision support",
            "retention_basis": "Art. 30 — 3-year minimum for ADM records",
        })
        return audit_id

    @property
    def entries(self) -> List[Dict[str, Any]]:
        return list(self._log)


# ---------------------------------------------------------------------------
# Pipeline Orchestrator
# ---------------------------------------------------------------------------

class GDPRArticle22Guard:
    """
    Four-layer GDPR Article 22 automated decision-making guard.

    Evaluates every RAG request through:
      1. ADM Detection       — is this a legally-significant decision query?
      2. Special Category    — does the retrieved context contain Art. 9 data?
      3. Human Review Gate   — is an Art. 22(2) exception present?
      4. Audit Log           — Art. 30 processing record, regardless of outcome.
    """

    def __init__(self) -> None:
        self._adm_filter = ADMDetectionFilter()
        self._special_filter = SpecialCategoryFilter()
        self._human_gate = HumanReviewGate()
        self._audit = GDPRAuditLogger()

    def evaluate(self, request: RAGRequest) -> PipelineResult:
        citations: List[str] = []
        adm_category: Optional[str] = None
        special_category: Optional[str] = None
        human_review_required = False

        # Layer 1 — ADM Detection
        adm_verdict, adm_category = self._adm_filter.evaluate(request.query)
        if adm_verdict == ADMVerdict.ADM_SAFE:
            audit_id = self._audit.record(
                request, adm_category, None, False,
                "ADM_SAFE", ["GDPR Art. 22(1) — no ADM detected"],
            )
            return PipelineResult(
                allowed=True,
                verdict="ADM_SAFE",
                adm_category=None,
                citation="GDPR Art. 22(1) — query does not constitute an ADM",
                human_review_required=False,
                audit_id=audit_id,
            )

        citations.append(_ADM_CITATIONS[adm_category])

        # Layer 2 — Special Category Gate
        sc_verdict, special_category = self._special_filter.evaluate(
            request.retrieved_context, request.art9_basis
        )
        if sc_verdict == SpecialCategoryVerdict.SPECIAL_CATEGORY_BLOCKED:
            citations.append(
                f"GDPR Art. 9(1) — special category '{special_category}' "
                f"blocked; no valid Art. 9(2) basis provided"
            )
            audit_id = self._audit.record(
                request, adm_category, special_category, True,
                "SPECIAL_CATEGORY_BLOCKED", citations,
            )
            return PipelineResult(
                allowed=False,
                verdict="SPECIAL_CATEGORY_BLOCKED",
                adm_category=adm_category,
                citation="; ".join(citations),
                human_review_required=True,
                audit_id=audit_id,
                details={
                    "special_category": special_category,
                    "remediation": (
                        "Obtain explicit consent per Art. 9(2)(a) or establish "
                        "another Art. 9(2) basis before processing."
                    ),
                },
            )
        if special_category:
            citations.append(
                f"GDPR Art. 9(2) — special category '{special_category}' "
                f"permitted under basis '{request.art9_basis}'"
            )

        # Layer 3 — Human Review Gate
        hr_verdict, hr_record = self._human_gate.evaluate(
            session_id=request.session_id,
            adm_category=adm_category,
            art6_lawful_basis=request.art6_lawful_basis,
            art9_basis=request.art9_basis,
        )

        if hr_verdict == HumanReviewVerdict.HUMAN_REVIEW_REQUIRED:
            human_review_required = True
            citations.append(
                "GDPR Art. 22(1) — human review required; no Art. 22(2) "
                "exception established"
            )
            citations.append("GDPR Art. 22(3) — data subject notification issued")
            audit_id = self._audit.record(
                request, adm_category, special_category, True,
                "HUMAN_REVIEW_REQUIRED", citations,
            )
            return PipelineResult(
                allowed=False,
                verdict="HUMAN_REVIEW_REQUIRED",
                adm_category=adm_category,
                citation="; ".join(citations),
                human_review_required=True,
                audit_id=audit_id,
                details={
                    "art22_exception": None,
                    "notification": hr_record.notification_text,
                },
            )

        # Art. 22(2) exception present — PROCEED with audit
        citations.append(
            f"GDPR Art. 22(2) — ADM permitted under exception "
            f"'{hr_record.art22_exception_applied}'"
        )
        citations.append("GDPR Art. 22(3) — data subject notification issued")
        audit_id = self._audit.record(
            request, adm_category, special_category, False,
            "PROCEED", citations,
        )
        return PipelineResult(
            allowed=True,
            verdict="PROCEED",
            adm_category=adm_category,
            citation="; ".join(citations),
            human_review_required=False,
            audit_id=audit_id,
            details={
                "art22_exception": hr_record.art22_exception_applied,
                "notification": hr_record.notification_text,
            },
        )

    @property
    def audit_log(self) -> List[Dict[str, Any]]:
        return self._audit.entries


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main() -> None:
    guard = GDPRArticle22Guard()

    scenarios = [
        {
            "label": "Scenario 1 — Loan application, no special categories "
                     "(ADM detected, human review required)",
            "request": RAGRequest(
                query="Assess this loan application and recommend approval or denial "
                      "based on the applicant's creditworthiness.",
                retrieved_context="Applicant income: 45,000 GBP. "
                                  "Outstanding debts: 12,000 GBP. "
                                  "Employment status: permanent full-time.",
                data_subject_id="user-001",
                art6_lawful_basis="legitimate_interest",  # not an Art. 22(2) exception
            ),
        },
        {
            "label": "Scenario 2 — Credit check with health data, no Art. 9(2) basis "
                     "(BLOCKED — Art. 9(1))",
            "request": RAGRequest(
                query="Evaluate creditworthiness for this mortgage application.",
                retrieved_context="Applicant has a diagnosis of type 2 diabetes. "
                                  "Credit history: 3 missed payments in 24 months.",
                data_subject_id="user-002",
                art6_lawful_basis="contract",
                art9_basis=None,   # no basis supplied
            ),
        },
        {
            "label": "Scenario 3 — Medical triage with explicit consent Art. 9(2)(a) "
                     "(PROCEED)",
            "request": RAGRequest(
                query="Prioritise this patient for urgent clinical triage.",
                retrieved_context="Patient presents with chest pain and elevated troponin. "
                                  "Medical history includes prior cardiac event.",
                data_subject_id="user-003",
                art6_lawful_basis="explicit_consent",
                art9_basis="explicit_consent",   # Art. 9(2)(a)
            ),
        },
        {
            "label": "Scenario 4 — General product search, no ADM "
                     "(ADM_SAFE, passes all layers)",
            "request": RAGRequest(
                query="What are the best-selling running shoes in stock?",
                retrieved_context="Product catalogue: Nike Pegasus, Adidas Ultraboost, "
                                  "Brooks Ghost — all available in sizes 7-13.",
                data_subject_id="user-004",
                art6_lawful_basis="legitimate_interest",
            ),
        },
    ]

    print("\nGDPR Article 22 Automated Decision-Making Guard")
    print("=" * 60)

    for scenario in scenarios:
        result = guard.evaluate(scenario["request"])
        print(f"\n[{scenario['label']}]")
        print(f"  Verdict  : {result.verdict}")
        print(f"  Allowed  : {result.allowed}")
        if result.adm_category:
            print(f"  ADM Cat  : {result.adm_category}")
        print(f"  Human rev: {result.human_review_required}")
        print(f"  Citation : {result.citation[:120]}{'...' if len(result.citation) > 120 else ''}")
        if result.details.get("notification"):
            print(f"  Notice   : {result.details['notification'][:100]}...")
        if result.details.get("remediation"):
            print(f"  Remediate: {result.details['remediation']}")
        print(f"  Audit ID : {result.audit_id}")

    print(f"\nArt. 30 audit log — {len(guard.audit_log)} entries")
    print("-" * 60)
    for entry in guard.audit_log:
        print(
            f"  {entry['timestamp']} | {entry['verdict']:30s} | "
            f"category={entry['adm_category'] or 'none':30s} | "
            f"subject={entry['data_subject_pseudonym']}"
        )


if __name__ == "__main__":
    main()
