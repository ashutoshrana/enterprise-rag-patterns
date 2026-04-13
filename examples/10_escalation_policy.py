"""
10_escalation_policy.py — Human escalation policies for workflow-safe enterprise RAG.

Demonstrates how to use ``ActionPolicy`` and ``EscalationRule`` to define
explicit human-handoff boundaries for an AI enrollment advisor agent.

Three escalation trigger types are covered:

  1. **Regulatory triggers** — actions that require human authorization by
     regulation or institution policy (withdrawal, financial aid changes, PII
     export). The agent must stop and route to a human advisor regardless of
     confidence.

  2. **Confidence-based triggers** — the agent's confidence in its answer
     is below an operational threshold.  Rather than giving a low-quality
     response, the agent routes to a human who can access primary systems.

  3. **Content-based triggers** — the retrieved context contains categories
     of information that require human judgment: legal disputes, academic
     integrity flags, medical or financial hardship disclosures.

The example also shows:
  - How ``ActionPolicy`` enforces the permitted action boundary.
  - How to build an audit trail of escalation decisions.
  - The "escalate quietly" pattern: agents should not disclose *why* they are
    escalating (e.g. "I found a disciplinary record") — they should say only
    that they are routing to a human advisor (FERPA 34 CFR § 99.12).

Run:
    python examples/10_escalation_policy.py
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from enterprise_rag_patterns.policy import ActionPolicy, EscalationRule

# ---------------------------------------------------------------------------
# Escalation tier enum
# ---------------------------------------------------------------------------


class EscalationTier(str, Enum):
    """Urgency / routing tier for a human escalation."""

    AUTOMATED = "automated"  # no escalation — agent handles
    SOFT = "soft"  # recommend human; agent may attempt answer
    REQUIRED = "required"  # must route to human; agent cannot answer
    REGULATORY = "regulatory"  # compliance-required; immediate routing


# ---------------------------------------------------------------------------
# Escalation audit record
# ---------------------------------------------------------------------------


@dataclass
class EscalationEvent:
    """Immutable record of an escalation decision."""

    session_id: str
    query: str
    action_attempted: str
    tier: EscalationTier
    triggered_by: str  # which rule or check triggered this
    notes: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_log_entry(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "query_preview": self.query[:80],
            "action": self.action_attempted,
            "tier": self.tier.value,
            "triggered_by": self.triggered_by,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# Escalation policy engine
# ---------------------------------------------------------------------------


class EscalationPolicyEngine:
    """
    Evaluates whether an agent action requires human escalation.

    Checks three layers in priority order:
      1. Regulatory triggers (always escalate — cannot override)
      2. Content-based triggers (inspect retrieved context)
      3. Confidence-based triggers (inspect agent confidence score)
    """

    REGULATORY_ACTIONS: frozenset[str] = frozenset(
        {
            "submit_withdrawal",
            "process_financial_aid_change",
            "override_academic_hold",
            "release_pii_export",
            "issue_enrollment_certification",
            "authorize_late_registration",
        }
    )

    CONTENT_TRIGGER_KEYWORDS: dict[str, str] = {
        "disciplinary": "Academic integrity / disciplinary record referenced",
        "grievance": "Student grievance or complaint referenced",
        "medical hardship": "Medical hardship disclosure — requires advisor review",
        "financial hardship": "Financial hardship disclosure — requires advisor review",
        "legal dispute": "Legal matter referenced — requires compliance review",
        "deceased": "Deceased student record — requires registrar review",
    }

    CONFIDENCE_THRESHOLD_SOFT = 0.75
    CONFIDENCE_THRESHOLD_REQUIRED = 0.50

    def __init__(
        self,
        policy: ActionPolicy,
        audit_sink: Any = None,
    ) -> None:
        self._policy = policy
        self._audit_sink = audit_sink or (lambda e: None)

    def evaluate(
        self,
        session_id: str,
        action: str,
        query: str,
        retrieved_context: list[dict[str, Any]],
        confidence: float = 1.0,
    ) -> tuple[EscalationTier, str]:
        """
        Evaluate whether the action should be escalated.

        Returns (tier, reason). If tier == AUTOMATED, the agent may proceed.
        Any other tier indicates some form of human involvement is needed.

        Args:
            session_id: Current session identifier for audit logging.
            action: The action the agent wants to perform.
            query: The user's query text.
            retrieved_context: Documents retrieved for this query.
            confidence: Agent's self-reported confidence (0.0–1.0).

        Returns:
            A tuple (EscalationTier, reason_string).
        """
        tier, reason = self._check_regulatory(action)
        if tier == EscalationTier.REGULATORY:
            self._log(session_id, query, action, tier, "regulatory_action_list", reason)
            return tier, reason

        if not self._policy.can_run(action):
            reason = f"Action '{action}' is not in the permitted action set for this scope"
            self._log(session_id, query, action, EscalationTier.REQUIRED, "policy_boundary", reason)
            return EscalationTier.REQUIRED, reason

        tier, reason = self._check_content(query, retrieved_context)
        if tier != EscalationTier.AUTOMATED:
            self._log(session_id, query, action, tier, "content_trigger", reason)
            return tier, reason

        tier, reason = self._check_confidence(confidence)
        if tier != EscalationTier.AUTOMATED:
            self._log(session_id, query, action, tier, "confidence_threshold", reason)
            return tier, reason

        return EscalationTier.AUTOMATED, "all checks passed"

    def _check_regulatory(self, action: str) -> tuple[EscalationTier, str]:
        if action in self.REGULATORY_ACTIONS:
            return (
                EscalationTier.REGULATORY,
                f"Action '{action}' requires human authorization — cannot be performed by AI agent",
            )
        return EscalationTier.AUTOMATED, ""

    def _check_content(self, query: str, docs: list[dict[str, Any]]) -> tuple[EscalationTier, str]:
        combined_text = (query + " " + " ".join(str(d.get("content", "")) for d in docs)).lower()
        for keyword, description in self.CONTENT_TRIGGER_KEYWORDS.items():
            if keyword in combined_text:
                return EscalationTier.REQUIRED, description
        return EscalationTier.AUTOMATED, ""

    def _check_confidence(self, confidence: float) -> tuple[EscalationTier, str]:
        if confidence < self.CONFIDENCE_THRESHOLD_REQUIRED:
            return (
                EscalationTier.REQUIRED,
                f"Confidence {confidence:.0%} below required threshold ({self.CONFIDENCE_THRESHOLD_REQUIRED:.0%})",
            )
        if confidence < self.CONFIDENCE_THRESHOLD_SOFT:
            return (
                EscalationTier.SOFT,
                f"Confidence {confidence:.0%} below soft threshold "
                f"({self.CONFIDENCE_THRESHOLD_SOFT:.0%}) — recommend human review",
            )
        return EscalationTier.AUTOMATED, ""

    def _log(
        self,
        session_id: str,
        query: str,
        action: str,
        tier: EscalationTier,
        triggered_by: str,
        notes: str,
    ) -> None:
        event = EscalationEvent(
            session_id=session_id,
            query=query,
            action_attempted=action,
            tier=tier,
            triggered_by=triggered_by,
            notes=notes,
        )
        self._audit_sink(event)


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------


STUDENT_SESSION = "sess-enroll-8821"

escalation_log: list[EscalationEvent] = []

# Build the action policy for an enrollment advisor agent.
# The agent may search the knowledge base, answer questions about course
# requirements, and look up general program information.
# It may NOT modify enrollment records, process financial changes, or
# access disciplinary data — those require a human advisor.

enrollment_advisor_policy = ActionPolicy(
    allowed_actions={
        "search_course_catalog",
        "lookup_graduation_requirements",
        "answer_general_question",
        "retrieve_student_schedule",
        "check_prerequisite_status",
    },
    escalation_rules=[
        EscalationRule(
            name="withdrawal_request",
            reason="Course and program withdrawals require advisor review and may affect financial aid",
        ),
        EscalationRule(
            name="financial_aid_inquiry",
            reason="Financial aid changes require human authorization per HEA regulations",
        ),
        EscalationRule(
            name="academic_hold",
            reason="Academic holds require registrar office action",
        ),
        EscalationRule(
            name="low_confidence_response",
            reason="Agent confidence below threshold — human advisor may have additional context",
        ),
    ],
)

engine = EscalationPolicyEngine(
    policy=enrollment_advisor_policy,
    audit_sink=escalation_log.append,
)


def run_scenario(
    title: str,
    action: str,
    query: str,
    docs: list[dict[str, Any]],
    confidence: float = 1.0,
) -> None:
    tier, reason = engine.evaluate(
        session_id=STUDENT_SESSION,
        action=action,
        query=query,
        retrieved_context=docs,
        confidence=confidence,
    )

    status_icon = {
        EscalationTier.AUTOMATED: "✅",
        EscalationTier.SOFT: "⚠️ ",
        EscalationTier.REQUIRED: "🚫",
        EscalationTier.REGULATORY: "⛔",
    }[tier]

    print(f"\n  {status_icon}  [{tier.value.upper()}]  {title}")
    print(f"      Action:   {action}")
    print(f"      Query:    {query[:70]}")
    print(f"      Reason:   {reason}")

    if tier != EscalationTier.AUTOMATED:
        print()
        print('      Agent message to user: "I\'m connecting you with an enrollment advisor who can help with this."')
        if tier == EscalationTier.REGULATORY:
            print("      → Route to: human_advisor queue (regulatory flag)")
        elif tier == EscalationTier.REQUIRED:
            print("      → Route to: human_advisor queue")
        else:
            print("      → Agent may attempt soft response; advisor available on request")


def main() -> None:
    print("=" * 68)
    print("Human Escalation Policy — Enrollment Advisor Agent")
    print("=" * 68)
    print(f"\nSession:  {STUDENT_SESSION}")
    print(f"\nPermitted actions: {sorted(enrollment_advisor_policy.allowed_actions)}")
    print(f"\nEscalation rules defined: {len(enrollment_advisor_policy.escalation_rules)}")
    for rule in enrollment_advisor_policy.escalation_rules:
        print(f"  • {rule.name}: {rule.reason[:60]}")

    print("\n" + "─" * 68)
    print("SCENARIO EVALUATION")
    print("─" * 68)

    # --- Scenario 1: Normal course catalog query (automated) ---
    run_scenario(
        title="General course catalog lookup",
        action="search_course_catalog",
        query="What CS courses are available in the spring semester?",
        docs=[
            {"content": "CS 301: Data Structures. 3 credits. Spring/Fall."},
            {"content": "CS 401: Algorithms. Prerequisites: CS 301."},
        ],
        confidence=0.95,
    )

    # --- Scenario 2: Regulatory trigger — withdrawal action ---
    run_scenario(
        title="Withdrawal request (regulatory action)",
        action="submit_withdrawal",
        query="I want to withdraw from all my courses this semester.",
        docs=[
            {"content": "Withdrawal deadline is November 15. Refund policy applies."},
        ],
        confidence=0.92,
    )

    # --- Scenario 3: Action outside permitted set ---
    run_scenario(
        title="Action outside permitted boundary",
        action="override_academic_hold",
        query="Can you remove the hold on my account so I can register?",
        docs=[
            {"content": "Account hold: unpaid balance of $450."},
        ],
        confidence=0.88,
    )

    # --- Scenario 4: Content trigger — disciplinary record in context ---
    run_scenario(
        title="Content trigger: disciplinary record in retrieved context",
        action="answer_general_question",
        query="Why was I placed on academic probation?",
        docs=[
            {"content": "Academic probation policy: GPA below 2.0 for two consecutive semesters."},
            {"content": "Student file note: disciplinary hearing scheduled for academic integrity violation."},
        ],
        confidence=0.85,
    )

    # --- Scenario 5: Content trigger — financial hardship disclosure ---
    run_scenario(
        title="Content trigger: financial hardship disclosure",
        action="lookup_graduation_requirements",
        query="I have a financial hardship situation — can I still graduate on time?",
        docs=[
            {"content": "Graduation requirements: 120 credits, minimum 2.0 GPA."},
        ],
        confidence=0.90,
    )

    # --- Scenario 6: Confidence below required threshold ---
    run_scenario(
        title="Confidence below required threshold (REQUIRED escalation)",
        action="answer_general_question",
        query="What happens to my enrollment if my visa status changes?",
        docs=[
            {"content": "F-1 visa students must maintain full-time enrollment."},
            {"content": "SEVIS reporting requirements apply to international students."},
        ],
        confidence=0.42,  # Below 0.50 threshold
    )

    # --- Scenario 7: Confidence below soft threshold ---
    run_scenario(
        title="Confidence below soft threshold (SOFT escalation)",
        action="answer_general_question",
        query="Are there any exceptions to the prerequisite waiver policy?",
        docs=[
            {"content": "Prerequisites may be waived by department chair with written justification."},
        ],
        confidence=0.68,  # Below 0.75 soft threshold
    )

    # --- Scenario 8: High-confidence, permitted action, clean context (automated) ---
    run_scenario(
        title="Graduation requirements lookup (no escalation)",
        action="lookup_graduation_requirements",
        query="How many credits do I need to graduate from the CS program?",
        docs=[
            {"content": "CS program requires 120 credits total, 45 in major."},
            {"content": "Minimum 2.0 GPA in major courses required for graduation."},
        ],
        confidence=0.97,
    )

    # ---------------------------------------------------------------------------
    # Audit trail summary
    # ---------------------------------------------------------------------------
    print()
    print("─" * 68)
    print("ESCALATION AUDIT TRAIL")
    print("─" * 68)
    print(f"\n  {len(escalation_log)} escalation event(s) logged:\n")

    for i, event in enumerate(escalation_log, 1):
        entry = event.to_log_entry()
        print(f"  [{i}] tier={entry['tier']}  action={entry['action']}")
        print(f"       triggered_by={entry['triggered_by']}")
        print(f"       notes={entry['notes'][:70]}")
        print()

    # ---------------------------------------------------------------------------
    # Escalation routing summary
    # ---------------------------------------------------------------------------
    print("─" * 68)
    print("ROUTING SUMMARY")
    print("─" * 68)

    tier_counts: dict[str, int] = {}
    for event in escalation_log:
        tier_counts[event.tier.value] = tier_counts.get(event.tier.value, 0) + 1

    total = 8
    escalated = len(escalation_log)
    automated_count = total - escalated

    print(f"""
  Total queries evaluated:   {total}
  Automated (no escalation): {automated_count}
  Escalated (any tier):      {escalated}
    • regulatory:  {tier_counts.get("regulatory", 0)}
    • required:    {tier_counts.get("required", 0)}
    • soft:        {tier_counts.get("soft", 0)}

  FERPA note: When escalating, the agent does not disclose the specific
  reason to the user (e.g. "disciplinary record found"). It says only
  "I'm connecting you with an advisor" — 34 CFR § 99.12 prohibits
  disclosing which records were accessed or withheld.
""")

    # ---------------------------------------------------------------------------
    # Design principles
    # ---------------------------------------------------------------------------
    print("─" * 68)
    print("DESIGN PRINCIPLES")
    print("─" * 68)
    print(
        """
  1. Escalation is structural, not ad-hoc.
     EscalationRule and ActionPolicy make the handoff boundary explicit in
     code — not in documentation or developer convention. Any new action must
     be added to allowed_actions or it is denied by default.

  2. Regulatory triggers cannot be overridden.
     Withdrawal, financial aid changes, and PII exports always route to a
     human regardless of confidence or retrieved context.

  3. The agent does not disclose the escalation reason to the user.
     "Connecting you with an advisor" is the correct message. Saying "I found
     a disciplinary record" would itself be a FERPA disclosure.

  4. Confidence thresholds have two tiers.
     REQUIRED (< 50%) blocks the agent entirely. SOFT (< 75%) lets the agent
     attempt a response while flagging that a human advisor is available.

  5. Every escalation is logged for auditability.
     The EscalationEvent audit trail answers: "why did this query go to a
     human?" post-hoc, without requiring conversation replay.
"""
    )


if __name__ == "__main__":
    main()
