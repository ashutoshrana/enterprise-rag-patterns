"""Reference patterns for enterprise retrieval and workflow-safe AI integration."""

from .compliance import (
    AuditRecord,
    DisclosureReason,
    FERPAContextPolicy,
    RecordCategory,
    StudentIdentityScope,
    make_enrollment_advisor_policy,
)
from .context import ContextEnvelope, ContextSource
from .policy import ActionPolicy, EscalationRule
from .session import SessionState

__all__ = [
    # Compliance / FERPA
    "AuditRecord",
    "DisclosureReason",
    "FERPAContextPolicy",
    "RecordCategory",
    "StudentIdentityScope",
    "make_enrollment_advisor_policy",
    # Context
    "ContextEnvelope",
    "ContextSource",
    # Policy
    "ActionPolicy",
    "EscalationRule",
    # Session
    "SessionState",
]
