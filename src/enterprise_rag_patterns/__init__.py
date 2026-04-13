"""Reference patterns for enterprise retrieval and workflow-safe AI integration."""

__version__ = "0.35.0"

from .compliance import (
    AuditRecord,
    DisclosureReason,
    FERPAContextPolicy,
    RecordCategory,
    StudentIdentityScope,
    make_enrollment_advisor_policy,
)
from .context import ContextEnvelope, ContextSource
from .pipeline import FilterPipeline, PipelineResult
from .policy import ActionPolicy, EscalationRule
from .session import SessionState

__all__ = [
    # Version
    "__version__",
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
    # Pipeline
    "FilterPipeline",
    "PipelineResult",
    # Policy
    "ActionPolicy",
    "EscalationRule",
    # Session
    "SessionState",
]
