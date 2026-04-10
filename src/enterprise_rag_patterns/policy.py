from dataclasses import dataclass, field


@dataclass(slots=True)
class EscalationRule:
    """Defines when human intervention should be required."""

    name: str
    reason: str


@dataclass(slots=True)
class ActionPolicy:
    """Simple policy boundary for workflow-safe actions."""

    allowed_actions: set[str] = field(default_factory=set)
    escalation_rules: list[EscalationRule] = field(default_factory=list)

    def can_run(self, action_name: str) -> bool:
        return action_name in self.allowed_actions
