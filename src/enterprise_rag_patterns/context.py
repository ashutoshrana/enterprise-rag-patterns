from dataclasses import dataclass, field


@dataclass(slots=True)
class ContextSource:
    """Represents one authoritative context input for an AI workflow."""

    name: str
    freshness_seconds: int | None = None
    required: bool = True


@dataclass(slots=True)
class ContextEnvelope:
    """A small container describing assembled context for one interaction turn."""

    session_id: str
    channel: str
    sources: list[ContextSource] = field(default_factory=list)
    facts: dict[str, str] = field(default_factory=dict)

    def add_fact(self, key: str, value: str) -> None:
        self.facts[key] = value

    def source_names(self) -> list[str]:
        return [source.name for source in self.sources]
