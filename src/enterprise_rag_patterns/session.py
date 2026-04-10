from dataclasses import dataclass, field


@dataclass(slots=True)
class SessionState:
    """Tracks cross-channel continuity for a single user or workflow."""

    session_id: str
    primary_channel: str
    known_channels: set[str] = field(default_factory=set)
    checkpoints: list[str] = field(default_factory=list)
    escalated: bool = False

    def register_channel(self, channel: str) -> None:
        self.known_channels.add(channel)

    def add_checkpoint(self, checkpoint: str) -> None:
        self.checkpoints.append(checkpoint)
