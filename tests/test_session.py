"""Tests for enterprise_rag_patterns.session — SessionState."""

from enterprise_rag_patterns.session import SessionState


class TestSessionState:
    def test_initial_state(self):
        s = SessionState(session_id="s-1", primary_channel="web_chat")
        assert s.session_id == "s-1"
        assert s.primary_channel == "web_chat"
        assert s.known_channels == set()
        assert s.checkpoints == []
        assert s.escalated is False

    def test_register_channel(self):
        s = SessionState(session_id="s-1", primary_channel="web_chat")
        s.register_channel("voice")
        assert "voice" in s.known_channels

    def test_register_channel_idempotent(self):
        s = SessionState(session_id="s-1", primary_channel="web_chat")
        s.register_channel("voice")
        s.register_channel("voice")
        assert len(s.known_channels) == 1

    def test_add_checkpoint(self):
        s = SessionState(session_id="s-1", primary_channel="web_chat")
        s.add_checkpoint("authenticated")
        s.add_checkpoint("identity_verified")
        assert s.checkpoints == ["authenticated", "identity_verified"]

    def test_escalated_defaults_false(self):
        s = SessionState(session_id="s-1", primary_channel="web_chat")
        assert s.escalated is False

    def test_escalated_can_be_set(self):
        s = SessionState(session_id="s-1", primary_channel="web_chat", escalated=True)
        assert s.escalated is True
