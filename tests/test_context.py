"""Tests for enterprise_rag_patterns.context — ContextEnvelope and ContextSource."""

from enterprise_rag_patterns.context import ContextEnvelope, ContextSource


class TestContextSource:
    def test_required_defaults_true(self):
        src = ContextSource(name="crm")
        assert src.required is True

    def test_freshness_defaults_none(self):
        src = ContextSource(name="kb")
        assert src.freshness_seconds is None

    def test_fields_stored(self):
        src = ContextSource(name="erp", freshness_seconds=60, required=False)
        assert src.name == "erp"
        assert src.freshness_seconds == 60
        assert src.required is False


class TestContextEnvelope:
    def _env(self):
        return ContextEnvelope(session_id="s-1", channel="web_chat")

    def test_add_and_retrieve_fact(self):
        env = self._env()
        env.add_fact("student_name", "Jane Doe")
        assert env.facts["student_name"] == "Jane Doe"

    def test_add_fact_overwrites(self):
        env = self._env()
        env.add_fact("key", "v1")
        env.add_fact("key", "v2")
        assert env.facts["key"] == "v2"

    def test_source_names_empty(self):
        env = self._env()
        assert env.source_names() == []

    def test_source_names_returns_names(self):
        env = self._env()
        env.sources.append(ContextSource(name="crm"))
        env.sources.append(ContextSource(name="erp"))
        assert env.source_names() == ["crm", "erp"]

    def test_initial_facts_empty(self):
        env = self._env()
        assert env.facts == {}

    def test_session_id_and_channel_stored(self):
        env = ContextEnvelope(session_id="sess-42", channel="voice")
        assert env.session_id == "sess-42"
        assert env.channel == "voice"
