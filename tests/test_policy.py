"""Tests for enterprise_rag_patterns.policy — ActionPolicy and EscalationRule."""

from enterprise_rag_patterns.policy import ActionPolicy, EscalationRule


class TestEscalationRule:
    def test_fields_stored(self):
        rule = EscalationRule(name="pii_detected", reason="Response contains student PII")
        assert rule.name == "pii_detected"
        assert rule.reason == "Response contains student PII"


class TestActionPolicy:
    def test_can_run_allowed_action(self):
        policy = ActionPolicy(allowed_actions={"search_kb", "fetch_record"})
        assert policy.can_run("search_kb") is True

    def test_cannot_run_disallowed_action(self):
        policy = ActionPolicy(allowed_actions={"search_kb"})
        assert policy.can_run("delete_record") is False

    def test_empty_allowed_actions(self):
        policy = ActionPolicy()
        assert policy.can_run("anything") is False

    def test_escalation_rules_stored(self):
        rule = EscalationRule(name="out_of_scope", reason="Topic outside enrollment domain")
        policy = ActionPolicy(escalation_rules=[rule])
        assert len(policy.escalation_rules) == 1
        assert policy.escalation_rules[0].name == "out_of_scope"

    def test_multiple_allowed_actions(self):
        actions = {"a", "b", "c"}
        policy = ActionPolicy(allowed_actions=actions)
        for action in actions:
            assert policy.can_run(action) is True
        assert policy.can_run("d") is False
