"""D9: the steer-chat depth control actually bounds the turn's tool loop."""
from nexus.langgraph.context_loop import load_loop_budget


def test_budget_rounds_override_is_clamped():
    default = load_loop_budget()
    assert default.rounds >= 1
    assert load_loop_budget(6).rounds == 6
    # The control cannot raise the ceiling the env var enforces.
    assert load_loop_budget(999).rounds == 30
    assert load_loop_budget(0).rounds == default.rounds
    assert load_loop_budget(-3).rounds == default.rounds
    # Only rounds moves; the other limits keep their defaults.
    assert load_loop_budget(6).calls == default.calls
    assert load_loop_budget(6).seconds == default.seconds
