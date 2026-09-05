"""The hard limits. A profile changes what is adjustable, never what is permitted."""

import ast
import pathlib

import pytest

from netcheck.budget import (
    LAYER2,
    LAYER3,
    MAX_MACS_HARD_CAP,
    RATE_HARD_CAP,
    Budget,
    CapExceeded,
    validate_max_macs,
    validate_rate,
)
from netcheck.profile import ENGAGEMENT, SELF, ConfigError, parse_profile

SOURCE = pathlib.Path("netcheck")


@pytest.mark.parametrize("name", [SELF, ENGAGEMENT])
def test_the_rate_hard_cap_cannot_be_exceeded_in_either_profile(name):
    with pytest.raises(ConfigError):
        Budget.resolve(parse_profile(name), rate_pps=RATE_HARD_CAP + 1)
    with pytest.raises(ConfigError):
        validate_rate(RATE_HARD_CAP + 1)


def test_self_may_raise_the_rate_to_the_hard_cap():
    budget = Budget.resolve(parse_profile(SELF), rate_pps=RATE_HARD_CAP)
    assert budget.rate_pps == RATE_HARD_CAP


def test_engagement_caps_the_rate_at_the_default_not_the_hard_cap():
    """Two limits stack: the hard cap, and the profile's own ceiling below it."""
    profile = parse_profile(ENGAGEMENT)
    assert Budget.resolve(profile, rate_pps=50).rate_pps == 50
    with pytest.raises(ConfigError) as excinfo:
        Budget.resolve(profile, rate_pps=RATE_HARD_CAP)
    assert "ceilings" in str(excinfo.value)


def test_the_rate_cap_is_enforced_in_code_not_in_help_text():
    text = (SOURCE / "budget.py").read_text()
    assert "RATE_HARD_CAP = %d" % RATE_HARD_CAP in text
    tree = ast.parse((SOURCE / "cli.py").read_text())
    names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "validate_max_macs" in names


def test_a_rate_below_one_is_rejected():
    with pytest.raises(ConfigError):
        validate_rate(0)


def test_max_macs_above_the_hard_cap_is_rejected():
    assert validate_max_macs(MAX_MACS_HARD_CAP) == MAX_MACS_HARD_CAP
    with pytest.raises(ConfigError) as excinfo:
        validate_max_macs(MAX_MACS_HARD_CAP + 1)
    assert str(MAX_MACS_HARD_CAP) in str(excinfo.value)
    with pytest.raises(ConfigError):
        validate_max_macs(0)


def test_the_two_budgets_are_enforced_independently():
    budget = Budget(frames=5, packets=10)
    budget.spend(LAYER2, 5)
    with pytest.raises(CapExceeded):
        budget.spend(LAYER2, 1)
    assert budget.spend(LAYER3, 10) is None
    with pytest.raises(CapExceeded):
        budget.spend(LAYER3, 1)


def test_a_batch_that_would_overshoot_spends_nothing():
    budget = Budget(frames=4)
    with pytest.raises(CapExceeded):
        budget.spend(LAYER2, 5)
    assert budget.frames_sent == 0


def test_exhaustion_is_reported_per_layer():
    budget = Budget(frames=1, packets=1)
    budget.spend(LAYER2, 1)
    assert budget.exhausted(LAYER2)
    assert not budget.exhausted(LAYER3)


def test_the_runtime_cap_exists_and_is_carried_in_the_budget():
    assert Budget().runtime_seconds == 15 * 60
    assert Budget.resolve(parse_profile(SELF), runtime_minutes=30).runtime_seconds == 1800
    with pytest.raises(ConfigError):
        Budget.resolve(parse_profile(ENGAGEMENT), runtime_minutes=30)


def test_a_budget_exhausted_check_is_skipped_not_reported_absent():
    from netcheck.models import BUDGET_EXHAUSTED, Posture
    from netcheck.platform.detect import CapabilitySet
    from netcheck.registry import Check, Registry, skipped_controls

    registry = Registry()
    registry.register(Check("L3A02", "TCP inventory", ("Egress filtering",)))
    budget = Budget(packets=1)
    budget.spend(LAYER3, 1)
    runnable, skipped = registry.resolve(["L3A02"], CapabilitySet(), budget)
    assert runnable == []
    assert skipped[0].reason == BUDGET_EXHAUSTED

    posture = Posture.new()
    skipped_controls(skipped, registry, posture)
    assert posture.controls["Egress filtering"].state == "UNTESTED"


def test_no_module_sends_before_the_profile_gate_has_passed():
    """No check package exists yet, and nothing outside it may reach the wire."""
    senders = {"sendp", "sr", "sr1", "srp", "srp1", "sendpfast"}
    for path in SOURCE.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = {alias.name.split(".")[0] for alias in node.names}
                assert not (names & senders), "%s imports a sender" % path
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in senders, "%s calls %s" % (path, node.func.id)


def test_the_forbidden_techniques_appear_nowhere_in_the_source():
    """The hard limits are a promise about what code exists, not about flags."""
    banned = ("deauth", "monitor_mode", "handshake", "password_list", "brute")
    for path in SOURCE.rglob("*.py"):
        lowered = path.read_text().lower()
        for needle in banned:
            assert needle not in lowered, "%s mentions %s" % (path, needle)
