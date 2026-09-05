"""The posture model. UNTESTED never becomes a pass."""

import pytest

from netcheck.models import (
    ABSENT,
    BUDGET_EXHAUSTED,
    CONTROL_TABLE,
    HOST,
    INDETERMINATE,
    L2,
    L3,
    NOT_SELECTED,
    PRESENT,
    UNTESTED,
    Posture,
)


def test_a_new_posture_is_entirely_untested_with_a_reason():
    posture = Posture.new()
    assert len(posture.controls) == len(CONTROL_TABLE) == 24
    for control in posture.controls.values():
        assert control.state == UNTESTED
        assert control.detail == NOT_SELECTED
    assert posture.counts()[UNTESTED] == 24
    assert posture.exit_code() == 0


def test_untested_and_absent_never_collapse_into_each_other():
    posture = Posture.new()
    assert posture.counts()[ABSENT] == 0
    posture.set("BPDU Guard", ABSENT, "L2A02", "no reaction")
    assert posture.counts()[ABSENT] == 1
    assert posture.counts()[UNTESTED] == 23
    assert posture.exit_code() == 1


def test_an_unselected_check_yields_untested():
    posture = Posture.new()
    assert posture.controls["Port Security"].state == UNTESTED
    assert posture.controls["Port Security"].detail == NOT_SELECTED


def test_budget_exhausted_yields_untested_not_absent():
    posture = Posture.new()
    posture.set("Egress filtering", UNTESTED, "L3A07", BUDGET_EXHAUSTED)
    control = posture.controls["Egress filtering"]
    assert control.state == UNTESTED
    assert control.state != ABSENT
    assert control.detail == BUDGET_EXHAUSTED


def test_controls_carry_their_layer():
    posture = Posture.new()
    assert len(posture.by_layer(L2)) == 12
    assert len(posture.by_layer(L3)) == 11
    assert len(posture.by_layer(HOST)) == 1
    assert posture.controls["ICMP redirect handling"].layer == HOST


def test_an_unknown_control_or_state_is_rejected():
    posture = Posture.new()
    with pytest.raises(KeyError):
        posture.set("Imaginary Guard", PRESENT, "L9A99")
    with pytest.raises(ValueError):
        posture.set("BPDU Guard", "MAYBE", "L2A02")


def test_every_control_names_the_checks_that_establish_it():
    for name, _, checks in CONTROL_TABLE:
        assert checks, "%s has no establishing check" % name
        for identifier in checks:
            assert identifier[:3] in ("L2P", "L2A", "L3P", "L3A", "CFG")


def test_a_posture_survives_a_round_trip():
    posture = Posture.new()
    posture.set("DHCP Snooping", INDETERMINATE, "L2A04", "no offer")
    restored = Posture.from_dict(posture.as_dict())
    assert restored.counts() == posture.counts()
    assert restored.controls["DHCP Snooping"].state == INDETERMINATE
    assert restored.controls["DHCP Snooping"].layer == L2
