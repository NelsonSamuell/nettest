"""Profile behaviour. self needs nothing; engagement gates everything."""

from datetime import date

import pytest
import yaml

from netcheck.authorisation import check_scope, confirm_segment
from netcheck.authorisation import load as load_authorisation
from netcheck.budget import Budget
from netcheck.cli import main
from netcheck.profile import ENGAGEMENT, SELF, ConfigError, parse_profile

VALID = {
    "client": "Example Ltd",
    "engagement": "Internal network assessment",
    "authorised_by": "Jane Mwangi, Head of Infrastructure",
    "contact": "jane@example.co.ke",
    "issued": date(2026, 9, 1),
    "expires": date(2026, 9, 14),
    "segment": "Floor 3 user VLAN, patch panel port 3-14",
    "scope_subnets": ["192.0.2.0/24"],
}
IN_WINDOW = date(2026, 9, 7)


def write(tmp_path, document, name="authorisation.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    return path


def test_self_is_the_default_and_needs_no_authorisation_file():
    profile = parse_profile(None)
    assert profile.name == SELF
    assert not profile.requires_authorisation
    assert profile.allows_all_tests
    assert not profile.budgets_are_ceilings


def test_a_self_report_says_it_is_not_a_deliverable():
    assert "not a client deliverable" in parse_profile(SELF).header()
    assert parse_profile(ENGAGEMENT).header() == "profile: engagement"


def test_an_unknown_profile_is_rejected():
    with pytest.raises(ConfigError):
        parse_profile("holiday")


def test_engagement_without_an_authorisation_file_exits_2(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["probe", "--active", "--profile", "engagement", "--tests", "L3A02"]) == 2


def test_a_valid_file_in_window_loads(tmp_path):
    authorisation = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    assert authorisation.client == "Example Ltd"
    assert len(authorisation.sha256) == 64
    assert authorisation.scope_subnets == ("192.0.2.0/24",)


def test_boundary_days_are_inside_the_window(tmp_path):
    path = write(tmp_path, VALID)
    assert load_authorisation(path, today=date(2026, 9, 1))
    assert load_authorisation(path, today=date(2026, 9, 14))


def test_an_expired_file_is_rejected_and_prints_the_window(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_authorisation(write(tmp_path, VALID), today=date(2026, 9, 15))
    assert "2026-09-01" in str(excinfo.value) and "2026-09-14" in str(excinfo.value)


def test_a_future_dated_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_authorisation(write(tmp_path, VALID), today=date(2026, 8, 31))
    assert "outside its window" in str(excinfo.value)


@pytest.mark.parametrize("field", sorted(VALID))
def test_each_required_field_missing_in_turn_is_a_hard_stop(tmp_path, field):
    document = dict(VALID)
    del document[field]
    with pytest.raises(ConfigError) as excinfo:
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)
    assert field in str(excinfo.value)


@pytest.mark.parametrize("field", ["client", "engagement", "authorised_by", "contact", "segment"])
def test_an_empty_field_is_a_hard_stop(tmp_path, field):
    document = dict(VALID)
    document[field] = "   "
    with pytest.raises(ConfigError):
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)


def test_an_empty_scope_list_is_a_hard_stop(tmp_path):
    document = dict(VALID)
    document["scope_subnets"] = []
    with pytest.raises(ConfigError):
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)


def test_a_reversed_window_is_rejected(tmp_path):
    document = dict(VALID)
    document["issued"], document["expires"] = document["expires"], document["issued"]
    with pytest.raises(ConfigError):
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)


def test_a_target_outside_scope_is_rejected(tmp_path):
    authorisation = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    check_scope(authorisation, ["192.0.2.0/25"])
    with pytest.raises(ConfigError) as excinfo:
        check_scope(authorisation, ["198.51.100.0/24"])
    assert "outside the authorised scope" in str(excinfo.value)


def test_a_supernet_of_the_scope_is_also_rejected(tmp_path):
    """No wildcards and no supernet matching: containment must be exact."""
    authorisation = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    with pytest.raises(ConfigError):
        check_scope(authorisation, ["192.0.0.0/16"])


def test_segment_confirmation_must_match_exactly(tmp_path):
    authorisation = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    confirm_segment(authorisation, supplied=VALID["segment"])
    with pytest.raises(ConfigError):
        confirm_segment(authorisation, supplied=VALID["segment"] + " ")
    with pytest.raises(ConfigError):
        confirm_segment(authorisation, supplied="Floor 4")


def test_segment_confirmation_prompts_when_not_supplied(tmp_path):
    authorisation = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    printed = []
    confirm_segment(authorisation, prompt=lambda _: VALID["segment"], out=printed.append)
    assert any(VALID["segment"] in line for line in printed)
    with pytest.raises(ConfigError):
        confirm_segment(authorisation, prompt=lambda _: "wrong", out=printed.append)


def test_all_is_rejected_in_engagement(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = write(tmp_path, VALID)
    code = main(
        ["probe", "--active", "--profile", "engagement", "--authorisation", str(path), "--all"]
    )
    assert code == 2


def test_a_budget_raised_above_the_default_is_rejected_in_engagement():
    profile = parse_profile(ENGAGEMENT)
    with pytest.raises(ConfigError) as excinfo:
        Budget.resolve(profile, packet_budget=99999)
    assert "ceilings" in str(excinfo.value)


def test_a_budget_lowered_is_accepted_in_engagement():
    budget = Budget.resolve(parse_profile(ENGAGEMENT), packet_budget=100)
    assert budget.packets == 100


def test_a_budget_raised_is_accepted_in_self():
    assert Budget.resolve(parse_profile(SELF), packet_budget=99999).packets == 99999


def test_tests_are_required_unless_all_is_given(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["probe", "--active"]) == 2


def test_probe_without_active_exits_2(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["probe", "--tests", "L3A02"]) == 2
