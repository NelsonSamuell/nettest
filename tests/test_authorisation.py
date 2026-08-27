from datetime import date

import pytest
import yaml

from l2check import authorisation
from l2check.authorisation import (
    ActiveSession,
    AuthorisationError,
    NotAuthorised,
    confirm_segment,
    load_authorisation,
    parse_tests,
    validate_max_macs,
)

VALID = {
    "client": "Example Ltd",
    "engagement": "Internal network assessment",
    "authorised_by": "Jane Mwangi, Head of Infrastructure",
    "contact": "jane@example.co.ke",
    "issued": date(2026, 9, 1),
    "expires": date(2026, 9, 14),
    "segment": "Floor 3 user VLAN, patch panel port 3-14",
    "change_window": True,
}

IN_WINDOW = date(2026, 9, 7)


def write(tmp_path, document, name="authorisation.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    return path


def test_valid_file_in_window_loads(tmp_path):
    auth = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    assert auth.client == "Example Ltd"
    assert auth.segment == "Floor 3 user VLAN, patch panel port 3-14"
    assert auth.change_window is True
    assert len(auth.sha256) == 64


def test_shipped_example_file_matches_the_required_fields():
    document = yaml.safe_load(open("examples/authorisation.example.yaml").read())
    assert set(document) == set(authorisation.REQUIRED_FIELDS)


def test_sha256_is_recorded_and_matches_the_file(tmp_path):
    path = write(tmp_path, VALID)
    auth = load_authorisation(path, today=IN_WINDOW)
    assert auth.sha256 == authorisation.file_sha256(path)


def test_boundary_days_are_inside_the_window(tmp_path):
    path = write(tmp_path, VALID)
    assert load_authorisation(path, today=date(2026, 9, 1))
    assert load_authorisation(path, today=date(2026, 9, 14))


def test_expired_file_is_rejected_and_prints_the_window(tmp_path):
    with pytest.raises(AuthorisationError) as excinfo:
        load_authorisation(write(tmp_path, VALID), today=date(2026, 9, 15))
    assert "2026-09-01" in str(excinfo.value)
    assert "2026-09-14" in str(excinfo.value)


def test_future_file_is_rejected(tmp_path):
    with pytest.raises(AuthorisationError) as excinfo:
        load_authorisation(write(tmp_path, VALID), today=date(2026, 8, 31))
    assert "outside its window" in str(excinfo.value)


@pytest.mark.parametrize("field", authorisation.REQUIRED_FIELDS)
def test_each_required_field_missing_in_turn_is_a_hard_stop(tmp_path, field):
    document = dict(VALID)
    del document[field]
    with pytest.raises(AuthorisationError) as excinfo:
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)
    assert field in str(excinfo.value)


@pytest.mark.parametrize("field", ["client", "engagement", "authorised_by", "contact", "segment"])
def test_empty_string_fields_are_rejected(tmp_path, field):
    document = dict(VALID)
    document[field] = "   "
    with pytest.raises(AuthorisationError):
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)


def test_change_window_must_be_a_boolean(tmp_path):
    document = dict(VALID)
    document["change_window"] = "yes please"
    with pytest.raises(AuthorisationError):
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)


def test_dates_must_be_dates(tmp_path):
    document = dict(VALID)
    document["expires"] = "next friday"
    with pytest.raises(AuthorisationError):
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)


def test_reversed_window_is_rejected(tmp_path):
    document = dict(VALID)
    document["issued"], document["expires"] = document["expires"], document["issued"]
    with pytest.raises(AuthorisationError):
        load_authorisation(write(tmp_path, document), today=IN_WINDOW)


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(AuthorisationError):
        load_authorisation(tmp_path / "nope.yaml", today=IN_WINDOW)


def test_non_mapping_file_is_an_error(tmp_path):
    path = tmp_path / "auth.yaml"
    path.write_text("- just\n- a list\n")
    with pytest.raises(AuthorisationError):
        load_authorisation(path, today=IN_WINDOW)


def test_tests_absent_is_a_hard_stop():
    with pytest.raises(AuthorisationError):
        parse_tests(None)


def test_tests_empty_is_a_hard_stop():
    with pytest.raises(AuthorisationError):
        parse_tests("")
    with pytest.raises(AuthorisationError):
        parse_tests("  ,  ,")


def test_tests_must_name_known_probes():
    with pytest.raises(AuthorisationError) as excinfo:
        parse_tests("L2A01,L2A99")
    assert "L2A99" in str(excinfo.value)


def test_tests_are_parsed_deduplicated_and_upper_cased():
    assert parse_tests("l2a01, L2A02 ,L2A01") == ["L2A01", "L2A02"]


def test_segment_confirmation_accepts_an_exact_match(tmp_path):
    auth = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    confirm_segment(auth, supplied=VALID["segment"])


def test_segment_confirmation_mismatch_is_rejected(tmp_path):
    auth = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    with pytest.raises(AuthorisationError):
        confirm_segment(auth, supplied="Floor 3 user VLAN, patch panel port 3-15")
    with pytest.raises(AuthorisationError):
        confirm_segment(auth, supplied=VALID["segment"] + " ")


def test_segment_confirmation_prompts_when_not_supplied(tmp_path):
    auth = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    printed = []
    confirm_segment(auth, prompt=lambda _: VALID["segment"], out=printed.append)
    assert any(VALID["segment"] in line for line in printed)

    with pytest.raises(AuthorisationError):
        confirm_segment(auth, prompt=lambda _: "wrong port", out=printed.append)


def test_max_macs_bounds():
    assert validate_max_macs(50) == 50
    assert validate_max_macs(500) == 500
    with pytest.raises(AuthorisationError):
        validate_max_macs(501)
    with pytest.raises(AuthorisationError):
        validate_max_macs(0)


def test_session_refuses_to_send_before_the_gate_passes():
    sent = []
    session = ActiveSession(interface="lo", sender=lambda iface, frame: sent.append(frame))
    with pytest.raises(NotAuthorised):
        session.send(b"\x00" * 60)
    assert sent == []


def test_session_sends_once_authorised(tmp_path):
    auth = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    sent = []
    session = ActiveSession(interface="lo", sender=lambda iface, frame: sent.append(frame))
    session.authorise(auth, ["L2A01"])
    assert session.send(b"\x00" * 60) == 1
    assert session.frames_sent == 1
    assert len(sent) == 1


def test_session_refuses_an_empty_test_list(tmp_path):
    auth = load_authorisation(write(tmp_path, VALID), today=IN_WINDOW)
    session = ActiveSession(interface="lo", sender=lambda iface, frame: None)
    with pytest.raises(AuthorisationError):
        session.authorise(auth, [])
