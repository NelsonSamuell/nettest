"""Report rendering: the Markdown writer and the diff between two runs."""

from netcheck import report
from netcheck.models import ABSENT, Posture
from netcheck.profile import parse_profile




def test_markdown_carries_the_run_the_posture_and_the_findings():
    from netcheck.models import Finding

    board = Posture.new()
    board.set("BPDU Guard", ABSENT, "L2A02", "no reaction")
    findings = [Finding("HIGH", "L2A02", "BPDU Guard is not enforcing", "enabling it")]
    document = report.to_dict(board, findings, parse_profile("self"))
    text = report.to_markdown(document, board, findings)

    assert text.startswith("# netcheck report")
    assert "not a client deliverable" in text
    assert "## Posture" in text and "## Findings" in text
    assert "BPDU Guard" in text and "L2A02" in text
    assert "enabling it" in text
    assert "| Control | State | Basis | Detail |" in text


def test_markdown_groups_controls_by_layer():
    board = Posture.new()
    text = report.to_markdown(report.to_dict(board, [], parse_profile("self")), board, [])
    assert "### layer 2" in text and "### layer 3" in text and "### this host" in text


def test_markdown_says_so_when_nothing_was_found():
    board = Posture.new()
    text = report.to_markdown(report.to_dict(board, [], parse_profile("self")), board, [])
    assert "Nothing observed." in text


def test_markdown_records_an_engagement_profile_and_its_hash():
    board = Posture.new()
    document = report.to_dict(board, [], parse_profile("engagement"))
    document["authorisation"] = {"file": "auth.yaml", "sha256": "abc123"}
    text = report.to_markdown(document, board, [])
    assert "Profile: engagement" in text
    assert "abc123" in text
    assert "not a client deliverable" not in text


def test_markdown_renders_the_reachability_matrix():
    board = Posture.new()
    document = report.to_dict(board, [], parse_profile("self"))
    document["reachability"] = {"guest>lan": "reachable", "lan>guest": "untested",
                                "guest>guest": "untested", "lan>lan": "untested"}
    text = report.to_markdown(document, board, [])
    assert "## Reachability" in text and "reachable" in text


def test_diff_reports_a_changed_control():
    before = report.to_dict(Posture.new(), [], parse_profile("self"))
    board = Posture.new()
    board.set("BPDU Guard", ABSENT, "L2A02", "no reaction")
    after = report.to_dict(board, [], parse_profile("self"))
    text = report.diff(before, after)
    assert "BPDU Guard" in text and "UNTESTED -> ABSENT" in text


def test_diff_reports_new_and_gone_findings():
    from netcheck.models import Finding

    board = Posture.new()
    before = report.to_dict(board, [Finding("HIGH", "L2P02", "old", "")], parse_profile("self"))
    after = report.to_dict(board, [Finding("HIGH", "L2P09", "new", "")], parse_profile("self"))
    text = report.diff(before, after)
    assert "+ L2P09" in text and "- L2P02" in text and "gone" in text


def test_diff_says_nothing_changed_when_nothing_did():
    document = report.to_dict(Posture.new(), [], parse_profile("self"))
    assert "nothing changed" in report.diff(document, document)
