from l2check import posture, report
from l2check.models import Capture, Finding
from l2check.posture import ABSENT, PRESENT, Posture
from l2check.session import Budget


def board_with_both_layers():
    board = Posture.new(posture.WIRED)
    board.set(posture.BPDU_GUARD, ABSENT, "L2P03 passive", "BPDUs reached the port")
    board.set(posture.DHCP_SNOOPING, PRESENT, "L2A04 active probe", "one server")
    return board


def test_layers_filter_the_control_table():
    board = board_with_both_layers()
    l2_only = report.posture_table(board, layers="l2")
    assert posture.BPDU_GUARD in l2_only
    assert posture.EGRESS_FILTERING not in l2_only
    l3_only = report.posture_table(board, layers="l3")
    assert posture.EGRESS_FILTERING in l3_only
    assert posture.BPDU_GUARD not in l3_only


def test_layer_grouping_uses_membership_not_the_basis_text():
    """An untested L3 control has an L2-looking basis and must still group as L3."""
    board = board_with_both_layers()
    assert board.controls[posture.EGRESS_FILTERING].basis == "probe not selected"
    assert posture.EGRESS_FILTERING in report.posture_table(board, layers="l3")
    # A common control stays at layer 2 even when an L3 check set its basis.
    board.set(posture.CLIENT_ISOLATION, ABSENT, "L3A09 active check")
    assert posture.CLIENT_ISOLATION in report.posture_table(board, layers="l2")


def test_both_layers_groups_them():
    text = report.posture_table(board_with_both_layers(), layers="both")
    assert "layer 2:" in text and "layer 3:" in text


def test_the_matrix_and_devices_are_empty_until_layer_three_runs():
    assert "no segment pairs tested" in report.reachability_matrix(None)
    assert "none correlated" in report.device_table([])


def test_the_matrix_renders_when_there_is_data():
    matrix = {("guest", "lan"): "filtered", ("lan", "guest"): "reachable"}
    text = report.reachability_matrix(matrix)
    assert "guest" in text and "filtered" in text and "reachable" in text


def test_device_table_renders_an_inventory():
    text = report.device_table(
        [{"macs": ["aa:bb:cc:dd:ee:01"], "ipv4": ["192.168.1.5"], "oui_vendor": "Acme"}]
    )
    assert "aa:bb:cc:dd:ee:01" in text and "192.168.1.5" in text and "Acme" in text


def test_render_omits_the_new_sections_when_they_are_empty():
    board = board_with_both_layers()
    text = report.render(board, [])
    assert "REACHABILITY" not in text
    assert "CONTROL" in text


def test_budget_balance_reaches_the_json():
    budget = Budget(frames=600, packets=5000)
    budget.spend(2, 10)
    budget.spend(3, 250)
    document = report.to_dict(Posture.new(), [], budget=budget)
    assert document["budget"]["frames_remaining"] == 590
    assert document["budget"]["packets_remaining"] == 4750
    assert document["budget"]["packets_sent"] == 250


def test_packets_seen_sits_next_to_frames_seen():
    capture = Capture(interface="wlan0", duration=5)
    capture.frames_seen = 100
    capture.packets_seen = 80
    document = report.to_dict(Posture.new(), [], capture=capture)
    assert document["capture"]["frames_seen"] == 100
    assert document["capture"]["packets_seen"] == 80


def test_markdown_carries_the_same_content():
    board = board_with_both_layers()
    findings = [Finding("HIGH", "L2P03", "BPDUs received on the port")]
    document = report.to_dict(board, findings)
    text = report.to_markdown(document, board, findings)
    assert text.startswith("# netcheck report")
    assert posture.BPDU_GUARD in text
    assert "L2P03" in text
    assert "| Control | State | Basis |" in text


def test_markdown_says_so_when_nothing_was_found():
    board = Posture.new()
    assert "Nothing observed." in report.to_markdown(report.to_dict(board, []), board, [])


def test_diff_reports_a_changed_control():
    before = report.to_dict(Posture.new(posture.WIRED), [])
    board = board_with_both_layers()
    after = report.to_dict(board, [])
    text = report.diff(before, after)
    assert "%s" % posture.BPDU_GUARD in text
    assert "UNTESTED -> ABSENT" in text
    assert "UNTESTED -> PRESENT" in text


def test_diff_reports_new_and_gone_findings():
    board = Posture.new()
    before = report.to_dict(board, [Finding("HIGH", "L2P02", "old thing")])
    after = report.to_dict(board, [Finding("HIGH", "L2P09", "new thing")])
    text = report.diff(before, after)
    assert "+ L2P09" in text
    assert "- L2P02" in text and "gone" in text


def test_diff_says_nothing_changed_when_nothing_did():
    document = report.to_dict(board_with_both_layers(), [])
    assert "nothing changed" in report.diff(document, document)


def test_diff_notices_a_control_that_appeared():
    before = report.to_dict(Posture.new(posture.WIRELESS), [])
    after = report.to_dict(Posture.new(posture.WIRED), [])
    text = report.diff(before, after)
    assert "new control" in text
    assert "no longer reported" in text
