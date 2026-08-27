from l2check import wireless
from l2check.wireless import OPEN, WEP, WPA, WPA2, WPA2_WPA3, WPA3, parse_scan_dump

WPA2_PSK = """BSS 00:00:5e:00:53:01(on wlan0) -- associated
\tTSF: 1234567890 usec
\tfreq: 2412.0
\tcapability: ESS Privacy ShortSlotTime RadioMeasure (0x1411)
\tSSID: Example Home
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)
\tWMM:\t * Parameter version 1
"""

WPA3_SAE = WPA2_PSK.replace(
    "* Authentication suites: PSK", "* Authentication suites: SAE"
).replace("(0x000c)", "(0x00cc)")

TRANSITION = WPA2_PSK.replace(
    "* Authentication suites: PSK", "* Authentication suites: PSK SAE"
).replace("(0x000c)", "(0x008c)")

TKIP = WPA2_PSK.replace("* Pairwise ciphers: CCMP", "* Pairwise ciphers: TKIP CCMP")

OPEN_NETWORK = """BSS 00:11:22:33:44:55(on wlan0) -- associated
\tcapability: ESS ShortSlotTime (0x0401)
\tSSID: Coffee Shop
"""

WEP_NETWORK = """BSS 00:11:22:33:44:55(on wlan0) -- associated
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tSSID: Old Router
"""

WPA1_NETWORK = """BSS 00:11:22:33:44:55(on wlan0) -- associated
\tcapability: ESS Privacy (0x0411)
\tSSID: Ancient
\tWPA:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: TKIP
\t\t * Authentication suites: PSK
"""

WITH_WPS = WPA2_PSK.replace("\tWMM:", "\tWPS:\t * Version: 1.0\n\tWMM:")

NOT_ASSOCIATED = """BSS aa:bb:cc:dd:ee:ff(on wlan0)
\tcapability: ESS Privacy (0x0411)
\tSSID: Someone Else
"""


def test_wpa2_psk_is_recognised():
    link = parse_scan_dump(WPA2_PSK, "wlan0")
    assert link.security == WPA2
    assert link.ssid == "Example Home"
    assert link.bssid == "00:00:5e:00:53:01"
    assert link.auth_suites == ["PSK"]
    assert link.pairwise_ciphers == ["CCMP"]
    assert link.group_cipher == "CCMP"
    assert link.encrypted


def test_pmf_bits_are_read_from_the_rsn_capabilities():
    absent = parse_scan_dump(WPA2_PSK, "wlan0")
    assert not absent.pmf_capable
    assert not absent.pmf_required

    required = parse_scan_dump(WPA3_SAE, "wlan0")
    assert required.pmf_capable
    assert required.pmf_required

    capable_only = parse_scan_dump(TRANSITION, "wlan0")
    assert capable_only.pmf_capable
    assert not capable_only.pmf_required


def test_wpa3_and_transition_mode():
    assert parse_scan_dump(WPA3_SAE, "wlan0").security == WPA3
    assert parse_scan_dump(TRANSITION, "wlan0").security == WPA2_WPA3


def test_open_and_wep_are_not_treated_as_encrypted():
    open_link = parse_scan_dump(OPEN_NETWORK, "wlan0")
    assert open_link.security == OPEN
    assert not open_link.privacy
    assert not open_link.encrypted

    wep_link = parse_scan_dump(WEP_NETWORK, "wlan0")
    assert wep_link.security == WEP
    assert wep_link.privacy
    assert not wep_link.encrypted


def test_wpa1_is_recognised_separately_from_wpa2():
    link = parse_scan_dump(WPA1_NETWORK, "wlan0")
    assert link.security == WPA
    assert link.encrypted


def test_weak_cipher_is_reported():
    assert parse_scan_dump(TKIP, "wlan0").weak_cipher == "TKIP"
    assert parse_scan_dump(WPA2_PSK, "wlan0").weak_cipher == ""
    assert parse_scan_dump(WPA1_NETWORK, "wlan0").weak_cipher == "TKIP"


def test_wps_is_detected():
    assert parse_scan_dump(WITH_WPS, "wlan0").wps
    assert not parse_scan_dump(WPA2_PSK, "wlan0").wps


def test_an_unassociated_dump_yields_nothing():
    assert parse_scan_dump(NOT_ASSOCIATED, "wlan0") is None
    assert parse_scan_dump("", "wlan0") is None


def test_read_link_returns_none_for_a_wired_interface():
    assert wireless.read_link("lo", runner=lambda iface: WPA2_PSK) is None


def test_read_link_survives_iw_being_absent(monkeypatch):
    monkeypatch.setattr(wireless, "is_wireless", lambda iface: True)

    def missing(iface):
        raise FileNotFoundError("iw")

    assert wireless.read_link("wlan0", runner=missing) is None
    assert wireless.read_link("wlan0", runner=lambda iface: "") is None


def test_read_link_parses_when_wireless(monkeypatch):
    monkeypatch.setattr(wireless, "is_wireless", lambda iface: True)
    link = wireless.read_link("wlan0", runner=lambda iface: WPA2_PSK)
    assert link.security == WPA2
