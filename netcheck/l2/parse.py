"""Layer 2 passive parsers.

Protocol metadata only. Nothing here returns, copies or retains the payload of a
frame that is not to or from this interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scapy.contrib.cdp import (
    CDPMsgDeviceID,
    CDPMsgMgmtAddr,
    CDPMsgNativeVLAN,
    CDPMsgPlatform,
    CDPMsgPortID,
    CDPMsgSoftwareVersion,
    CDPMsgVTPMgmtDomain,
    CDPv2_HDR,
)
from scapy.contrib.dtp import DTP, DTPDomain, DTPStatus
from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUManagementAddress,
    LLDPDUPortID,
    LLDPDUSystemDescription,
    LLDPDUSystemName,
)
from scapy.contrib.vtp import VTP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.hsrp import HSRP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, IPv6
from scapy.layers.l2 import ARP, STP, Dot1Q, Ether
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.netbios import NBNSQueryRequest
from scapy.layers.snmp import SNMP
from scapy.layers.vrrp import VRRP, VRRPv3
from scapy.packet import Packet

GLBP_PORT = 3222
LLMNR_PORT = 5355
MDNS_PORT = 5353
NBNS_PORT = 137
SSDP_PORT = 1900
WSD_PORT = 3702

# The low nibble of the DTP status TLV carries the negotiation mode; bit 7 is
# set once the port is operationally trunking.
DTP_MODES = {
    0x01: "access",
    0x02: "trunk, no negotiate",
    0x03: "dynamic desirable",
    0x04: "dynamic auto",
}

CLEARTEXT_TCP = {21: "FTP", 23: "Telnet"}
CLEARTEXT_UDP = {69: "TFTP"}

DEFAULT_BRIDGE_PRIORITY = 32768

# A busy segment produces millions of frames. Records deduplicate on their own
# contents and then cap, because findings are built from the distinct facts
# observed and never from how many times each recurred.
MAX_RECORDS = 2000


@dataclass
class Discovery:
    protocol: str
    source_mac: str
    device_id: str = ""
    platform: str = ""
    software: str = ""
    port_id: str = ""
    native_vlan: int | None = None
    management_address: str = ""
    vtp_domain: str = ""


@dataclass
class Trunking:
    source_mac: str
    mode: str
    domain: str = ""


@dataclass
class Bpdu:
    source_mac: str
    root_priority: int
    root_mac: str
    root_path_cost: int
    bridge_priority: int
    bridge_mac: str

    @property
    def root_priority_is_default(self) -> bool:
        return self.root_priority // 4096 * 4096 == DEFAULT_BRIDGE_PRIORITY


@dataclass
class Vtp:
    source_mac: str
    domain: str
    revision: int


@dataclass
class Tagged:
    source_mac: str
    vlan: int


@dataclass
class DhcpServer:
    server_mac: str
    server_ip: str


@dataclass
class Arp:
    source_mac: str
    claimed_ip: str
    gratuitous: bool


@dataclass
class NameQuery:
    protocol: str
    source_mac: str
    query_name: str


@dataclass
class Fhrp:
    """A first hop redundancy advertisement.

    There is deliberately no field for the authentication value. Whether one is
    present is a finding; the value is a credential and is never recorded.
    """

    protocol: str
    source_mac: str
    group: int | None
    priority: int | None
    virtual_ip: str
    authenticated: bool


@dataclass
class Cleartext:
    protocol: str
    source: str
    destination: str


@dataclass
class RouterAdvert:
    source_mac: str
    source_ip: str
    prefix: str
    managed: bool
    lifetime: int


@dataclass
class ServiceAnnouncement:
    protocol: str
    source_mac: str
    service_type: str


@dataclass
class Capture:
    interface: str = ""
    duration: int = 0
    frames_seen: int = 0
    parse_errors: int = 0
    gratuitous_arps: int = 0
    truncated: set = field(default_factory=set)
    discovery: list = field(default_factory=list)
    trunking: list = field(default_factory=list)
    bpdu: list = field(default_factory=list)
    vtp: list = field(default_factory=list)
    tagged: list = field(default_factory=list)
    dhcp_servers: list = field(default_factory=list)
    arp: list = field(default_factory=list)
    names: list = field(default_factory=list)
    fhrp: list = field(default_factory=list)
    cleartext: list = field(default_factory=list)
    router_adverts: list = field(default_factory=list)
    services: list = field(default_factory=list)
    _seen: set = field(default_factory=set, repr=False)

    def add(self, name: str, record) -> bool:
        """Store a record unless it duplicates one held or the cap is reached."""
        from dataclasses import astuple

        sink = getattr(self, name)
        key = (name,) + astuple(record)
        if key in self._seen:
            return False
        if len(sink) >= MAX_RECORDS:
            self.truncated.add(name)
            return False
        self._seen.add(key)
        sink.append(record)
        return True

    def observed_root_priority(self) -> int | None:
        """The best root priority seen. L2A02 refuses to run without this."""
        if not self.bpdu:
            return None
        return min(record.root_priority for record in self.bpdu)

    def management_address(self) -> str:
        """A switch management address disclosed by L2P01, if any."""
        for record in self.discovery:
            if record.management_address:
                return record.management_address
        return ""

    def observed_ips(self) -> set[str]:
        found = {r.claimed_ip for r in self.arp}
        found |= {r.server_ip for r in self.dhcp_servers}
        found |= {r.virtual_ip for r in self.fhrp}
        found |= {r.management_address for r in self.discovery}
        return {address for address in found if address}

    def as_dict(self) -> dict:
        return {
            "interface": self.interface,
            "duration": self.duration,
            "frames_seen": self.frames_seen,
            "parse_errors": self.parse_errors,
            "gratuitous_arps": self.gratuitous_arps,
            "truncated": sorted(self.truncated),
            "records": {
                name: len(getattr(self, name))
                for name in (
                    "discovery", "trunking", "bpdu", "vtp", "tagged", "dhcp_servers",
                    "arp", "names", "fhrp", "cleartext", "router_adverts", "services",
                )
            },
        }


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    return "" if value is None else str(value)


def parse_cdp(pkt: Packet) -> Discovery | None:
    """L2P01 via CDP."""
    if CDPv2_HDR not in pkt:
        return None
    record = Discovery(protocol="CDP", source_mac=pkt.src)
    for tlv in pkt[CDPv2_HDR].msg:
        if isinstance(tlv, CDPMsgDeviceID):
            record.device_id = _text(tlv.val)
        elif isinstance(tlv, CDPMsgPlatform):
            record.platform = _text(tlv.val)
        elif isinstance(tlv, CDPMsgSoftwareVersion):
            record.software = _text(tlv.val)
        elif isinstance(tlv, CDPMsgPortID):
            record.port_id = _text(tlv.iface)
        elif isinstance(tlv, CDPMsgNativeVLAN):
            record.native_vlan = int(tlv.vlan)
        elif isinstance(tlv, CDPMsgVTPMgmtDomain):
            record.vtp_domain = _text(tlv.val)
        elif isinstance(tlv, CDPMsgMgmtAddr) and tlv.addr:
            record.management_address = _text(tlv.addr[0].addr)
    return record


def parse_lldp(pkt: Packet) -> Discovery | None:
    """L2P01 via LLDP."""
    if LLDPDU not in pkt:
        return None
    record = Discovery(protocol="LLDP", source_mac=pkt[Ether].src)
    if LLDPDUChassisID in pkt:
        record.device_id = _text(pkt[LLDPDUChassisID].id)
    if LLDPDUSystemName in pkt:
        record.device_id = _text(pkt[LLDPDUSystemName].system_name) or record.device_id
    if LLDPDUSystemDescription in pkt:
        record.software = _text(pkt[LLDPDUSystemDescription].description)
    if LLDPDUPortID in pkt:
        record.port_id = _text(pkt[LLDPDUPortID].id)
    if LLDPDUManagementAddress in pkt:
        address = pkt[LLDPDUManagementAddress].management_address
        if pkt[LLDPDUManagementAddress].management_address_subtype == 1 and len(address) == 4:
            record.management_address = ".".join(str(octet) for octet in address)
    return record


def parse_dtp(pkt: Packet) -> Trunking | None:
    """L2P02."""
    if DTP not in pkt:
        return None
    mode, domain = "unknown", ""
    for tlv in pkt[DTP].tlvlist:
        if isinstance(tlv, DTPStatus) and tlv.status:
            status = tlv.status[0]
            mode = DTP_MODES.get(status & 0x0F, "unknown (0x%02x)" % status)
            if status & 0x80:
                mode = "trunking, " + mode
        elif isinstance(tlv, DTPDomain):
            domain = _text(tlv.domain)
    return Trunking(source_mac=pkt.src, mode=mode, domain=domain)


def parse_bpdu(pkt: Packet) -> Bpdu | None:
    """L2P03. The root priority here is what L2A02 needs to be worse than."""
    if STP not in pkt:
        return None
    stp = pkt[STP]
    return Bpdu(
        source_mac=pkt.src,
        root_priority=int(stp.rootid),
        root_mac=stp.rootmac,
        root_path_cost=int(stp.pathcost),
        bridge_priority=int(stp.bridgeid),
        bridge_mac=stp.bridgemac,
    )


def parse_vtp(pkt: Packet) -> Vtp | None:
    """L2P04."""
    if VTP not in pkt:
        return None
    return Vtp(source_mac=pkt.src, domain=_text(pkt[VTP].domname), revision=int(pkt[VTP].rev))


def parse_tagged(pkt: Packet) -> list[Tagged]:
    """L2P06. One record per 802.1Q tag on the frame."""
    records = []
    layer = pkt.getlayer(Dot1Q)
    while layer is not None:
        records.append(Tagged(source_mac=pkt.src, vlan=int(layer.vlan)))
        layer = layer.payload.getlayer(Dot1Q)
    return records


def parse_dhcp_server(pkt: Packet) -> DhcpServer | None:
    """L2P07."""
    if BOOTP not in pkt or DHCP not in pkt or pkt[BOOTP].op != 2:
        return None
    server_ip = pkt[IP].src if IP in pkt else ""
    for option in pkt[DHCP].options:
        if isinstance(option, tuple) and option[0] == "server_id":
            server_ip = _text(option[1])
    return DhcpServer(server_mac=pkt[Ether].src, server_ip=server_ip)


def parse_arp(pkt: Packet) -> Arp | None:
    """L2P08."""
    if ARP not in pkt:
        return None
    arp = pkt[ARP]
    gratuitous = arp.psrc == arp.pdst and arp.psrc != "0.0.0.0"
    return Arp(source_mac=arp.hwsrc, claimed_ip=arp.psrc, gratuitous=gratuitous)


def parse_name_query(pkt: Packet) -> NameQuery | None:
    """L2P09."""
    if UDP not in pkt:
        return None
    port = pkt[UDP].dport
    if port == NBNS_PORT and NBNSQueryRequest in pkt:
        name = _text(pkt[NBNSQueryRequest].QUESTION_NAME).strip()
        protocol = "WPAD" if name.lower().startswith("wpad") else "NBT-NS"
        return NameQuery(protocol=protocol, source_mac=pkt.src, query_name=name)
    if port not in (LLMNR_PORT, MDNS_PORT):
        return None
    # LLMNR has its own layer class in scapy; mDNS reuses the DNS one.
    dns = pkt[LLMNRQuery] if LLMNRQuery in pkt else pkt[DNS] if DNS in pkt else None
    if dns is None or dns.qr != 0 or dns.qdcount < 1:
        return None
    name = _text(dns.qd[0].qname).rstrip(".")
    protocol = "LLMNR" if port == LLMNR_PORT else "mDNS"
    if name.lower().split(".")[0] == "wpad":
        protocol = "WPAD"
    return NameQuery(protocol=protocol, source_mac=pkt.src, query_name=name)


def _parse_glbp(pkt: Packet) -> Fhrp | None:
    payload = bytes(pkt[UDP].payload)
    if len(payload) < 16 or payload[0] != 1:
        return None
    group = int.from_bytes(payload[2:4], "big")
    priority: int | None = None
    virtual_ip = ""
    offset = 16
    while offset + 2 <= len(payload):
        tlv_type, tlv_len = payload[offset], payload[offset + 1]
        if tlv_len < 2 or offset + tlv_len > len(payload):
            break
        # Type 1 is the hello TLV: priority is the fourth byte of its value and
        # the virtual address is the last four bytes when it is IPv4.
        if tlv_type == 1 and tlv_len >= 28:
            value = payload[offset + 2 : offset + tlv_len]
            priority = value[3]
            if value[20] == 1 and value[21] == 4:
                virtual_ip = ".".join(str(octet) for octet in value[22:26])
        offset += tlv_len
    return Fhrp("GLBP", pkt.src, group, priority, virtual_ip, authenticated=False)


def parse_fhrp(pkt: Packet) -> Fhrp | None:
    """L2P10. Whether authentication is present, never the value itself."""
    if HSRP in pkt:
        hsrp = pkt[HSRP]
        auth = bytes(hsrp.auth).rstrip(b"\x00")
        return Fhrp(
            "HSRP", pkt.src, int(hsrp.group), int(hsrp.priority), hsrp.virtualIP,
            authenticated=auth not in (b"", b"cisco"),
        )
    if VRRPv3 in pkt:
        vrrp = pkt[VRRPv3]
        addresses = list(vrrp.addrlist or [])
        return Fhrp(
            "VRRPv3", pkt.src, int(vrrp.vrid), int(vrrp.priority),
            addresses[0] if addresses else "", authenticated=False,
        )
    if VRRP in pkt:
        vrrp = pkt[VRRP]
        addresses = list(vrrp.addrlist or [])
        return Fhrp(
            "VRRP", pkt.src, int(vrrp.vrid), int(vrrp.priority),
            addresses[0] if addresses else "", authenticated=int(vrrp.authtype) != 0,
        )
    if UDP in pkt and pkt[UDP].dport == GLBP_PORT:
        return _parse_glbp(pkt)
    return None


def parse_cleartext(pkt: Packet) -> Cleartext | None:
    """L2P11. Protocol and endpoints only."""
    if IP not in pkt:
        return None
    source, destination = pkt[IP].src, pkt[IP].dst
    if TCP in pkt:
        for port in (pkt[TCP].dport, pkt[TCP].sport):
            if port in CLEARTEXT_TCP:
                return Cleartext(CLEARTEXT_TCP[port], source, destination)
        return None
    if UDP not in pkt:
        return None
    for port in (pkt[UDP].dport, pkt[UDP].sport):
        if port in CLEARTEXT_UDP:
            return Cleartext(CLEARTEXT_UDP[port], source, destination)
    if SNMP in pkt and int(pkt[SNMP].version) in (0, 1):
        version = "v1" if int(pkt[SNMP].version) == 0 else "v2c"
        return Cleartext("SNMP " + version, source, destination)
    return None


def parse_router_advert(pkt: Packet) -> RouterAdvert | None:
    """L2P12."""
    if ICMPv6ND_RA not in pkt:
        return None
    advert = pkt[ICMPv6ND_RA]
    prefix = ""
    option = pkt.getlayer(ICMPv6NDOptPrefixInfo)
    if option is not None:
        prefix = "%s/%d" % (option.prefix, option.prefixlen)
    return RouterAdvert(
        source_mac=pkt.src,
        source_ip=pkt[IPv6].src if IPv6 in pkt else "",
        prefix=prefix,
        managed=bool(advert.M),
        lifetime=int(advert.routerlifetime),
    )


def parse_service(pkt: Packet) -> ServiceAnnouncement | None:
    """L2P13. SSDP and WS-Discovery announcements."""
    if UDP not in pkt:
        return None
    port = pkt[UDP].dport
    if port == WSD_PORT:
        return ServiceAnnouncement("WS-Discovery", pkt.src, "unnamed")
    if port != SSDP_PORT:
        return None
    payload = bytes(pkt[UDP].payload)
    if not payload.startswith((b"NOTIFY", b"M-SEARCH", b"HTTP/1.1")):
        return None
    service = ""
    for line in payload.split(b"\r\n"):
        if line.upper().startswith((b"NT:", b"ST:")):
            service = _text(line.split(b":", 1)[1].strip())
    return ServiceAnnouncement("SSDP", pkt.src, service or "unnamed")


PARSERS = (
    (parse_cdp, "discovery"),
    (parse_lldp, "discovery"),
    (parse_dtp, "trunking"),
    (parse_bpdu, "bpdu"),
    (parse_vtp, "vtp"),
    (parse_dhcp_server, "dhcp_servers"),
    (parse_arp, "arp"),
    (parse_name_query, "names"),
    (parse_fhrp, "fhrp"),
    (parse_cleartext, "cleartext"),
    (parse_router_advert, "router_adverts"),
    (parse_service, "services"),
)


def parse_frame(pkt: Packet, capture: Capture) -> None:
    """Dispatch one frame into the capture.

    Every parser is guarded. A truncated or malformed frame is routine on a real
    segment and this runs inside the sniffer's callback, so an exception escaping
    here would abort the capture and lose the run.
    """
    capture.frames_seen += 1
    for parser, name in PARSERS:
        try:
            record = parser(pkt)
        except Exception:
            capture.parse_errors += 1
            continue
        if record is not None:
            if name == "arp" and record.gratuitous:
                capture.gratuitous_arps += 1
            capture.add(name, record)
    try:
        for tag in parse_tagged(pkt):
            capture.add("tagged", tag)
    except Exception:
        capture.parse_errors += 1
