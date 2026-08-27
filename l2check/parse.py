"""Frame parsers for the passive listener.

Each parser takes one scapy packet and returns a metadata record or None. No
parser returns, copies or retains frame payload: what comes out is the protocol
fields the posture model needs and nothing else.
"""

from __future__ import annotations

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
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.l2 import ARP, Dot1Q, Ether, STP
from scapy.layers.netbios import NBNSQueryRequest
from scapy.layers.snmp import SNMP
from scapy.layers.vrrp import VRRP, VRRPv3
from scapy.packet import Packet

from l2check.models import (
    ArpRecord,
    PeerTrafficRecord,
    RouterAdvertRecord,
    UpnpRecord,
    BpduRecord,
    Capture,
    CleartextRecord,
    DhcpServerRecord,
    DiscoveryRecord,
    DtpRecord,
    FhrpRecord,
    NameResolutionRecord,
    TaggedFrameRecord,
    VtpRecord,
)

GLBP_PORT = 3222
SSDP_PORT = 1900
HSRP_PORT = 1985
LLMNR_PORT = 5355
MDNS_PORT = 5353
NBNS_PORT = 137

# The low nibble of the DTP status TLV carries the negotiation mode; bit 7 is
# set once the port is operationally trunking.
DTP_MODES = {
    0x01: "access",
    0x02: "trunk, no negotiate",
    0x03: "dynamic desirable",
    0x04: "dynamic auto",
}

CLEARTEXT_TCP_PORTS = {21: "FTP", 23: "Telnet"}
CLEARTEXT_UDP_PORTS = {69: "TFTP"}


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    return "" if value is None else str(value)


def parse_cdp(pkt: Packet) -> DiscoveryRecord | None:
    """Return a discovery record for a CDP frame, or None."""
    if CDPv2_HDR not in pkt:
        return None
    record = DiscoveryRecord(protocol="CDP", source_mac=pkt[Ether].src if Ether in pkt else pkt.src)
    for tlv in pkt[CDPv2_HDR].msg:
        if isinstance(tlv, CDPMsgDeviceID):
            record.device_id = _text(tlv.val)
        elif isinstance(tlv, CDPMsgPlatform):
            record.platform = _text(tlv.val)
        elif isinstance(tlv, CDPMsgSoftwareVersion):
            record.software_version = _text(tlv.val)
        elif isinstance(tlv, CDPMsgPortID):
            record.port_id = _text(tlv.iface)
        elif isinstance(tlv, CDPMsgNativeVLAN):
            record.native_vlan = int(tlv.vlan)
        elif isinstance(tlv, CDPMsgVTPMgmtDomain):
            record.vtp_domain = _text(tlv.val)
        elif isinstance(tlv, CDPMsgMgmtAddr) and tlv.addr:
            record.management_address = _text(tlv.addr[0].addr)
    return record


def parse_lldp(pkt: Packet) -> DiscoveryRecord | None:
    """Return a discovery record for an LLDP frame, or None."""
    if LLDPDU not in pkt:
        return None
    record = DiscoveryRecord(protocol="LLDP", source_mac=pkt[Ether].src)
    if LLDPDUChassisID in pkt:
        record.device_id = _text(pkt[LLDPDUChassisID].id)
    if LLDPDUSystemName in pkt:
        record.device_id = _text(pkt[LLDPDUSystemName].system_name) or record.device_id
    if LLDPDUSystemDescription in pkt:
        record.software_version = _text(pkt[LLDPDUSystemDescription].description)
    if LLDPDUPortID in pkt:
        record.port_id = _text(pkt[LLDPDUPortID].id)
    if LLDPDUManagementAddress in pkt:
        address = pkt[LLDPDUManagementAddress].management_address
        if pkt[LLDPDUManagementAddress].management_address_subtype == 1 and len(address) == 4:
            record.management_address = ".".join(str(octet) for octet in address)
    return record


def parse_dtp(pkt: Packet) -> DtpRecord | None:
    """Return a DTP record, or None."""
    if DTP not in pkt:
        return None
    mode = "unknown"
    domain = ""
    for tlv in pkt[DTP].tlvlist:
        if isinstance(tlv, DTPStatus) and tlv.status:
            status = tlv.status[0]
            mode = DTP_MODES.get(status & 0x0F, "unknown (0x%02x)" % status)
            if status & 0x80:
                mode = "trunking, " + mode
        elif isinstance(tlv, DTPDomain):
            domain = _text(tlv.domain)
    return DtpRecord(source_mac=pkt.src, mode=mode, domain=domain)


def parse_bpdu(pkt: Packet) -> BpduRecord | None:
    """Return a BPDU record, or None."""
    if STP not in pkt:
        return None
    stp = pkt[STP]
    return BpduRecord(
        source_mac=pkt.src,
        root_priority=int(stp.rootid),
        root_mac=stp.rootmac,
        root_path_cost=int(stp.pathcost),
        bridge_priority=int(stp.bridgeid),
        bridge_mac=stp.bridgemac,
    )


def parse_vtp(pkt: Packet) -> VtpRecord | None:
    """Return a VTP record, or None."""
    if VTP not in pkt:
        return None
    return VtpRecord(
        source_mac=pkt.src,
        domain=_text(pkt[VTP].domname),
        revision=int(pkt[VTP].rev),
    )


def parse_tagged(pkt: Packet) -> list[TaggedFrameRecord]:
    """Return one record per 802.1Q tag on the frame."""
    records = []
    layer = pkt.getlayer(Dot1Q)
    while layer is not None:
        records.append(TaggedFrameRecord(source_mac=pkt.src, vlan=int(layer.vlan)))
        layer = layer.payload.getlayer(Dot1Q)
    return records


def parse_dhcp_server(pkt: Packet) -> DhcpServerRecord | None:
    """Return a record for a DHCP offer or acknowledgement, or None."""
    if BOOTP not in pkt or DHCP not in pkt or pkt[BOOTP].op != 2:
        return None
    server_ip = pkt[IP].src if IP in pkt else ""
    for option in pkt[DHCP].options:
        if isinstance(option, tuple) and option[0] == "server_id":
            server_ip = _text(option[1])
    return DhcpServerRecord(server_mac=pkt[Ether].src, server_ip=server_ip)


def parse_arp(pkt: Packet) -> ArpRecord | None:
    """Return an ARP record, flagging gratuitous announcements."""
    if ARP not in pkt:
        return None
    arp = pkt[ARP]
    gratuitous = arp.psrc == arp.pdst and arp.psrc != "0.0.0.0"
    return ArpRecord(source_mac=arp.hwsrc, claimed_ip=arp.psrc, gratuitous=gratuitous)


def parse_name_resolution(pkt: Packet) -> NameResolutionRecord | None:
    """Return a record for an LLMNR, NBT-NS, mDNS or WPAD query, or None."""
    if UDP not in pkt:
        return None
    port = pkt[UDP].dport
    if port == NBNS_PORT and NBNSQueryRequest in pkt:
        name = _text(pkt[NBNSQueryRequest].QUESTION_NAME).strip()
        protocol = "WPAD" if name.lower().startswith("wpad") else "NBT-NS"
        return NameResolutionRecord(protocol=protocol, source_mac=pkt.src, query_name=name)
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
    return NameResolutionRecord(protocol=protocol, source_mac=pkt.src, query_name=name)


def _parse_glbp(pkt: Packet) -> FhrpRecord | None:
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
    # GLBP carries no authentication TLV in the common deployment, and any
    # value present is not recorded.
    return FhrpRecord(
        protocol="GLBP",
        source_mac=pkt.src,
        group=group,
        priority=priority,
        virtual_ip=virtual_ip,
        authenticated=False,
    )


def parse_fhrp(pkt: Packet) -> FhrpRecord | None:
    """Return a first hop redundancy record for HSRP, VRRP or GLBP, or None.

    The authentication value itself is never returned, only whether one that is
    neither absent nor the vendor default was present.
    """
    if HSRP in pkt:
        hsrp = pkt[HSRP]
        auth = bytes(hsrp.auth).rstrip(b"\x00")
        return FhrpRecord(
            protocol="HSRP",
            source_mac=pkt.src,
            group=int(hsrp.group),
            priority=int(hsrp.priority),
            virtual_ip=hsrp.virtualIP,
            authenticated=auth not in (b"", b"cisco"),
        )
    if VRRPv3 in pkt:
        vrrp = pkt[VRRPv3]
        addresses = list(vrrp.addrlist or [])
        return FhrpRecord(
            protocol="VRRPv3",
            source_mac=pkt.src,
            group=int(vrrp.vrid),
            priority=int(vrrp.priority),
            virtual_ip=addresses[0] if addresses else "",
            authenticated=False,
        )
    if VRRP in pkt:
        vrrp = pkt[VRRP]
        addresses = list(vrrp.addrlist or [])
        return FhrpRecord(
            protocol="VRRP",
            source_mac=pkt.src,
            group=int(vrrp.vrid),
            priority=int(vrrp.priority),
            virtual_ip=addresses[0] if addresses else "",
            authenticated=int(vrrp.authtype) != 0,
        )
    if UDP in pkt and pkt[UDP].dport == GLBP_PORT:
        return _parse_glbp(pkt)
    return None


def parse_router_advert(pkt: Packet) -> RouterAdvertRecord | None:
    """Return a record for an IPv6 router advertisement, or None."""
    if ICMPv6ND_RA not in pkt:
        return None
    advert = pkt[ICMPv6ND_RA]
    prefix = ""
    option = pkt.getlayer(ICMPv6NDOptPrefixInfo)
    if option is not None:
        prefix = "%s/%d" % (option.prefix, option.prefixlen)
    return RouterAdvertRecord(
        source_mac=pkt.src,
        source_ip=pkt[IPv6].src if IPv6 in pkt else "",
        prefix=prefix,
        managed=bool(advert.M),
        router_lifetime=int(advert.routerlifetime),
    )


def parse_upnp(pkt: Packet) -> UpnpRecord | None:
    """Return a record for an SSDP announcement or search, or None.

    Only the SERVER banner is kept, for the same reason CDP's platform string is
    kept: it is the disclosure. The rest of the payload is not read.
    """
    if UDP not in pkt or SSDP_PORT not in (pkt[UDP].dport, pkt[UDP].sport):
        return None
    payload = bytes(pkt[UDP].payload)
    if not payload.startswith((b"NOTIFY", b"M-SEARCH", b"HTTP/1.1")):
        return None
    server = ""
    for line in payload.split(b"\r\n"):
        if line.upper().startswith(b"SERVER:"):
            server = _text(line.split(b":", 1)[1].strip())
    address = ""
    if IP in pkt:
        address = pkt[IP].src
    elif IPv6 in pkt:
        address = pkt[IPv6].src
    return UpnpRecord(source_mac=pkt.src, source_ip=address, server=server)


def parse_peer_traffic(pkt: Packet, local_macs: set[str]) -> PeerTrafficRecord | None:
    """Return a record when a frame is unicast between two other stations.

    A segment that isolates its clients never delivers these. Only the two MAC
    addresses and the protocol name are kept.
    """
    if Ether not in pkt or not local_macs:
        return None
    source, destination = pkt[Ether].src.lower(), pkt[Ether].dst.lower()
    if source in local_macs or destination in local_macs:
        return None
    # Group addressed frames reach every station by design and prove nothing.
    if int(destination.split(":")[0], 16) & 0x01:
        return None
    return PeerTrafficRecord(
        source_mac=source,
        destination_mac=destination,
        protocol=pkt.payload.name if pkt.payload else "unknown",
    )


def parse_cleartext(pkt: Packet) -> CleartextRecord | None:
    """Return a record for a cleartext management protocol, or None."""
    if IP not in pkt:
        return None
    source, destination = pkt[IP].src, pkt[IP].dst
    if TCP in pkt:
        for port in (pkt[TCP].dport, pkt[TCP].sport):
            if port in CLEARTEXT_TCP_PORTS:
                return CleartextRecord(CLEARTEXT_TCP_PORTS[port], source, destination)
        return None
    if UDP not in pkt:
        return None
    for port in (pkt[UDP].dport, pkt[UDP].sport):
        if port in CLEARTEXT_UDP_PORTS:
            return CleartextRecord(CLEARTEXT_UDP_PORTS[port], source, destination)
    if SNMP in pkt and int(pkt[SNMP].version) in (0, 1):
        version = "v1" if int(pkt[SNMP].version) == 0 else "v2c"
        return CleartextRecord("SNMP " + version, source, destination)
    return None


def parse_frame(pkt: Packet, capture: Capture) -> None:
    """Dispatch one packet into the capture's metadata records."""
    capture.frames_seen += 1
    for parser, sink in (
        (parse_cdp, capture.discovery),
        (parse_lldp, capture.discovery),
        (parse_dtp, capture.dtp),
        (parse_bpdu, capture.bpdu),
        (parse_vtp, capture.vtp),
        (parse_dhcp_server, capture.dhcp_servers),
        (parse_arp, capture.arp),
        (parse_name_resolution, capture.name_resolution),
        (parse_fhrp, capture.fhrp),
        (parse_cleartext, capture.cleartext),
        (parse_router_advert, capture.router_adverts),
        (parse_upnp, capture.upnp),
    ):
        record = parser(pkt)
        if record is not None:
            sink.append(record)
    capture.tagged.extend(parse_tagged(pkt))
    peer = parse_peer_traffic(pkt, capture.local_macs)
    if peer is not None:
        capture.peer_traffic.append(peer)
