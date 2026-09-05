"""Everything that differs between operating systems.

No module outside this package may reference ``sys.platform``, ``os.name`` or
``platform.system``. A check declares the capabilities it needs and the registry
skips it when they are missing; it never asks which operating system it is on.
"""

from netcheck.platform.detect import (
    CAPABILITIES,
    RAW_L2_CAPTURE,
    RAW_L2_SEND,
    RAW_L3_SEND,
    REASON_PRIVILEGE,
    REASON_UNSUPPORTED,
    ROUTING_READ,
    SOCKET_L4,
    SYSCTL_READ,
    FIREWALL_READ,
    Capability,
    CapabilitySet,
)

__all__ = [
    "CAPABILITIES",
    "Capability",
    "CapabilitySet",
    "FIREWALL_READ",
    "RAW_L2_CAPTURE",
    "RAW_L2_SEND",
    "RAW_L3_SEND",
    "REASON_PRIVILEGE",
    "REASON_UNSUPPORTED",
    "ROUTING_READ",
    "SOCKET_L4",
    "SYSCTL_READ",
]
