"""Portability. Runs on all three platforms in CI."""

import ast
import pathlib

import pytest

from netcheck.models import ABSENT, INSUFFICIENT_PRIVILEGE, UNSUPPORTED_PLATFORM, Posture
from netcheck.platform import interfaces as interfaces_module
from netcheck.platform import privilege, sockets
from netcheck.platform.detect import (
    CAPABILITIES,
    REASON_PRIVILEGE,
    REASON_UNSUPPORTED,
    Capability,
    CapabilitySet,
    detect,
)
from netcheck.platform.system import config_home, in_container, state_home, system
from netcheck.registry import Check, Registry, skipped_controls

SOURCE = pathlib.Path("netcheck")
PLATFORM_PACKAGE = SOURCE / "platform"


def source_files(exclude_platform: bool = True):
    for path in SOURCE.rglob("*.py"):
        if exclude_platform and PLATFORM_PACKAGE in path.parents:
            continue
        yield path


def test_the_capability_set_resolves_without_raising():
    found = detect()
    assert set(found.capabilities) == set(CAPABILITIES)
    for capability in found.capabilities.values():
        assert isinstance(capability.available, bool)
        assert capability.how, "%s must record how it was probed" % capability.name


def test_an_unavailable_capability_always_carries_a_reason():
    for capability in detect().capabilities.values():
        if not capability.available:
            assert capability.reason in (REASON_PRIVILEGE, REASON_UNSUPPORTED)


def test_layer_four_sockets_work_everywhere():
    """Ordinary TCP needs no privilege on any supported platform."""
    assert sockets.probe_socket_l4().ok


def test_the_two_skip_reasons_are_distinguished():
    privileged = CapabilitySet(
        {"raw_l3_send": Capability("raw_l3_send", False, "probe", REASON_PRIVILEGE)}
    )
    unsupported = CapabilitySet(
        {"raw_l2_send": Capability("raw_l2_send", False, "probe", REASON_UNSUPPORTED)}
    )
    assert privileged.reason_for({"raw_l3_send"}) == REASON_PRIVILEGE
    assert unsupported.reason_for({"raw_l2_send"}) == REASON_UNSUPPORTED


def test_privilege_is_reported_before_platform_when_both_apply():
    """A missing privilege is actionable; a missing platform mechanism is not."""
    mixed = CapabilitySet(
        {
            "raw_l2_send": Capability("raw_l2_send", False, "p", REASON_UNSUPPORTED),
            "raw_l3_send": Capability("raw_l3_send", False, "p", REASON_PRIVILEGE),
        }
    )
    assert mixed.reason_for({"raw_l2_send", "raw_l3_send"}) == REASON_PRIVILEGE


def test_a_check_with_unmet_requirements_is_skipped_never_absent():
    registry = Registry()
    registry.register(
        Check("L3A02", "TCP inventory", ("Egress filtering",), frozenset({"raw_l3_send"}))
    )
    capabilities = CapabilitySet(
        {"raw_l3_send": Capability("raw_l3_send", False, "probe", REASON_PRIVILEGE)}
    )
    runnable, skipped = registry.resolve(["L3A02"], capabilities)
    assert runnable == []
    assert skipped[0].reason == INSUFFICIENT_PRIVILEGE

    posture = Posture.new()
    skipped_controls(skipped, registry, posture)
    assert posture.controls["Egress filtering"].state != ABSENT
    assert posture.controls["Egress filtering"].state == "UNTESTED"


def test_an_unsupported_platform_also_never_yields_absent():
    registry = Registry()
    registry.register(
        Check("L2A06", "Double tagging", ("VLAN isolation",), frozenset({"raw_l2_send"}))
    )
    capabilities = CapabilitySet(
        {"raw_l2_send": Capability("raw_l2_send", False, "probe", REASON_UNSUPPORTED)}
    )
    _, skipped = registry.resolve(["L2A06"], capabilities)
    assert skipped[0].reason == UNSUPPORTED_PLATFORM
    posture = Posture.new()
    skipped_controls(skipped, registry, posture)
    assert posture.controls["VLAN isolation"].state != ABSENT


def test_only_the_platform_package_names_an_operating_system():
    """Checked by parsing, because netcheck.platform.system is a legitimate path."""
    for path in source_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "platform", "%s imports stdlib platform" % path
            if isinstance(node, ast.ImportFrom) and node.module == "platform":
                raise AssertionError("%s imports from stdlib platform" % path)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                pair = "%s.%s" % (node.value.id, node.attr)
                assert pair not in ("sys.platform", "os.name"), (
                    "%s references %s" % (path, pair)
                )


def test_the_platform_package_is_where_the_branch_lives():
    """The guard above is only meaningful if the branch exists somewhere."""
    text = (PLATFORM_PACKAGE / "system.py").read_text()
    assert "sys.platform" in text


def test_no_source_file_hardcodes_an_interface_name():
    for path in SOURCE.rglob("*.py"):
        assert "eth0" not in path.read_text(), "%s hardcodes an interface name" % path


def test_no_absolute_path_is_used_to_load_package_data():
    """Package data loads through importlib.resources, never a source-relative path."""
    for path in SOURCE.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            value = node.value
            if value.startswith("/") and value not in ("/",):
                # Reading a kernel interface is not loading package data.
                assert value.startswith(("/proc", "/sys", "/dev", "/usr", "/.")), (
                    "%s uses the absolute path %r" % (path, value)
                )
        assert "__file__).resolve().parent /" not in path.read_text()


def test_platform_helpers_return_usable_values():
    assert system() in ("linux", "macos", "windows", "other")
    assert config_home().name
    assert state_home().name
    detected, detail = in_container()
    assert isinstance(detected, bool)
    assert isinstance(detail, str)


def test_interface_enumeration_does_not_raise():
    found = interfaces_module.list_interfaces()
    assert isinstance(found, list)
    for entry in found:
        assert entry.name
        assert entry.kind in ("wired", "wireless", "loopback")


def test_the_elevation_command_names_this_platform_only():
    command = privilege.elevation_command()
    assert command
    hints = {
        "linux": "setcap",
        "macos": "bpf",
        "windows": "Npcap",
    }
    expected = hints.get(system())
    if expected:
        assert expected in command
        for kind, other in hints.items():
            if kind != system():
                assert other not in command


def test_registry_rejects_an_unknown_capability():
    registry = Registry()
    with pytest.raises(ValueError):
        registry.register(Check("L3A01", "x", requires=frozenset({"time_travel"})))


def test_a_shared_interpreter_is_flagged_in_the_elevation_command():
    """Granting a capability to a system interpreter covers every program using it."""
    if system() != "linux":
        pytest.skip("file capabilities are a Linux mechanism")
    command = privilege.elevation_command()
    if privilege.interpreter_is_shared():
        assert "shared" in command
        assert "--copies" in command
    else:
        assert "shared" not in command
