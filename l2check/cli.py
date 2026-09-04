"""Command line interface.

Four subcommands. ``listen`` is passive and needs no permission. ``probe`` is
the only one that transmits, and every gate check runs before the session that
owns the wire is opened.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from l2check import doctor, listen, posture, probes, report
from l2check.l3 import targets as targets_module
from l2check.session import (
    ACTIVE_CHECKS,
    DEFAULT_MAX_MACS,
    DEFAULT_RATE_PPS,
    ActiveSession,
    Budget,
    ConfigError,
    parse_tests,
    validate_max_macs,
    validate_rate,
)
from l2check.observe import Observer

EXIT_ABSENT = 1
EXIT_INPUT_ERROR = 2

CAPABILITY_HINT = (
    "no permission to read frames on %s.\n"
    "  Run ./setup.sh once to grant this to the project only, then try again.\n"
    "  Run 'l2check doctor' to see what is missing."
)

NO_INTERFACE_HINT = (
    "no usable interface found. Run 'l2check doctor' to see what is available, "
    "or name one with --interface"
)


def build_parser(prog: str = "netcheck") -> argparse.ArgumentParser:
    """Return the argument parser for the netcheck command."""
    parser = argparse.ArgumentParser(prog=prog, description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    listener = sub.add_parser("listen", help="passive capture, sends nothing")
    listener.add_argument("--interface", help="defaults to the interface with the default route")
    listener.add_argument("--duration", type=int, default=listen.DEFAULT_DURATION)
    listener.add_argument("--json", action="store_true", help="print JSON instead of a table")
    listener.add_argument("--out", help="write the JSON report to this path")
    listener.add_argument("--config", help="targets file, default ./netcheck.yaml")
    listener.add_argument(
        "--profile",
        choices=("auto", posture.WIRED, posture.WIRELESS),
        default="auto",
        help="which control set to report; auto follows the interface",
    )

    prober = sub.add_parser("probe", help="active checks, needs --active")
    prober.add_argument("--interface", help="defaults to the interface with the default route")
    prober.add_argument("--active", action="store_true")
    prober.add_argument("--tests", help="check identifiers: %s" % ", ".join(ACTIVE_CHECKS))
    prober.add_argument("--all", action="store_true", help="run every supported check")
    prober.add_argument("--config", help="targets file, default ./netcheck.yaml")
    prober.add_argument("--frame-budget", type=int)
    prober.add_argument("--packet-budget", type=int)
    prober.add_argument("--runtime", type=int, metavar="MINUTES")
    prober.add_argument("--rate", type=int, metavar="PPS", default=DEFAULT_RATE_PPS)
    prober.add_argument("--yes", action="store_true", help="proceed past a wide sweep warning")
    prober.add_argument("--wan", action="store_true", help="include the WAN address")
    prober.add_argument("--test-ip")
    prober.add_argument("--target-vlan", type=int, help="inner VLAN for L2A06")
    prober.add_argument("--observer", metavar="HOST:PORT")
    prober.add_argument("--max-macs", type=int, default=DEFAULT_MAX_MACS)
    prober.add_argument("--duration", type=int, default=listen.DEFAULT_DURATION)
    prober.add_argument("--json", action="store_true")
    prober.add_argument("--out")
    prober.add_argument(
        "--profile",
        choices=("auto", posture.WIRED, posture.WIRELESS),
        default="auto",
    )

    observer = sub.add_parser("observe", help="cooperating listener for L2A05 and L2A06")
    observer.add_argument("--interface", required=True)
    observer.add_argument("--port", type=int, required=True)
    observer.add_argument(
        "--side",
        choices=("internal", "external"),
        default="internal",
        help="which side of the NAT boundary this observer sits on",
    )

    rebuild = sub.add_parser("posture", help="rebuild the table from a saved JSON report")
    rebuild.add_argument("--from", dest="source", required=True)

    auditor = sub.add_parser("audit", help="offline config audit, sends nothing")
    auditor.add_argument("--config", help="exported router config to parse")
    auditor.add_argument("--json", action="store_true")
    auditor.add_argument("--out")
    auditor.add_argument("--markdown", metavar="PATH")
    auditor.add_argument("--layers", choices=("l2", "l3", "both"), default="both")

    sub.add_parser("doctor", help="check the environment and say what to run next")

    for name in ("listen", "probe", "posture"):
        sub.choices[name].add_argument(
            "--layers",
            choices=("l2", "l3", "both"),
            default="both",
            help="which control set to report",
        )
        sub.choices[name].add_argument(
            "--markdown", metavar="PATH", help="also write a Markdown report"
        )
    sub.choices["posture"].add_argument(
        "--diff", metavar="PREVIOUS", help="compare against an earlier saved run"
    )

    return parser


# What each check needs before it can say anything. Checks whose requirement is
# missing are skipped up front by --all, with a reason, rather than failing
# halfway through a run.
REQUIREMENTS = {
    "L3A05": ("external observer and --wan", lambda c, a: bool(c.external_observer and a.wan)),
    "L3A07": ("external observer and external.test_host",
              lambda c, a: bool(c.external_observer and c.external.get("test_host"))),
    "L3A08": ("external observer", lambda c, a: bool(c.external_observer)),
    "L3A09": ("guest_subnet and an internal observer",
              lambda c, a: bool(c.guest_subnet and c.internal_observer)),
    "L3A10": ("external.authoritative_ns", lambda c, a: bool(c.external.get("authoritative_ns"))),
    "L3A11": ("external observer and --wan", lambda c, a: bool(c.external_observer and a.wan)),
    "L3A13": ("external observer and external.test_host",
              lambda c, a: bool(c.external_observer and c.external.get("test_host"))),
    "L3A14": ("external observer and external.test_host",
              lambda c, a: bool(c.external_observer and c.external.get("test_host"))),
    "L3A15": ("external observer and external.test_host",
              lambda c, a: bool(c.external_observer and c.external.get("test_host"))),
    "L2A05": ("--test-ip", lambda c, a: bool(a.test_ip)),
    "L2A06": ("--target-vlan and --test-ip", lambda c, a: bool(a.target_vlan and a.test_ip)),
}


def supportable(tests: list[str], config, args) -> tuple[list[str], list[tuple[str, str]]]:
    """Split the selected checks into those this setup can run and those it cannot."""
    runnable, skipped = [], []
    for check in tests:
        requirement = REQUIREMENTS.get(check)
        if requirement is None or requirement[1](config, args):
            runnable.append(check)
        else:
            skipped.append((check, "needs %s" % requirement[0]))
    return runnable, skipped


def resolve_interface(args) -> str:
    """Return the interface to use, picking a sensible one when none was named."""
    if getattr(args, "interface", None):
        return args.interface
    chosen = doctor.suggested_interface()
    if not chosen:
        raise ConfigError(NO_INTERFACE_HINT)
    print("using interface %s" % chosen, file=sys.stderr)
    return chosen


def _emit(
    document: dict,
    board: posture.Posture,
    findings: list,
    args,
    host=None,
    matrix=None,
    devices=None,
) -> None:
    if getattr(args, "out", None):
        Path(args.out).write_text(report.to_json(document) + "\n")
    if getattr(args, "markdown", None):
        Path(args.markdown).write_text(report.to_markdown(document, board, findings))
    if getattr(args, "json", False):
        print(report.to_json(document))
    else:
        print(
            report.render(
                board,
                findings,
                layers=getattr(args, "layers", "both"),
                host=host,
                matrix=matrix,
                devices=devices,
            )
        )


def _profile(args) -> str | None:
    """None lets the posture model pick the profile from the interface."""
    return None if args.profile == "auto" else args.profile


def run_listen(args) -> int:
    from l2check.l3.correlate import correlate, reachability

    args.interface = resolve_interface(args)
    config = targets_module.load(getattr(args, "config", None), args.interface)
    capture = listen.capture(args.interface, args.duration)
    board, findings = posture.from_capture(capture, profile=_profile(args), targets=config)
    devices = correlate(capture, config)
    matrix = reachability(capture, None, config)
    _emit(
        report.to_dict(
            board, findings, capture=capture, targets=config,
            devices=devices, matrix=matrix,
        ),
        board,
        findings,
        args,
        host=capture.host_posture,
        matrix=matrix,
        devices=[d.as_dict() for d in devices],
    )
    return board.exit_code()


def run_probe(args) -> int:
    args.interface = resolve_interface(args)
    if not args.active:
        raise ConfigError("active checks require --active")

    config = targets_module.load(args.config, args.interface)
    tests = list(ACTIVE_CHECKS) if args.all else parse_tests(args.tests)
    if args.all:
        tests, skipped = supportable(tests, config, args)
        for check, reason in skipped:
            print("skipping %s: %s" % (check, reason), file=sys.stderr)
    max_macs = validate_max_macs(args.max_macs)
    rate = validate_rate(args.rate or config.limits.rate_pps)

    wide = config.wide_prefixes()
    if wide and not args.yes:
        for subnet, count in wide:
            print(
                "%s is wider than a /24: about %d addresses, roughly %d minutes at "
                "%d pps" % (subnet, count, count // max(rate, 1) // 60 + 1, rate),
                file=sys.stderr,
            )
        raise ConfigError("wide prefix in targets. Re-run with --yes to proceed")

    # The passive capture happens before anything is sent: L2A02 cannot pick a
    # losing bridge priority without a root priority observed from this port.
    capture = listen.capture(args.interface, args.duration)
    board, findings = posture.from_capture(capture, profile=_profile(args), targets=config)

    budget = Budget(
        frames=args.frame_budget or config.limits.frame_budget,
        packets=args.packet_budget or config.limits.packet_budget,
    )
    from l2check.l3.probes.discovery import DEFAULT_TCP_PORTS, DEFAULT_UDP_PORTS

    if args.wan:
        config.wan_address = targets_module.discover_wan(config)

    session = ActiveSession(
        interface=args.interface,
        budget=budget,
        rate_pps=rate,
        runtime_cap=(args.runtime or config.limits.runtime_minutes) * 60,
        max_macs=max_macs,
        test_ip=args.test_ip,
        target_vlan=args.target_vlan,
        observer=args.observer or config.internal_observer or None,
        external_observer=config.external_observer or None,
        local_cidr=listen.interface_cidr(args.interface) or None,
        gateway=config.gateway or None,
        sweep_targets=config.addresses(include_wan=args.wan),
        guest_subnet=config.guest_subnet,
        test_host=config.external.get("test_host", ""),
        authoritative_ns=config.external.get("authoritative_ns", ""),
        wan_address=config.wan_address,
        tcp_ports=DEFAULT_TCP_PORTS,
        udp_ports=DEFAULT_UDP_PORTS,
    )
    session.start(tests)
    results = probes.run_selected(session, capture)
    for result in results:
        board.apply(result)

    # Correlation runs after every check and before the report.
    from l2check.l3.correlate import correlate, correlation_findings, reachability

    devices = correlate(capture, config)
    # from_capture already correlated the passive data. Active checks can add
    # hosts, so recompute and replace rather than appending a second copy.
    findings = [f for f in findings if not f.check.startswith("COR")]
    findings = findings + correlation_findings(devices, board, capture)
    matrix = reachability(capture, results, config)

    document = report.to_dict(
        board,
        findings,
        capture=capture,
        targets=config,
        budget=budget,
        frames_sent=session.frames_sent,
        devices=devices,
        matrix=matrix,
    )
    _emit(
        document, board, findings, args,
        host=capture.host_posture, matrix=matrix,
        devices=[d.as_dict() for d in devices],
    )
    return board.exit_code()


def run_doctor(args) -> int:
    print(doctor.report(getattr(args, "prog", "netcheck")))
    return 0 if doctor.can_open_raw_socket() else EXIT_INPUT_ERROR


def run_observe(args) -> int:
    Observer(args.interface, args.port, args.side).serve()
    return 0


def run_audit(args) -> int:
    """Offline audit. Sends nothing, needs no targets file and no interface."""
    from l2check.l3.config_audit import parse_router_config, read_host_posture
    from l2check.models import Capture

    capture = Capture(interface="", duration=0)
    capture.host_posture = read_host_posture()
    if args.config:
        capture.router_config = parse_router_config(args.config)
    board, findings = posture.from_capture(capture, profile=posture.WIRED)
    document = report.to_dict(board, findings, capture=capture)
    _emit(document, board, findings, args, host=capture.host_posture)
    return board.exit_code()


def run_posture(args) -> int:
    source = Path(args.source)
    if not source.is_file():
        raise ConfigError("saved report not found: %s" % source)
    document = json.loads(source.read_text())
    board, findings = report.from_dict(document)
    if getattr(args, "diff", None):
        previous = Path(args.diff)
        if not previous.is_file():
            raise ConfigError("previous report not found: %s" % previous)
        print(report.diff(json.loads(previous.read_text()), document))
        print()
    _emit(document, board, findings, args)
    return board.exit_code()


def main(argv: list[str] | None = None, prog: str = "netcheck") -> int:
    """The netcheck entry point. 0, 1 for an absent control, 2 for an input error."""
    args = build_parser(prog).parse_args(argv)
    args.prog = prog
    handlers = {
        "listen": run_listen,
        "probe": run_probe,
        "observe": run_observe,
        "posture": run_posture,
        "doctor": run_doctor,
        "audit": run_audit,
    }
    try:
        return handlers[args.command](args)
    except ConfigError as error:
        print("error: %s" % error, file=sys.stderr)
        return EXIT_INPUT_ERROR
    except PermissionError:
        target = getattr(args, "interface", None) or "this interface"
        print("error: " + CAPABILITY_HINT % target, file=sys.stderr)
        return EXIT_INPUT_ERROR
    except KeyboardInterrupt:
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    sys.exit(main())


def main_l2check(argv: list[str] | None = None) -> int:
    """The l2check alias. Same commands, layer 2 control set only."""
    args = argv if argv is not None else sys.argv[1:]
    if args and args[0] in ("listen", "probe", "posture") and "--layers" not in args:
        args = list(args) + ["--layers", "l2"]
    return main(args, prog="l2check")
