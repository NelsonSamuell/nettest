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

from l2check import listen, posture, probes, report
from l2check.authorisation import (
    ACTIVE_CHECKS,
    ActiveSession,
    AuthorisationError,
    DEFAULT_MAX_MACS,
    confirm_segment,
    load_authorisation,
    parse_tests,
    validate_max_macs,
)
from l2check.observe import Observer

EXIT_ABSENT = 1
EXIT_INPUT_ERROR = 2

CAPABILITY_HINT = (
    "no permission to open a raw socket on %s. l2check needs CAP_NET_RAW; "
    "setting it on the Python binary is preferable to running as root"
)


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for the l2check command."""
    parser = argparse.ArgumentParser(prog="l2check", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    listener = sub.add_parser("listen", help="passive capture, sends nothing")
    listener.add_argument("--interface", required=True)
    listener.add_argument("--duration", type=int, default=listen.DEFAULT_DURATION)
    listener.add_argument("--json", action="store_true", help="print JSON instead of a table")
    listener.add_argument("--out", help="write the JSON report to this path")

    prober = sub.add_parser("probe", help="active probes, requires written authorisation")
    prober.add_argument("--interface", required=True)
    prober.add_argument("--active", action="store_true")
    prober.add_argument("--authorisation")
    prober.add_argument("--tests", help="probe identifiers: %s" % ", ".join(ACTIVE_CHECKS))
    prober.add_argument("--test-ip")
    prober.add_argument("--target-vlan", type=int, help="inner VLAN for L2A06")
    prober.add_argument("--observer", metavar="HOST:PORT")
    prober.add_argument("--max-macs", type=int, default=DEFAULT_MAX_MACS)
    prober.add_argument("--confirm-segment")
    prober.add_argument("--duration", type=int, default=listen.DEFAULT_DURATION)
    prober.add_argument("--json", action="store_true")
    prober.add_argument("--out")

    observer = sub.add_parser("observe", help="cooperating listener for L2A05 and L2A06")
    observer.add_argument("--interface", required=True)
    observer.add_argument("--port", type=int, required=True)

    rebuild = sub.add_parser("posture", help="rebuild the table from a saved JSON report")
    rebuild.add_argument("--from", dest="source", required=True)

    return parser


def _emit(document: dict, board: posture.Posture, findings: list, args) -> None:
    if args.out:
        Path(args.out).write_text(report.to_json(document) + "\n")
    print(report.to_json(document) if args.json else report.render(board, findings))


def run_listen(args) -> int:
    capture = listen.capture(args.interface, args.duration)
    board, findings = posture.from_capture(capture)
    _emit(report.to_dict(board, findings, capture=capture), board, findings, args)
    return board.exit_code()


def run_probe(args) -> int:
    if not args.active:
        raise AuthorisationError("active probes require --active and --authorisation")
    if not args.authorisation:
        raise AuthorisationError("active probes require --authorisation FILE")

    authorisation = load_authorisation(args.authorisation)
    tests = parse_tests(args.tests)
    max_macs = validate_max_macs(args.max_macs)
    confirm_segment(authorisation, args.confirm_segment)

    # The passive capture happens before the gate is opened: L2A02 cannot pick a
    # losing bridge priority without a root priority observed from this port.
    capture = listen.capture(args.interface, args.duration)
    board, findings = posture.from_capture(capture)

    session = ActiveSession(
        interface=args.interface,
        max_macs=max_macs,
        test_ip=args.test_ip,
        target_vlan=args.target_vlan,
        observer=args.observer,
    )
    session.authorise(authorisation, tests)
    for result in probes.run_selected(session, capture):
        board.apply(result)

    document = report.to_dict(
        board,
        findings,
        capture=capture,
        authorisation=authorisation,
        frames_sent=session.frames_sent,
    )
    _emit(document, board, findings, args)
    return board.exit_code()


def run_observe(args) -> int:
    Observer(args.interface, args.port).serve()
    return 0


def run_posture(args) -> int:
    source = Path(args.source)
    if not source.is_file():
        raise AuthorisationError("saved report not found: %s" % source)
    document = json.loads(source.read_text())
    board, findings = report.from_dict(document)
    print(report.render(board, findings))
    return board.exit_code()


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns 0, 1 for an absent control, or 2 for an input error."""
    args = build_parser().parse_args(argv)
    handlers = {
        "listen": run_listen,
        "probe": run_probe,
        "observe": run_observe,
        "posture": run_posture,
    }
    try:
        return handlers[args.command](args)
    except AuthorisationError as error:
        print("error: %s" % error, file=sys.stderr)
        return EXIT_INPUT_ERROR
    except PermissionError:
        print("error: " + CAPABILITY_HINT % args.interface, file=sys.stderr)
        return EXIT_INPUT_ERROR
    except KeyboardInterrupt:
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    sys.exit(main())
