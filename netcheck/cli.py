"""Command line interface.

Every subcommand resolves the profile, the config and the capability set before
it does anything else, so a run that cannot produce a trustworthy answer says so
rather than producing one.
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path

from netcheck import __version__, config as config_module, doctor, report
from netcheck.abort import AbortWatcher
from netcheck.authorisation import check_scope, confirm_segment
from netcheck.authorisation import load as load_authorisation
from netcheck.budget import Budget, validate_max_macs
from netcheck.models import MAX_MACS_DEFAULT, Posture
from netcheck.platform.detect import detect
from netcheck.profile import ConfigError, parse_profile
from netcheck.registry import REGISTRY, skipped_controls

EXIT_ABSENT = 1
EXIT_INPUT_ERROR = 2

LAYER_CHOICES = ("l2", "l3", "both")


def build_parser(prog: str = "netcheck") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def shared(target, with_layers: bool = True) -> None:
        target.add_argument("--config", help="targets file; overrides the search order")
        target.add_argument("--json", action="store_true", help="print JSON instead of text")
        target.add_argument("--out", help="write the JSON report to this path")
        target.add_argument("--state-dir", help="where the tool may write state")
        if with_layers:
            target.add_argument("--layers", choices=LAYER_CHOICES, default="both")

    listener = sub.add_parser("listen", help="passive and offline checks, sends nothing")
    listener.add_argument("--interface")
    listener.add_argument("--duration", type=int, default=120)
    shared(listener)

    auditor = sub.add_parser("audit", help="offline audit, sends nothing")
    auditor.add_argument("--config", help="exported router config to parse")
    auditor.add_argument("--json", action="store_true")
    auditor.add_argument("--out")
    auditor.add_argument("--state-dir")
    auditor.add_argument("--layers", choices=LAYER_CHOICES, default="both")

    prober = sub.add_parser("probe", help="active checks")
    prober.add_argument("--interface")
    prober.add_argument("--duration", type=int, default=120)
    prober.add_argument("--active", action="store_true")
    prober.add_argument("--profile", choices=("self", "engagement"), default="self")
    prober.add_argument("--authorisation", help="required in the engagement profile")
    prober.add_argument("--confirm-segment")
    prober.add_argument("--tests", help="comma separated check identifiers")
    prober.add_argument("--all", action="store_true", help="every supported check")
    prober.add_argument("--test-ip")
    prober.add_argument("--wan", action="store_true", help="include the WAN address")
    prober.add_argument("--yes", action="store_true", help="proceed past a wide sweep")
    prober.add_argument("--frame-budget", type=int)
    prober.add_argument("--packet-budget", type=int)
    prober.add_argument("--runtime", type=int, metavar="MINUTES")
    prober.add_argument("--rate", type=int, metavar="PPS")
    prober.add_argument("--max-macs", type=int, default=MAX_MACS_DEFAULT)
    shared(prober)

    observer = sub.add_parser("observe", help="cooperating listener")
    observer.add_argument("--interface")
    observer.add_argument("--port", type=int, required=True)
    observer.add_argument("--side", choices=("internal", "external"), default="internal")

    rebuild = sub.add_parser("posture", help="rebuild a table from a saved run")
    rebuild.add_argument("--from", dest="source", required=True)
    rebuild.add_argument("--diff", metavar="PREVIOUS")
    shared(rebuild)

    physician = sub.add_parser("doctor", help="what this host can do, and what to run next")
    physician.add_argument("--config")
    physician.add_argument("--json", action="store_true")

    return parser


def resolve_interface(args) -> str:
    """The named interface, or the one holding the default route."""
    from netcheck.platform import interfaces as interfaces_module

    if getattr(args, "interface", None):
        return args.interface
    chosen = interfaces_module.default_interface()
    if not chosen:
        raise ConfigError(
            "no default route, so no interface could be chosen. Run '%s doctor' to "
            "see what is available, or name one with --interface" % args.prog
        )
    return chosen


def git_commit() -> str:
    """The commit this was built from, when the source tree is present."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _emit(document: dict, text: str, args) -> None:
    if getattr(args, "out", None):
        Path(args.out).write_text(report.to_json(document) + "\n")
    print(report.to_json(document) if getattr(args, "json", False) else text)


def _metadata(started: datetime.datetime, interface: str = "") -> dict:
    return {
        "version": __version__,
        "commit": git_commit(),
        "started": started.isoformat(timespec="seconds"),
        "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "interface": interface,
    }


def _empty_run(args, profile, configuration, interface: str = "") -> int:
    """A run with no checks registered yet. Everything reports UNTESTED."""
    started = datetime.datetime.now(datetime.timezone.utc)
    capabilities = detect()
    posture = Posture.new()
    _, skipped = REGISTRY.resolve(REGISTRY.identifiers(), capabilities)
    skipped_controls(skipped, REGISTRY, posture)

    metadata = _metadata(started, interface)
    document = report.to_dict(
        posture, [], profile, configuration, metadata=metadata
    )
    text = report.render(
        posture,
        [],
        profile,
        configuration,
        layers=getattr(args, "layers", "both"),
        metadata=metadata,
    )
    _emit(document, text, args)
    return posture.exit_code()


def run_listen(args) -> int:
    interface = resolve_interface(args)
    profile = parse_profile("self")
    configuration = config_module.load(args.config, interface)
    return _empty_run(args, profile, configuration, interface)


def run_audit(args) -> int:
    profile = parse_profile("self")
    configuration = config_module.load(None)
    return _empty_run(args, profile, configuration)


def run_probe(args) -> int:
    profile = parse_profile(args.profile)
    if not args.active:
        raise ConfigError("active checks require --active")

    interface = resolve_interface(args)
    configuration = config_module.load(args.config, interface)
    validate_max_macs(args.max_macs)
    budget = Budget.resolve(
        profile,
        frame_budget=args.frame_budget,
        packet_budget=args.packet_budget,
        runtime_minutes=args.runtime,
        rate_pps=args.rate,
        defaults=Budget(
            frames=configuration.limits.frame_budget,
            packets=configuration.limits.packet_budget,
            runtime_seconds=configuration.limits.runtime_minutes * 60,
            rate_pps=configuration.limits.rate_pps,
        ),
    )

    authorisation = None
    if profile.requires_authorisation:
        if not args.authorisation:
            raise ConfigError(
                "the engagement profile requires --authorisation FILE"
            )
        authorisation = load_authorisation(args.authorisation)
        check_scope(authorisation, configuration.subnets)
    if args.all and not profile.allows_all_tests:
        raise ConfigError(
            "--all is rejected in the engagement profile. List the checks with --tests"
        )
    if not args.all and not (args.tests or "").strip():
        raise ConfigError("--tests is required unless --all is given")

    diagnosis = doctor.diagnose(args.config, REGISTRY)
    refusal = doctor.refuses_active(diagnosis)
    if refusal:
        raise ConfigError(refusal)

    wide = configuration.wide_prefixes()
    if wide and not args.yes:
        for subnet, count in wide:
            minutes = count // max(budget.rate_pps, 1) // 60 + 1
            print(
                "%s is wider than a /24: about %d addresses, roughly %d minutes at "
                "%d pps" % (subnet, count, minutes, budget.rate_pps),
                file=sys.stderr,
            )
        raise ConfigError("wide prefix in targets. Re-run with --yes to proceed")

    if authorisation is not None:
        confirm_segment(authorisation, args.confirm_segment)

    watcher = AbortWatcher(interface=interface, gateway=configuration.gateway)
    watcher.start()

    started = datetime.datetime.now(datetime.timezone.utc)
    posture = Posture.new()
    _, skipped = REGISTRY.resolve(REGISTRY.identifiers(), detect(), budget)
    skipped_controls(skipped, REGISTRY, posture)

    metadata = _metadata(started, interface)
    document = report.to_dict(
        posture, [], profile, configuration, authorisation, budget,
        abort=watcher.as_dict(), metadata=metadata,
    )
    text = report.render(
        posture, [], profile, configuration, authorisation,
        layers=args.layers, metadata=metadata,
    )
    _emit(document, text, args)
    return posture.exit_code()


def run_observe(args) -> int:
    raise ConfigError("the observer is not built yet")


def run_posture(args) -> int:
    source = Path(args.source)
    if not source.is_file():
        raise ConfigError("saved report not found: %s" % source)
    document = json.loads(source.read_text())
    posture, findings = report.from_dict(document)
    profile = parse_profile(document.get("profile"))
    if args.diff:
        previous = Path(args.diff)
        if not previous.is_file():
            raise ConfigError("previous report not found: %s" % previous)
        print(report.diff(json.loads(previous.read_text()), document))
        print()
    print(report.render(posture, findings, profile, layers=args.layers))
    return posture.exit_code()


def run_doctor(args) -> int:
    diagnosis = doctor.diagnose(args.config, REGISTRY)
    if args.json:
        print(report.to_json(diagnosis.as_dict()))
    else:
        print(doctor.render(diagnosis, args.prog))
    return 0


HANDLERS = {
    "listen": run_listen,
    "audit": run_audit,
    "probe": run_probe,
    "observe": run_observe,
    "posture": run_posture,
    "doctor": run_doctor,
}


def main(argv: list[str] | None = None, prog: str = "netcheck") -> int:
    """Entry point. 0 no control absent, 1 one or more absent, 2 input error."""
    args = build_parser(prog).parse_args(argv)
    args.prog = prog
    try:
        return HANDLERS[args.command](args)
    except ConfigError as error:
        print("error: %s" % error, file=sys.stderr)
        return EXIT_INPUT_ERROR
    except PermissionError:
        print(
            "error: no permission for that operation. Run '%s doctor' to see what "
            "is missing and the command that grants it." % prog,
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR
    except KeyboardInterrupt:
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    sys.exit(main())
