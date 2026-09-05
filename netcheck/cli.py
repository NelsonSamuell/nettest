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
from netcheck.abort import AbortWatcher, StateChanged
from netcheck.authorisation import check_scope, confirm_segment
from netcheck.authorisation import load as load_authorisation
from netcheck.budget import Budget, CapExceeded, validate_max_macs
from netcheck.l3.probes.upnp import CleanupFailed
from netcheck.models import MAX_MACS_DEFAULT, Posture
from netcheck.platform.detect import detect
from netcheck.profile import ConfigError, parse_profile
from netcheck.registry import REGISTRY, Context, skipped_controls

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


def registry() -> "object":
    """The registry with every built check registered."""
    from netcheck.l2 import register as register_l2
    from netcheck.l3 import register as register_l3

    if not REGISTRY.checks:
        register_l3(register_l2(REGISTRY))
    return REGISTRY


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


def capture_host(capture: dict | None) -> dict | None:
    """The CFG02 section, kept apart because it is about this machine."""
    return (capture or {}).get("host")


def _finish(args, profile, configuration, posture, findings, interface, **extra) -> int:
    started = extra.pop("started", datetime.datetime.now(datetime.timezone.utc))
    metadata = _metadata(started, interface)
    document = report.to_dict(
        posture, findings, profile, configuration, metadata=metadata, **extra
    )
    text = report.render(
        posture, findings, profile, configuration,
        authorisation=extra.get("authorisation"),
        layers=getattr(args, "layers", "both"),
        matrix=extra.get("matrix"),
        devices=extra.get("devices"),
        host=capture_host(extra.get("capture")),
        metadata=metadata,
    )
    _emit(document, text, args)
    return posture.exit_code()


def _passive(interface: str, duration: int, capabilities, posture, config=None,
             router_config: str | None = None):
    """Capture, read the offline checks, and fold both into the posture.

    The offline checks need no capture and no privilege, so they run even when
    the interface cannot be listened to.
    """
    from netcheck.cfg import host_posture, router_config as router_config_module
    from netcheck.l2 import apply_passive as apply_l2, findings as findings_l2
    from netcheck.l3 import apply_passive as apply_l3, findings as findings_l3
    from netcheck.l3.listen import listen
    from netcheck.models import Capture

    known = registry()
    passive = [i for i in known.identifiers() if known.checks[i].is_passive]
    runnable, skipped = known.resolve(passive, capabilities)
    skipped_controls(skipped, known, posture)

    if "CFG02" in runnable:
        capture_only = Capture(interface=interface, duration=duration)
        capture_only.host_posture = host_posture.read()
    else:
        capture_only = Capture(interface=interface, duration=duration)

    if any(i.startswith(("L2P", "L3P")) for i in runnable):
        listened = listen(interface, duration)
        listened.host_posture = capture_only.host_posture
        capture = listened
    else:
        capture = capture_only

    if router_config:
        capture.router_config = router_config_module.parse(router_config)

    apply_l2(posture, capture)
    apply_l3(posture, capture)
    findings = report.sort_findings(findings_l2(capture) + findings_l3(capture))
    return capture, findings


def run_listen(args) -> int:
    interface = resolve_interface(args)
    profile = parse_profile("self")
    configuration = config_module.load(args.config, interface)
    started = datetime.datetime.now(datetime.timezone.utc)
    posture = Posture.new()
    capture, findings = _passive(
        interface, args.duration, detect(), posture, configuration
    )
    devices, matrix, findings = _correlate(capture, configuration, posture, findings)
    return _finish(
        args, profile, configuration, posture, findings, interface,
        started=started, capture=capture.as_dict(), devices=devices, matrix=matrix,
    )


def _correlate(capture, configuration, posture, findings):
    """Join the layers, then add the findings only the join can produce."""
    from netcheck.correlate import correlate, findings as correlation_findings, reachability

    devices = correlate(capture, configuration)
    matrix = reachability(capture, None, configuration)
    combined = report.sort_findings(
        [f for f in findings if not f.check.startswith("COR")]
        + correlation_findings(devices, posture, capture)
    )
    return [d.as_dict() for d in devices], matrix, combined


def run_audit(args) -> int:
    """Offline audit. Sends nothing and needs no interface."""
    from netcheck.cfg import host_posture, router_config as router_config_module
    from netcheck.l3 import apply_passive as apply_l3, findings as findings_l3
    from netcheck.models import Capture

    profile = parse_profile("self")
    configuration = config_module.load(None)
    posture = Posture.new()
    capture = Capture()
    capture.host_posture = host_posture.read()
    if args.config:
        capture.router_config = router_config_module.parse(args.config)
    apply_l3(posture, capture)
    findings = report.sort_findings(findings_l3(capture))
    return _finish(
        args, profile, configuration, posture, findings, "",
        capture=capture.as_dict(),
    )


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

    diagnosis = doctor.diagnose(args.config, registry())
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
    capabilities = detect()
    capture, findings = _passive(
        interface, args.duration, capabilities, posture, configuration
    )

    known = registry()
    selected = (
        [i for i in known.identifiers() if not known.checks[i].is_passive]
        if args.all
        else [t.strip().upper() for t in args.tests.split(",") if t.strip()]
    )
    unknown = [i for i in selected if i not in known.checks]
    if unknown:
        raise ConfigError(
            "unknown check identifier: %s. Known checks: %s"
            % (", ".join(unknown), ", ".join(known.identifiers()))
        )

    runnable, skipped = known.resolve(selected, capabilities, budget)
    skipped_controls(skipped, known, posture)
    for entry in skipped:
        print("skipping %s: %s %s" % (entry.identifier, entry.reason, entry.detail),
              file=sys.stderr)

    context = Context(
        interface=interface, config=configuration, budget=budget, abort=watcher,
        capabilities=capabilities, profile=profile, capture=capture,
        test_ip=args.test_ip or "", observer=configuration.internal_observer,
        max_macs=args.max_macs,
    )
    context.start()

    try:
        for identifier in runnable:
            check = known.checks[identifier]
            if check.run is None:
                continue
            watcher.current_check = identifier
            try:
                outcome = check.run(context)
            except CapExceeded as error:
                print("stopping: %s" % error, file=sys.stderr)
                break
            except StateChanged as error:
                print("stopping during %s: %s" % (error.during, error.detail),
                      file=sys.stderr)
                break
            except CleanupFailed as error:
                # A check could not undo what it wrote. Halting is the point.
                print("stopping during %s: %s" % (identifier, error), file=sys.stderr)
                break
            state, basis, detail = outcome[0], outcome[1], outcome[2]
            findings = findings + list(outcome[3]) if len(outcome) > 3 else findings
            for control in check.controls:
                posture.set(control, state, basis, detail)
    finally:
        watcher.current_check = None
        context.run_cleanup()

    findings = report.sort_findings(findings)
    devices, matrix, findings = _correlate(capture, configuration, posture, findings)
    return _finish(
        args, profile, configuration, posture, findings, interface,
        started=started, authorisation=authorisation, budget=budget,
        abort=watcher.as_dict(), capture=capture.as_dict(),
        devices=devices, matrix=matrix,
    )


def run_observe(args) -> int:
    from netcheck.observe import Observer

    interface = resolve_interface(args)
    Observer(interface, args.port, args.side).serve()
    return 0


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
    diagnosis = doctor.diagnose(args.config, registry())
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
