"""The authorisation gate and the global safety caps.

Nothing in this package puts a frame on the wire except
:meth:`ActiveSession.send`, and that method refuses until the gate has passed.
The caps are held here rather than in the probes so that no probe can raise its
own ceiling: a probe can only ask the session to send, and the session counts.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Iterable

import yaml
from scapy.sendrecv import sendp

REQUIRED_FIELDS = (
    "client",
    "engagement",
    "authorised_by",
    "contact",
    "issued",
    "expires",
    "segment",
    "change_window",
)

ACTIVE_CHECKS = (
    "L2A01",
    "L2A02",
    "L2A03",
    "L2A04",
    "L2A05",
    "L2A06",
    "L2A07",
)

# Global caps for one active run. These are ceilings across every probe
# selected, not per probe budgets.
TOTAL_FRAME_CAP = 600
TOTAL_RUNTIME_CAP = 600
MAX_MACS_CAP = 500
DEFAULT_MAX_MACS = 50


class AuthorisationError(Exception):
    """An input or authorisation problem. The CLI turns this into exit 2."""


class CapExceeded(Exception):
    """A global frame or runtime cap was reached."""


class LinkStateChanged(Exception):
    """The interface link state changed when no probe expected it to."""


class NotAuthorised(Exception):
    """A send was attempted before the gate passed."""


@dataclass(frozen=True)
class Authorisation:
    client: str
    engagement: str
    authorised_by: str
    contact: str
    issued: date
    expires: date
    segment: str
    change_window: bool
    sha256: str
    path: str

    def window(self) -> str:
        return "%s to %s inclusive" % (self.issued.isoformat(), self.expires.isoformat())


def file_sha256(path: str | Path) -> str:
    """Return the SHA-256 of the authorisation file, for the report."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _as_date(value: object, name: str) -> date:
    if isinstance(value, date):
        return value
    raise AuthorisationError(
        "authorisation field '%s' must be a date in YYYY-MM-DD form" % name
    )


def load_authorisation(path: str | Path, today: date | None = None) -> Authorisation:
    """Read, validate and date check an authorisation file.

    Raises AuthorisationError for a missing field, an empty field, or a date
    outside the window. There is no override.
    """
    location = Path(path)
    if not location.is_file():
        raise AuthorisationError("authorisation file not found: %s" % location)

    document = yaml.safe_load(location.read_text())
    if not isinstance(document, dict):
        raise AuthorisationError("authorisation file is not a YAML mapping: %s" % location)

    for name in REQUIRED_FIELDS:
        if name not in document:
            raise AuthorisationError("authorisation file is missing field '%s'" % name)
        value = document[name]
        if value is None or (isinstance(value, str) and not value.strip()):
            raise AuthorisationError("authorisation field '%s' is empty" % name)

    if not isinstance(document["change_window"], bool):
        raise AuthorisationError("authorisation field 'change_window' must be true or false")

    issued = _as_date(document["issued"], "issued")
    expires = _as_date(document["expires"], "expires")
    if expires < issued:
        raise AuthorisationError(
            "authorisation window ends before it begins: %s to %s"
            % (issued.isoformat(), expires.isoformat())
        )

    now = today or date.today()
    if now < issued or now > expires:
        raise AuthorisationError(
            "authorisation is outside its window: valid %s to %s inclusive, today is %s"
            % (issued.isoformat(), expires.isoformat(), now.isoformat())
        )

    return Authorisation(
        client=str(document["client"]).strip(),
        engagement=str(document["engagement"]).strip(),
        authorised_by=str(document["authorised_by"]).strip(),
        contact=str(document["contact"]).strip(),
        issued=issued,
        expires=expires,
        segment=str(document["segment"]).strip(),
        change_window=document["change_window"],
        sha256=file_sha256(location),
        path=str(location),
    )


def parse_tests(value: str | None) -> list[str]:
    """Turn --tests into a validated list of probe identifiers."""
    if value is None or not value.strip():
        raise AuthorisationError(
            "--tests is required in active mode and must name specific probes: %s"
            % ", ".join(ACTIVE_CHECKS)
        )
    requested = [item.strip().upper() for item in value.split(",") if item.strip()]
    if not requested:
        raise AuthorisationError("--tests is empty")
    unknown = [item for item in requested if item not in ACTIVE_CHECKS]
    if unknown:
        raise AuthorisationError(
            "unknown probe identifier: %s. Known probes: %s"
            % (", ".join(unknown), ", ".join(ACTIVE_CHECKS))
        )
    ordered = []
    for item in requested:
        if item not in ordered:
            ordered.append(item)
    return ordered


def validate_max_macs(value: int) -> int:
    """Clamp check for --max-macs. The cap lives here, not in argument help."""
    if value < 1:
        raise AuthorisationError("--max-macs must be at least 1")
    if value > MAX_MACS_CAP:
        raise AuthorisationError(
            "--max-macs may not exceed %d, got %d" % (MAX_MACS_CAP, value)
        )
    return value


def confirm_segment(
    authorisation: Authorisation,
    supplied: str | None = None,
    prompt: Callable[[str], str] = input,
    out: Callable[[str], None] = print,
) -> None:
    """Require the segment string to be retyped exactly before any frame is sent.

    This is the check that stops a probe running on the wrong port after a
    lunch break.
    """
    if supplied is None:
        out("Authorised segment: %s" % authorisation.segment)
        supplied = prompt("Retype the segment exactly to continue: ")
    if supplied != authorisation.segment:
        raise AuthorisationError(
            "segment confirmation does not match the authorisation: expected %r"
            % authorisation.segment
        )


def link_state(interface: str) -> str:
    """Return the kernel's operstate for the interface, or 'unknown'."""
    path = Path("/sys/class/net") / interface / "operstate"
    if not path.exists():
        return "unknown"
    return path.read_text().strip()


def _send_frame(interface: str, frame: bytes) -> None:
    sendp(frame, iface=interface, verbose=False)


@dataclass
class ActiveSession:
    """The only route from a probe to the wire.

    A probe holds one of these and calls :meth:`send`. It has no other way to
    transmit, so the frame budget, the runtime cap and the gate itself cannot be
    bypassed by a probe getting it wrong.
    """

    interface: str
    authorisation: Authorisation | None = None
    tests: list[str] = field(default_factory=list)
    max_macs: int = DEFAULT_MAX_MACS
    test_ip: str | None = None
    observer: str | None = None
    frame_cap: int = TOTAL_FRAME_CAP
    runtime_cap: int = TOTAL_RUNTIME_CAP
    sender: Callable[[str, bytes], None] = _send_frame
    clock: Callable[[], float] = time.monotonic
    frames_sent: int = 0
    authorised: bool = False
    link_change_expected: bool = False
    _started_at: float | None = None
    _baseline_link: str = ""

    def authorise(self, authorisation: Authorisation, tests: Iterable[str]) -> None:
        """Open the gate. Called once, after every check in the gate has passed."""
        selected = list(tests)
        if not selected:
            raise AuthorisationError("no probes selected")
        self.authorisation = authorisation
        self.tests = selected
        self.authorised = True
        self._started_at = self.clock()
        self._baseline_link = link_state(self.interface)

    @property
    def frames_remaining(self) -> int:
        return self.frame_cap - self.frames_sent

    @property
    def elapsed(self) -> float:
        if self._started_at is None:
            return 0.0
        return self.clock() - self._started_at

    def check_runtime(self) -> None:
        if self.elapsed > self.runtime_cap:
            raise CapExceeded(
                "total runtime cap of %d seconds reached" % self.runtime_cap
            )

    def check_link(self) -> None:
        """Hard stop if the link changed when no probe was expecting it to."""
        if self.link_change_expected:
            return
        current = link_state(self.interface)
        if current != self._baseline_link:
            raise LinkStateChanged(
                "interface %s went from %s to %s"
                % (self.interface, self._baseline_link, current)
            )

    def send(self, frames: bytes | Iterable[bytes]) -> int:
        """Transmit one or more frames, counting them against the global cap."""
        if not self.authorised:
            raise NotAuthorised(
                "the authorisation gate has not passed, so no frame may be sent"
            )
        batch = [frames] if isinstance(frames, (bytes, bytearray)) else list(frames)
        self.check_runtime()
        self.check_link()
        if self.frames_sent + len(batch) > self.frame_cap:
            raise CapExceeded(
                "total frame cap of %d reached after %d frames"
                % (self.frame_cap, self.frames_sent)
            )
        for frame in batch:
            self.sender(self.interface, bytes(frame))
            self.frames_sent += 1
        return len(batch)
