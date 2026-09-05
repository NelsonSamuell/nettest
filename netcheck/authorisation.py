"""The engagement authorisation file.

Only the engagement profile reads this. Every check runs before a single frame
or packet leaves, and there is no override flag for any of them.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable, Iterable

import yaml

from netcheck.profile import ConfigError

REQUIRED_FIELDS = (
    "client",
    "engagement",
    "authorised_by",
    "contact",
    "issued",
    "expires",
    "segment",
    "scope_subnets",
)


@dataclass(frozen=True)
class Authorisation:
    client: str
    engagement: str
    authorised_by: str
    contact: str
    issued: date
    expires: date
    segment: str
    scope_subnets: tuple[str, ...]
    sha256: str
    path: str

    def window(self) -> str:
        return "%s to %s inclusive" % (self.issued.isoformat(), self.expires.isoformat())

    def as_dict(self) -> dict:
        return {
            "file": self.path,
            "sha256": self.sha256,
            "client": self.client,
            "engagement": self.engagement,
            "authorised_by": self.authorised_by,
            "contact": self.contact,
            "segment": self.segment,
            "window": self.window(),
            "scope_subnets": list(self.scope_subnets),
        }


def file_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _as_date(value: object, name: str) -> date:
    if isinstance(value, date):
        return value
    raise ConfigError("authorisation field %r must be a date in YYYY-MM-DD form" % name)


def load(path: str | Path, today: date | None = None) -> Authorisation:
    """Read, validate and date check the authorisation file."""
    location = Path(path)
    if not location.is_file():
        raise ConfigError("authorisation file not found: %s" % location)

    document = yaml.safe_load(location.read_text())
    if not isinstance(document, dict):
        raise ConfigError("authorisation file is not a YAML mapping: %s" % location)

    for name in REQUIRED_FIELDS:
        if name not in document:
            raise ConfigError("authorisation file is missing field %r" % name)
        value = document[name]
        empty = value is None or (isinstance(value, str) and not value.strip())
        if empty or (isinstance(value, list) and not value):
            raise ConfigError("authorisation field %r is empty" % name)

    issued = _as_date(document["issued"], "issued")
    expires = _as_date(document["expires"], "expires")
    if expires < issued:
        raise ConfigError(
            "authorisation window ends before it begins: %s to %s"
            % (issued.isoformat(), expires.isoformat())
        )

    now = today or date.today()
    if now < issued or now > expires:
        raise ConfigError(
            "authorisation is outside its window: valid %s to %s inclusive, "
            "today is %s" % (issued.isoformat(), expires.isoformat(), now.isoformat())
        )

    scope = [str(item) for item in document["scope_subnets"]]
    for entry in scope:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as error:
            raise ConfigError("bad scope subnet %r: %s" % (entry, error))

    return Authorisation(
        client=str(document["client"]).strip(),
        engagement=str(document["engagement"]).strip(),
        authorised_by=str(document["authorised_by"]).strip(),
        contact=str(document["contact"]).strip(),
        issued=issued,
        expires=expires,
        segment=str(document["segment"]).strip(),
        scope_subnets=tuple(scope),
        sha256=file_sha256(location),
        path=str(location),
    )


def check_scope(authorisation: Authorisation, subnets: Iterable[str]) -> None:
    """Every target subnet must sit inside a scope subnet.

    Containment is exact: a target is in scope only when a listed subnet is a
    supernet of it. No wildcards, and a target wider than the scope fails.
    """
    allowed = [ipaddress.ip_network(entry, strict=False) for entry in authorisation.scope_subnets]
    for subnet in subnets:
        target = ipaddress.ip_network(subnet, strict=False)
        if not any(target.subnet_of(entry) for entry in allowed if entry.version == target.version):
            raise ConfigError(
                "target %s is outside the authorised scope (%s)"
                % (subnet, ", ".join(authorisation.scope_subnets))
            )


def confirm_segment(
    authorisation: Authorisation,
    supplied: str | None = None,
    prompt: Callable[[str], str] = input,
    out: Callable[[str], None] = print,
) -> None:
    """Require the segment string to be retyped exactly.

    This is what stops a probe running on the wrong port after a lunch break.
    """
    if supplied is None:
        out("Authorised segment: %s" % authorisation.segment)
        supplied = prompt("Retype the segment exactly to continue: ")
    if supplied != authorisation.segment:
        raise ConfigError(
            "segment confirmation does not match the authorisation: expected %r"
            % authorisation.segment
        )
