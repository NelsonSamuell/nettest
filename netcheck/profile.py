"""The two operating profiles.

A profile changes what is adjustable, never what is permitted. The hard limits
apply identically in both, and no flag reaches past them.
"""

from __future__ import annotations

from dataclasses import dataclass

SELF = "self"
ENGAGEMENT = "engagement"
PROFILES = (SELF, ENGAGEMENT)

NOT_A_DELIVERABLE = (
    "profile: self. This is a self test of a network the operator owns. It is "
    "not a client deliverable."
)


class ConfigError(Exception):
    """An input, configuration or authorisation problem. The CLI exits 2."""


@dataclass(frozen=True)
class Profile:
    name: str

    @property
    def is_engagement(self) -> bool:
        return self.name == ENGAGEMENT

    @property
    def requires_authorisation(self) -> bool:
        return self.is_engagement

    @property
    def allows_all_tests(self) -> bool:
        """--all is rejected in engagement: checks must be listed explicitly."""
        return not self.is_engagement

    @property
    def budgets_are_ceilings(self) -> bool:
        """In engagement a flag may only lower a budget, never raise it."""
        return self.is_engagement

    def header(self) -> str:
        if self.is_engagement:
            return "profile: engagement"
        return NOT_A_DELIVERABLE


def parse_profile(name: str | None) -> Profile:
    chosen = (name or SELF).strip().lower()
    if chosen not in PROFILES:
        raise ConfigError(
            "unknown profile %r. Known profiles: %s" % (name, ", ".join(PROFILES))
        )
    return Profile(chosen)
