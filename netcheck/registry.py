"""The check registry.

Every check declares the capabilities it needs. A check whose requirements are
unmet is skipped before it runs, and the reason distinguishes a platform that
cannot do it from a privilege that has not been granted: the first cannot be
fixed, the second tells the operator what command to run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from netcheck.models import (
    BUDGET_EXHAUSTED,
    NOT_SELECTED,
    UNTESTED,
)
from netcheck.platform.detect import CAPABILITIES, CapabilitySet

L2P = "L2P"
L2A = "L2A"
L3P = "L3P"
L3A = "L3A"
CFG = "CFG"
PREFIXES = (L2P, L2A, L3P, L3A, CFG)

PASSIVE_PREFIXES = (L2P, L3P, CFG)


@dataclass
class Check:
    """One check, what it needs, and what it can establish."""

    identifier: str
    title: str
    controls: tuple[str, ...] = ()
    requires: frozenset[str] = frozenset()
    depends_on: tuple[str, ...] = ()
    run: Callable | None = None

    @property
    def prefix(self) -> str:
        return self.identifier[:3]

    @property
    def is_passive(self) -> bool:
        return self.prefix in PASSIVE_PREFIXES


@dataclass
class Skipped:
    identifier: str
    reason: str
    detail: str = ""


@dataclass
class Registry:
    checks: dict[str, Check] = field(default_factory=dict)

    def register(self, check: Check) -> Check:
        if check.prefix not in PREFIXES:
            raise ValueError("unknown check prefix: %s" % check.identifier)
        unknown = set(check.requires) - set(CAPABILITIES)
        if unknown:
            raise ValueError(
                "%s declares unknown capabilities: %s"
                % (check.identifier, ", ".join(sorted(unknown)))
            )
        if check.identifier in self.checks:
            raise ValueError("%s is already registered" % check.identifier)
        self.checks[check.identifier] = check
        return check

    def identifiers(self) -> list[str]:
        """Every registered check, in dependency order.

        Passive completes before active, and a check that reads another's output
        runs after it. Sorting by identifier alone would run L3A08 before L3P04.
        """
        return sorted(self.checks, key=self._order)

    def _order(self, identifier: str) -> tuple:
        check = self.checks[identifier]
        return (0 if check.is_passive else 1, len(check.depends_on), identifier)

    def resolve(
        self,
        selected: list[str],
        capabilities: CapabilitySet,
        budget=None,
    ) -> tuple[list[str], list[Skipped]]:
        """Split the selection into what can run and what cannot, with reasons."""
        runnable: list[str] = []
        skipped: list[Skipped] = []
        for identifier in sorted(selected, key=self._order):
            check = self.checks.get(identifier)
            if check is None:
                skipped.append(Skipped(identifier, NOT_SELECTED, "not registered"))
                continue
            reason = capabilities.reason_for(check.requires)
            if reason:
                missing = capabilities.missing(check.requires)
                skipped.append(
                    Skipped(
                        identifier,
                        reason,
                        "needs %s" % ", ".join(c.name for c in missing),
                    )
                )
                continue
            if budget is not None and not check.is_passive:
                from netcheck.budget import LAYER2, LAYER3

                layer = LAYER2 if check.prefix == L2A else LAYER3
                if budget.exhausted(layer):
                    skipped.append(Skipped(identifier, BUDGET_EXHAUSTED, ""))
                    continue
            runnable.append(identifier)
        return runnable, skipped


REGISTRY = Registry()


def skipped_controls(skipped: list[Skipped], registry: Registry, posture) -> None:
    """Record why a control was not established, never as ABSENT."""
    for entry in skipped:
        check = registry.checks.get(entry.identifier)
        if check is None:
            continue
        for control in check.controls:
            posture.set(
                control,
                UNTESTED,
                entry.identifier,
                entry.detail or entry.reason,
            )
