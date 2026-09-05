"""The two budgets, the runtime cap and the send rate.

Layer 2 frames and layer 3 packets decrement independently, because one ceiling
covering both would let a sweep starve the checks that need a handful of frames.

The rate cap is the one limit no flag reaches past, in either profile. Above
roughly a thousand packets per second consumer gateways drop responses
selectively and every silence in the report becomes ambiguous, so it is a
measurement constraint as much as a safety one.
"""

from __future__ import annotations

from dataclasses import dataclass

from netcheck.profile import ConfigError, Profile

FRAME_BUDGET = 600
PACKET_BUDGET = 5000
RUNTIME_MINUTES = 15
RATE_PPS = 200
RATE_HARD_CAP = 1000

MAX_MACS = 50
MAX_MACS_HARD_CAP = 500

LAYER2 = 2
LAYER3 = 3


class CapExceeded(Exception):
    """A budget, runtime or rate limit was reached."""


def validate_rate(value: int) -> int:
    """The rate cap. No profile and no flag raises this."""
    if value < 1:
        raise ConfigError("send rate must be at least 1 packet per second")
    if value > RATE_HARD_CAP:
        raise ConfigError(
            "send rate may not exceed %d packets per second in any profile. "
            "Above that, consumer gateways drop responses selectively and every "
            "silence in the report becomes ambiguous. Use nmap for a faster sweep."
            % RATE_HARD_CAP
        )
    return value


def validate_max_macs(value: int) -> int:
    """The port security walk length. Hard capped in code, not in help text."""
    if value < 1:
        raise ConfigError("--max-macs must be at least 1")
    if value > MAX_MACS_HARD_CAP:
        raise ConfigError(
            "--max-macs may not exceed %d, got %d" % (MAX_MACS_HARD_CAP, value)
        )
    return value


def _resolve(name: str, requested: int | None, default: int, profile: Profile) -> int:
    """Apply a flag against a default, honouring whether the profile caps it."""
    if requested is None:
        return default
    if requested < 1:
        raise ConfigError("%s must be at least 1" % name)
    if profile.budgets_are_ceilings and requested > default:
        raise ConfigError(
            "%s may not exceed %d in the engagement profile, where the defaults "
            "are ceilings. A flag may only lower them." % (name, default)
        )
    return requested


@dataclass
class Budget:
    frames: int = FRAME_BUDGET
    packets: int = PACKET_BUDGET
    runtime_seconds: int = RUNTIME_MINUTES * 60
    rate_pps: int = RATE_PPS
    frames_sent: int = 0
    packets_sent: int = 0

    @classmethod
    def resolve(
        cls,
        profile: Profile,
        frame_budget: int | None = None,
        packet_budget: int | None = None,
        runtime_minutes: int | None = None,
        rate_pps: int | None = None,
        defaults: "Budget | None" = None,
    ) -> "Budget":
        """Build a budget from flags, defaults and the profile's rules."""
        base = defaults or cls()
        return cls(
            frames=_resolve("--frame-budget", frame_budget, base.frames, profile),
            packets=_resolve("--packet-budget", packet_budget, base.packets, profile),
            runtime_seconds=_resolve(
                "--runtime", runtime_minutes, base.runtime_seconds // 60, profile
            )
            * 60,
            rate_pps=validate_rate(
                _resolve("--rate", rate_pps, base.rate_pps, profile)
            ),
        )

    def remaining(self, layer: int) -> int:
        if layer == LAYER2:
            return self.frames - self.frames_sent
        return self.packets - self.packets_sent

    def spend(self, layer: int, count: int) -> None:
        """Take from one budget, all or nothing."""
        if count > self.remaining(layer):
            raise CapExceeded(
                "layer %d budget of %d reached after %d"
                % (
                    layer,
                    self.frames if layer == LAYER2 else self.packets,
                    self.frames_sent if layer == LAYER2 else self.packets_sent,
                )
            )
        if layer == LAYER2:
            self.frames_sent += count
        else:
            self.packets_sent += count

    def exhausted(self, layer: int) -> bool:
        return self.remaining(layer) <= 0

    def as_dict(self) -> dict:
        return {
            "frame_budget": self.frames,
            "frames_sent": self.frames_sent,
            "frames_remaining": self.remaining(LAYER2),
            "packet_budget": self.packets,
            "packets_sent": self.packets_sent,
            "packets_remaining": self.remaining(LAYER3),
            "runtime_seconds": self.runtime_seconds,
            "rate_pps": self.rate_pps,
        }
