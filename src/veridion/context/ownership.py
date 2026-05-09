"""Ownership and team-trust context parsed from optional PR metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OwnershipSignals:
    """Ownership and team trust metadata for a change surface."""

    service_owner: str = ""
    owning_team: str = ""
    review_coverage: str = ""
    team_trust_level: str = ""
    oncall_defined: bool = False

    @property
    def elevated_signals(self) -> tuple[str, ...]:
        if not any((self.service_owner, self.owning_team, self.review_coverage, self.team_trust_level, self.oncall_defined)):
            return ()

        signals: list[str] = []

        if not self.service_owner:
            signals.append("service owner missing")
        if self.review_coverage == "cross_team":
            signals.append("review coverage: cross team")
        if self.team_trust_level in {"low", "degrading"}:
            signals.append(f"team trust: {self.team_trust_level}")
        if not self.oncall_defined:
            signals.append("on-call coverage missing")

        return tuple(signals)


def parse_ownership_signals(payload: dict[str, object]) -> OwnershipSignals:
    """Parse ownership and team trust context from a permissive metadata payload."""

    raw = payload.get("ownership")
    if not isinstance(raw, dict):
        return OwnershipSignals()

    return OwnershipSignals(
        service_owner=_as_string(raw.get("service_owner")),
        owning_team=_as_string(raw.get("owning_team")),
        review_coverage=_normalize_value(raw.get("review_coverage"), {"single_team", "cross_team"}),
        team_trust_level=_normalize_value(raw.get("team_trust_level"), {"high", "medium", "low", "degrading"}),
        oncall_defined=_as_bool(raw.get("oncall_defined")),
    )


def _normalize_value(value: object, allowed: set[str]) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    return normalized if normalized in allowed else ""


def _as_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False
