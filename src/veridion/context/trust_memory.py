"""Longitudinal trust-memory signals from recent decision history."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TrustMemorySignals:
    """Recent decision-memory signals for repo, service, and team trust."""

    recent_decisions_30d: int = 0
    conditional_go_count_30d: int = 0
    no_go_count_30d: int = 0
    policy_override_count_30d: int = 0
    accepted_risk_exception_count: int = 0
    mean_rdi_score_30d: float | None = None

    @property
    def elevated_signals(self) -> tuple[str, ...]:
        signals: list[str] = []

        if self.no_go_count_30d >= 3:
            signals.append(f"recent no-go decisions: {self.no_go_count_30d}")
        if self.conditional_go_count_30d >= 5:
            signals.append(f"recent conditional-go decisions: {self.conditional_go_count_30d}")
        if self.policy_override_count_30d >= 2:
            signals.append(f"policy overrides in 30d: {self.policy_override_count_30d}")
        if self.accepted_risk_exception_count >= 5:
            signals.append(f"accepted-risk exceptions in 30d: {self.accepted_risk_exception_count}")
        if self.mean_rdi_score_30d is not None and self.mean_rdi_score_30d < 70:
            signals.append(f"mean 30d RDI score: {self.mean_rdi_score_30d:.0f}")

        return tuple(signals)


def parse_trust_memory_signals(payload: dict[str, object]) -> TrustMemorySignals:
    """Parse longitudinal trust-memory signals from a permissive payload."""

    raw = payload.get("trust_memory")
    if not isinstance(raw, dict):
        return TrustMemorySignals()

    return TrustMemorySignals(
        recent_decisions_30d=_as_int(raw.get("recent_decisions_30d")),
        conditional_go_count_30d=_as_int(raw.get("conditional_go_count_30d")),
        no_go_count_30d=_as_int(raw.get("no_go_count_30d")),
        policy_override_count_30d=_as_int(raw.get("policy_override_count_30d")),
        accepted_risk_exception_count=_as_int(raw.get("accepted_risk_exception_count")),
        mean_rdi_score_30d=_as_float(raw.get("mean_rdi_score_30d")),
    )


def _as_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _as_float(value: object) -> float | None:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None
