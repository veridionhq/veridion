"""Shared text helpers for policy-facing output."""

from __future__ import annotations

import re

from veridion.policy.labels import APPROVAL_LABELS

SEVERITY_ISSUE_REASON_RE = re.compile(
    r"^\d+ new (critical|high|medium|low|info|unknown)-severity (?:issues?|issue\(s\)) detected$"
)


def format_approval_label(value: str) -> str:
    """Render a stable human label for an approval role."""

    return APPROVAL_LABELS.get(value, value.replace("_", " "))


def filter_approval_echo_recommendations(
    recommendations: tuple[str, ...],
    required_approvals: tuple[str, ...],
) -> tuple[str, ...]:
    """Remove approval-echo recommendations that duplicate explicit approval fields."""

    blocked = {f"Require approval from the {format_approval_label(value)}" for value in required_approvals}
    return tuple(item for item in recommendations if item not in blocked)
