"""Canonical evidence vocabulary for release signal producers."""

from __future__ import annotations


STATUS_CATALOG: dict[str, dict[str, object]] = {
    "passed": {
        "meaning": "The evidence passed its producer's release-readiness check.",
        "decision_effect_when_required": "none",
    },
    "warning": {
        "meaning": "The evidence completed with a non-blocking concern that should be reviewed.",
        "decision_effect_when_required": "review",
    },
    "failed": {
        "meaning": "The evidence failed its producer's release-readiness check.",
        "decision_effect_when_required": "block",
    },
    "blocked": {
        "meaning": "The producer could not proceed because an upstream gate blocked it.",
        "decision_effect_when_required": "block",
    },
    "healthy": {
        "meaning": "The runtime or operational signal is healthy.",
        "decision_effect_when_required": "none",
    },
    "degraded": {
        "meaning": "The runtime or operational signal is degraded but not fully unhealthy.",
        "decision_effect_when_required": "review",
    },
    "unhealthy": {
        "meaning": "The runtime or operational signal is unhealthy.",
        "decision_effect_when_required": "block",
    },
    "missing": {
        "meaning": "Required evidence was expected but was not produced.",
        "decision_effect_when_required": "review",
    },
    "unknown": {
        "meaning": "The producer cannot determine the evidence state.",
        "decision_effect_when_required": "review",
    },
    "skipped": {
        "meaning": "The producer intentionally skipped the evidence check.",
        "decision_effect_when_required": "review",
    },
    "stale": {
        "meaning": "The evidence exists but is not fresh enough for the current change.",
        "decision_effect_when_required": "review",
    },
    "satisfied": {
        "meaning": "An approval or control requirement is satisfied.",
        "decision_effect_when_required": "none",
    },
    "unsatisfied": {
        "meaning": "An approval or control requirement is not satisfied.",
        "decision_effect_when_required": "block",
    },
    "expired": {
        "meaning": "An exception, approval, or evidence validity window has expired.",
        "decision_effect_when_required": "block",
    },
    "valid": {
        "meaning": "A policy, exception, or metadata record is valid.",
        "decision_effect_when_required": "none",
    },
    "invalid": {
        "meaning": "A policy, exception, or metadata record is invalid.",
        "decision_effect_when_required": "block",
    },
    "detected": {
        "meaning": "A change or condition was detected.",
        "decision_effect_when_required": "none",
    },
    "not_detected": {
        "meaning": "A change or condition was not detected.",
        "decision_effect_when_required": "none",
    },
}

EVIDENCE_TYPE_CATALOG: dict[str, dict[str, object]] = {
    "test_result": {
        "category": "test",
        "meaning": "Unit, integration, end-to-end, smoke, regression, migration, or load test results.",
    },
    "ci_check": {
        "category": "ci",
        "meaning": "A CI provider check, job, workflow, or pipeline status.",
    },
    "runtime_signal": {
        "category": "runtime",
        "meaning": "Live readiness signals such as incidents, alerts, canary health, and rollback viability.",
    },
    "security_finding": {
        "category": "security",
        "meaning": "Scanner or security-control evidence, including dependency, code, container, secret, or license risk.",
    },
    "approval_state": {
        "category": "approval",
        "meaning": "Human or system approval requirements and satisfaction state.",
    },
    "change_signal": {
        "category": "change",
        "meaning": "Change-shape evidence such as dependency, infrastructure, migration, API, auth, or data-surface changes.",
    },
    "policy_state": {
        "category": "policy",
        "meaning": "Policy, waiver, exception, or governance metadata validity.",
    },
}

SEVERITY_CATALOG: dict[str, str] = {
    "info": "Informational signal with no inherent release risk.",
    "low": "Low-risk signal that rarely changes release posture alone.",
    "medium": "Moderate signal that may require review when required or combined with other context.",
    "high": "High-risk signal that often requires review or blocking when required.",
    "critical": "Critical signal that should generally block release when required.",
}


def evidence_catalog() -> dict[str, object]:
    """Return the public evidence vocabulary for adapters and producers."""

    return {
        "schema_version": 1,
        "statuses": STATUS_CATALOG,
        "evidence_types": EVIDENCE_TYPE_CATALOG,
        "severities": SEVERITY_CATALOG,
    }
