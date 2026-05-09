"""Shared labels and trigger names for policy-facing output."""

APPROVAL_LABELS = {
    "platform_owner": "platform owner",
    "security_owner": "security owner",
    "service_owner": "service owner",
    "sre_owner": "SRE owner",
}

VALID_POLICY_TRIGGERS = (
    "repo_criticality_high",
    "service_criticality_high",
    "historical_instability",
    "flaky_service",
    "sensitive_repo",
)
