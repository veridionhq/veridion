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
    "production_deployment",
    "public_exposure",
    "large_blast_radius",
    "after_hours_deploy",
    "low_team_trust",
    "unowned_service",
    "missing_oncall",
    "cross_team_change",
)
