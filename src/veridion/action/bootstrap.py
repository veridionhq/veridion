"""Scaffold a first-install Veridion setup from a starter preset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


POLICY_PACKS = {
    "application-team": """max_severity: critical
allow_conditional: true
no_go_below_score: 60
conditional_go_below_score: 85
require_approval_for:
  - production_iac
  - dependency_changes
require_platform_owner_for:
  - production_deployment
  - large_blast_radius
require_service_owner_for:
  - repo_criticality_high
  - service_criticality_high
  - payments_surface
  - auth_surface
require_sre_owner_for:
  - historical_instability
  - after_hours_deploy
  - database_migration_surface
require_security_owner_for:
  - sensitive_repo
  - public_exposure
  - dependency_reputation_risk
  - payments_surface
  - auth_surface
historical_instability_score_penalty: 0
service_criticality_score_penalty: 0
sensitive_repo_score_penalty: 0
ai_signal_score_penalty: 0
ai_authored_commit_score_penalty: 0
production_deployment_score_penalty: 0
after_hours_deploy_score_penalty: 0
public_exposure_score_penalty: 0
large_blast_radius_score_penalty: 0
low_team_trust_score_penalty: 0
unowned_service_score_penalty: 0
missing_oncall_score_penalty: 0
cross_team_change_score_penalty: 0
repo_fragility_score_penalty: 0
service_fragility_score_penalty: 0
low_test_coverage_score_penalty: 0
weak_rollback_readiness_score_penalty: 0
dependency_reputation_risk_score_penalty: 0
low_team_deploy_safety_score_penalty: 0
shared_platform_surface_score_penalty: 0
database_migration_surface_score_penalty: 0
payments_surface_score_penalty: 0
auth_surface_score_penalty: 0
data_surface_score_penalty: 0
""",
    "platform-team": """max_severity: critical
allow_conditional: true
no_go_below_score: 65
conditional_go_below_score: 88
require_approval_for:
  - production_iac
  - dependency_changes
require_platform_owner_for:
  - production_deployment
  - large_blast_radius
  - weak_rollback_readiness
  - shared_platform_surface
  - database_migration_surface
require_service_owner_for:
  - service_criticality_high
  - low_team_trust
  - low_test_coverage
  - payments_surface
  - auth_surface
  - data_surface
require_sre_owner_for:
  - historical_instability
  - flaky_service
  - after_hours_deploy
  - missing_oncall
  - service_fragility
  - low_team_deploy_safety
  - shared_platform_surface
  - database_migration_surface
  - data_surface
require_security_owner_for:
  - sensitive_repo
  - public_exposure
  - dependency_reputation_risk
  - payments_surface
  - auth_surface
  - data_surface
historical_instability_score_penalty: 3
service_criticality_score_penalty: 0
sensitive_repo_score_penalty: 0
ai_signal_score_penalty: 0
ai_authored_commit_score_penalty: 0
production_deployment_score_penalty: 0
after_hours_deploy_score_penalty: 0
public_exposure_score_penalty: 0
large_blast_radius_score_penalty: 0
low_team_trust_score_penalty: 0
unowned_service_score_penalty: 0
missing_oncall_score_penalty: 0
cross_team_change_score_penalty: 0
repo_fragility_score_penalty: 0
service_fragility_score_penalty: 0
low_test_coverage_score_penalty: 0
weak_rollback_readiness_score_penalty: 0
dependency_reputation_risk_score_penalty: 0
low_team_deploy_safety_score_penalty: 0
shared_platform_surface_score_penalty: 2
database_migration_surface_score_penalty: 2
payments_surface_score_penalty: 0
auth_surface_score_penalty: 0
data_surface_score_penalty: 0
""",
    "regulated-service": """max_severity: critical
allow_conditional: false
no_go_below_score: 70
conditional_go_below_score: 90
require_approval_for:
  - production_iac
  - dependency_changes
require_platform_owner_for:
  - production_deployment
  - large_blast_radius
  - weak_rollback_readiness
  - shared_platform_surface
  - database_migration_surface
require_service_owner_for:
  - repo_criticality_high
  - service_criticality_high
  - low_team_trust
  - low_test_coverage
  - payments_surface
  - auth_surface
  - data_surface
require_sre_owner_for:
  - historical_instability
  - flaky_service
  - after_hours_deploy
  - missing_oncall
  - service_fragility
  - low_team_deploy_safety
  - shared_platform_surface
  - database_migration_surface
  - data_surface
require_security_owner_for:
  - sensitive_repo
  - public_exposure
  - dependency_reputation_risk
  - payments_surface
  - auth_surface
  - data_surface
historical_instability_score_penalty: 5
service_criticality_score_penalty: 4
sensitive_repo_score_penalty: 4
ai_signal_score_penalty: 0
ai_authored_commit_score_penalty: 0
production_deployment_score_penalty: 4
after_hours_deploy_score_penalty: 3
public_exposure_score_penalty: 3
large_blast_radius_score_penalty: 4
low_team_trust_score_penalty: 2
unowned_service_score_penalty: 2
missing_oncall_score_penalty: 3
cross_team_change_score_penalty: 1
repo_fragility_score_penalty: 2
service_fragility_score_penalty: 3
low_test_coverage_score_penalty: 2
weak_rollback_readiness_score_penalty: 3
dependency_reputation_risk_score_penalty: 2
low_team_deploy_safety_score_penalty: 2
shared_platform_surface_score_penalty: 4
database_migration_surface_score_penalty: 5
payments_surface_score_penalty: 5
auth_surface_score_penalty: 4
data_surface_score_penalty: 4
""",
}

WORKFLOW_TEMPLATE = """name: veridion-rdi

on:
  pull_request:

jobs:
  release-decision-intelligence:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Generate diff artifact
        shell: bash
        run: |
          git diff --no-ext-diff --unified=0 \
            "${{{{ github.event.pull_request.base.sha }}}}...${{{{ github.event.pull_request.head.sha }}}}" > pr.diff

      - name: Prepare baseline worktree
        shell: bash
        run: |
          mkdir -p artifacts
          git worktree add --detach ../veridion-base "${{{{ github.event.pull_request.base.sha }}}}"

      - name: Install Semgrep CLI
        shell: bash
        run: python3 -m pip install semgrep

      - name: Run Semgrep on current workspace
        shell: bash
        run: semgrep scan --config auto --json --output artifacts/semgrep.json .

      - name: Run Semgrep on baseline workspace
        shell: bash
        run: semgrep scan --config auto --json --output artifacts/baseline-semgrep.json ../veridion-base

      - name: Run Trivy on current workspace
        uses: aquasecurity/trivy-action@0.35.0
        with:
          scan-type: fs
          scan-ref: .
          format: json
          output: artifacts/trivy.json
          exit-code: "0"
          scanners: vuln
          hide-progress: true

      - name: Run Trivy on baseline workspace
        uses: aquasecurity/trivy-action@0.35.0
        with:
          scan-type: fs
          scan-ref: ../veridion-base
          format: json
          output: artifacts/baseline-trivy.json
          exit-code: "0"
          scanners: vuln
          hide-progress: true
          skip-setup-trivy: true

      - name: Run Grype on current workspace
        uses: anchore/scan-action@v7
        with:
          path: .
          output-format: json
          output-file: artifacts/grype.json
          fail-build: false

      - name: Run Grype on baseline workspace
        uses: anchore/scan-action@v7
        with:
          path: ../veridion-base
          output-format: json
          output-file: artifacts/baseline-grype.json
          fail-build: false

      - name: Install Syft CLI
        uses: anchore/sbom-action/download-syft@v0
        id: syft

      - name: Run Syft on current workspace
        shell: bash
        run: ${{{{ steps.syft.outputs.cmd }}}} . -o syft-json=artifacts/syft.json

      - name: Run Syft on baseline workspace
        shell: bash
        run: ${{{{ steps.syft.outputs.cmd }}}} ../veridion-base -o syft-json=artifacts/baseline-syft.json

      - name: Run Veridion RDI
        id: run-rdi
        uses: {action_ref}
        with:
          diff-path: pr.diff
          reports: |
            trivy=artifacts/trivy.json
            semgrep=artifacts/semgrep.json
            grype=artifacts/grype.json
            syft=artifacts/syft.json
          baseline-reports: |
            trivy=artifacts/baseline-trivy.json
            semgrep=artifacts/baseline-semgrep.json
            grype=artifacts/baseline-grype.json
            syft=artifacts/baseline-syft.json
          policy-path: .veridion/policy.yaml
          trust-profile-source-path: .veridion/trust-profile.source.json
          trust-catalog-source-path: .veridion/trust-catalog.source.json
          suppression-path: .veridion/suppressions.json
          approval-map-path: .veridion/approval-map.json
          request-approvals: "true"
          verify-approvals: "true"
          comment-path: veridion-pr-comment.md
          json-output-path: veridion-result.json
          decision-contract-path: veridion-decision.json
          post-comment: "true"
          github-token: ${{{{ secrets.GITHUB_TOKEN }}}}
          repository: ${{{{ github.repository }}}}
          pull-request-number: ${{{{ github.event.pull_request.number }}}}

      - name: Upload RDI artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: veridion-rdi-artifacts
          path: |
            veridion-pr-comment.md
            veridion-result.json
            veridion-decision.json
"""


def build_bootstrap_files(
    *,
    preset: str,
    action_ref: str = "veridionhq/veridion@main",
    repo_id: str = "",
    service_id: str = "",
    team_id: str = "",
) -> dict[str, str]:
    """Build the file set for a first-install scaffold."""

    if preset not in POLICY_PACKS:
        raise ValueError(f"unsupported preset: {preset}")

    trust_profile = {
        "scope": {
            "repo_id": repo_id,
            "service_id": service_id,
            "team_id": team_id,
        },
        "historical": {},
        "runtime": {},
        "ownership": {},
        "trust_baseline": {},
    }
    trust_catalog = {
        "scope": {},
        "historical": {},
        "runtime": {},
        "ownership": {},
        "trust_baseline": {},
    }
    suppressions = {
        "schema_version": 1,
        "suppressions": [],
    }
    approval_map = {
        "schema_version": 1,
        "roles": {
            "platform_owner": {"teams": ["platform-team"]},
            "security_owner": {"teams": ["security-team"]},
            "service_owner": {"users": []},
            "sre_owner": {"teams": ["sre-team"]},
        },
    }

    return {
        ".veridion/policy.yaml": POLICY_PACKS[preset],
        ".veridion/trust-profile.source.json": json.dumps(trust_profile, indent=2) + "\n",
        ".veridion/trust-catalog.source.json": json.dumps(trust_catalog, indent=2) + "\n",
        ".veridion/suppressions.json": json.dumps(suppressions, indent=2) + "\n",
        ".veridion/approval-map.json": json.dumps(approval_map, indent=2) + "\n",
        ".github/workflows/veridion-rdi.yml": WORKFLOW_TEMPLATE.format(action_ref=action_ref),
    }


def write_bootstrap_files(
    *,
    output_root: str,
    files: dict[str, str],
    force: bool = False,
) -> None:
    """Write scaffolded files to disk."""

    root = Path(output_root)
    for relative_path, content in files.items():
        target = root / relative_path
        if target.exists() and not force:
            raise RuntimeError(f"refusing to overwrite existing file: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for bootstrapping a first-install setup."""

    parser = argparse.ArgumentParser(description="Bootstrap Veridion install files from a starter preset")
    parser.add_argument("--preset", required=True, choices=sorted(POLICY_PACKS), help="Starter policy preset")
    parser.add_argument("--output-root", default=".", help="Repo root where files should be written")
    parser.add_argument("--action-ref", default="veridionhq/veridion@main", help="Action ref to use in the workflow")
    parser.add_argument("--repo-id", default="", help="Optional stable repo identifier")
    parser.add_argument("--service-id", default="", help="Optional stable service identifier")
    parser.add_argument("--team-id", default="", help="Optional stable team identifier")
    parser.add_argument("--force", action="store_true", help="Overwrite existing scaffold files")
    args = parser.parse_args(argv)

    files = build_bootstrap_files(
        preset=args.preset,
        action_ref=args.action_ref,
        repo_id=args.repo_id,
        service_id=args.service_id,
        team_id=args.team_id,
    )
    write_bootstrap_files(output_root=args.output_root, files=files, force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
