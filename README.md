# Veridion

Veridion is operational trust infrastructure for autonomous engineering systems.

The product is not "AI for DevOps" and it is not another scanner wrapper. The wedge is Release Decision Intelligence (RDI): a system that determines whether a software change is safe to reach production, explains why, and recommends the next action.

## Category

Veridion sits in a distinct category:

- Not vulnerability scanning
- Not generic CI tooling
- Not observability
- Not DevSecOps automation
- Not AI code review

Veridion is the trust and governance layer for autonomous software delivery.

As engineering organizations adopt AI coding agents, AI-generated infrastructure, autonomous remediation, and increasingly automated deployment systems, they need a control plane that answers one question reliably:

Should this change ship?

## Product Wedge

The initial product is an AI-aware release decision engine delivered as a GitHub Action.

Core responsibilities:

- Collect findings from security and code analysis tools
- Understand what the current change introduced
- Incorporate operational and deployment context
- Surface lightweight AI-origin signals from PR metadata
- Produce an RDI score and release decision
- Explain the decision in a PR comment with recommended actions

Example output:

```text
RDI SCORE: 81
DECISION: CONDITIONAL GO

WHY:
- New critical dependency introduced
- IaC modified for production ingress
- Historical rollback rate elevated for this service

CONFIDENCE: MEDIUM

RECOMMENDATIONS:
- Require approval from platform owner
- Run staging smoke tests
- Delay Friday deployment
```

## Principles

- Introduced risk over legacy noise
- Operational context over scanner spam
- Explainable decisions over opaque scoring
- Fast installation over platform-heavy onboarding
- Trustworthy output over shallow breadth

## Initial Architecture

```text
GitHub PR
  -> GitHub Action
  -> Scanner Orchestration
  -> Normalization Layer
  -> Risk Engine
  -> RDI Decision Engine
  -> PR Comment
```

## Repo Docs

- [Execution Plan](docs/EXECUTION_PLAN.md)
- [Milestones](docs/roadmap/MILESTONES.md)
- [Testing Strategy](docs/TESTING_STRATEGY.md)

## Current Focus

Phase 0 and Phase 1:

- Define the category precisely
- Build the GitHub Action wedge
- Establish the normalization and decisioning primitives
- Test every increment as code is written
- Reach a usable MVP in 60 to 90 days

## Current State

The current `main` branch already includes:

- A working composite GitHub Action with deterministic outputs
- Multi-scanner normalization for Trivy, Grype, Semgrep, and Syft
- Introduced-only comparison with baseline suppression
- Cross-scanner dependency deduplication
- Policy-aware RDI scoring and PR comment rendering
- GitHub PR comment create/update support
- Smoke and PR-commenting workflow examples
- Initial AI-attribution signals from PR title, body, labels, and commit metadata
- Initial historical trust signals for criticality, rollback rate, incidents, and flaky services

These metadata-driven AI and historical signals are currently non-scoring. They affect explanation, recommendations, and approval requirements before they affect score.

The current policy surface can also drive metadata-based approvals, for example:

```yaml
require_service_owner_for:
  - repo_criticality_high
  - service_criticality_high
  - low_team_trust
require_sre_owner_for:
  - historical_instability
  - flaky_service
require_security_owner_for:
  - sensitive_repo
require_platform_owner_for:
  - production_deployment
  - large_blast_radius
```

The same policy can opt into contextual score penalties without changing the default model:

```yaml
historical_instability_score_penalty: 7
service_criticality_score_penalty: 5
sensitive_repo_score_penalty: 3
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
```
