# Veridion

Veridion is operational trust infrastructure for autonomous engineering systems.

Website: `https://getveridion.com`
Docs: `https://getveridion.com/docs/`

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

The action can now consume a versioned operational-context artifact as its primary context contract. That artifact can be produced by GitHub workflows today, and later by other CI/CD or platform integrations without changing the decision engine.

The current GitHub path still builds from two source inputs:

- PR metadata for request-scoped signals like title, body, labels, and commit history
- trust profile JSON for repo, service, and team posture that should persist across PRs

Those are merged into one versioned operational-context artifact:

```json
{
  "schema_version": 1,
  "provenance": {
    "source": "veridion-github-builder",
    "generated_at": "2026-05-10T00:00:00Z"
  },
  "metadata": {},
  "historical": {},
  "runtime": {},
  "ownership": {},
  "trust_baseline": {},
  "trust_profile_metadata": {}
}
```

The repo-local source example lives at [examples/trust/trust-profile.source.json](examples/trust/trust-profile.source.json). A shared catalog baseline can also be layered in from [examples/trust/trust-catalog.source.json](examples/trust/trust-catalog.source.json), and the workflow now builds `operational-context.json` before running Veridion. That is the integration point other products should target.

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

- [Website](https://getveridion.com)
- [Docs Home](https://getveridion.com/docs/)
- [Quickstart](docs/QUICKSTART.md)
- [Evaluation Guide](docs/EVALUATION_GUIDE.md)
- [Evaluation Checklist](docs/EVALUATION_CHECKLIST.md)
- [Design Partner Guide](docs/DESIGN_PARTNER.md)
- [One-Pager](docs/ONE_PAGER.md)
- [Operational Context Contract](docs/OPERATIONAL_CONTEXT.md)
- [Milestones](docs/roadmap/MILESTONES.md)
- [Testing Strategy](docs/TESTING_STRATEGY.md)
- [Support](SUPPORT.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [License](LICENSE)
- [Releasing](RELEASING.md)

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
- Initial trust-baseline signals for repo fragility, service stability, rollback readiness, and dependency reputation
- A versioned `operational-context` contract for non-GitHub producers
- Starter policy packs for application teams, platform teams, and regulated services

The current MVP has also been validated in an external canary repository with:

- a clean docs-only `GO`
- a deliberately risky dependency/ingress/IAM `NO GO`
- a middle-path `CONDITIONAL GO` scenario for product tuning
- an accepted-risk `CONDITIONAL GO` where suppressed findings remain visible

## Fastest Install Path

For the shortest path to a first install:

1. Install Veridion from GitHub in the repo where you want to bootstrap:

```bash
python3 -m pip install "git+https://github.com/veridionhq/veridion.git@main"
```

2. Run:

```bash
veridion-bootstrap \
  --preset application-team \
  --repo-id your-org/your-repo \
  --service-id your-service \
  --team-id your-team
```

3. Start with [docs/QUICKSTART.md](docs/QUICKSTART.md)
4. Pick a starter pack from [examples/policy-packs](examples/policy-packs) if `application-team` is not the right default
5. Treat `operational-context.json` as the integration contract for future non-GitHub environments

The GitHub Action can build `operational-context.json` internally from repo-local trust source files, so external repos do not need to import Veridion Python modules inside their workflow before the action runs.

Bootstrap also creates `.veridion/suppressions.json` so teams have a first-class accepted-risk feedback loop instead of ad hoc ignore behavior.

For contributor/local development only, an editable install also works:

```bash
python3 -m pip install -e /path/to/veridion
```

These metadata-driven AI, historical, and trust-baseline signals are currently non-scoring by default. They affect explanation, recommendations, and approval requirements before they affect score.

The current policy surface can also drive metadata-based approvals, for example:

```yaml
require_service_owner_for:
  - repo_criticality_high
  - service_criticality_high
  - low_team_trust
  - low_test_coverage
require_sre_owner_for:
  - historical_instability
  - flaky_service
  - service_fragility
require_security_owner_for:
  - sensitive_repo
  - dependency_reputation_risk
require_platform_owner_for:
  - production_deployment
  - large_blast_radius
  - weak_rollback_readiness
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
repo_fragility_score_penalty: 0
service_fragility_score_penalty: 0
low_test_coverage_score_penalty: 0
weak_rollback_readiness_score_penalty: 0
dependency_reputation_risk_score_penalty: 0
low_team_deploy_safety_score_penalty: 0
```
