# Veridion

Veridion is operational trust infrastructure for autonomous engineering systems.

Website: `https://getveridion.com`
Docs: `https://getveridion.com/docs/`

The product is not "AI for DevOps" and it is not another scanner wrapper. The wedge is Release Decision Intelligence (RDI): a system that determines whether a software change is safe to reach production, explains why, and recommends the next action.

Security is one signal inside that decision, not the category itself.

## Category

Veridion sits in a distinct category:

- Not vulnerability scanning
- Not AI AppSec
- Not vulnerability remediation
- Not generic CI tooling
- Not observability
- Not DevSecOps automation
- Not AI code review

Veridion is the trust and governance layer for autonomous software delivery.
It sits between increasingly autonomous engineering systems and production.

As engineering organizations adopt AI coding agents, AI-generated infrastructure, autonomous remediation, and increasingly automated deployment systems, they need a control plane that answers one question reliably:

Should this change ship?

That is a broader question than "is this vulnerable?"

## Product Wedge

The initial product is an AI-aware release decision engine delivered as a GitHub Action.

Core responsibilities:

- Collect findings from security and code analysis tools
- Understand what the current change introduced
- Incorporate operational and deployment context
- Surface lightweight AI-origin signals from PR metadata
- Produce an RDI score and release decision
- Explain the decision in a PR comment with recommended actions

Security matters inside this model, but Veridion is not a security scanner or a remediation engine.
It is the operational trust layer that decides whether a change should safely move toward production.

The action can now consume a versioned operational-context artifact as its primary context contract. That artifact can be produced by GitHub workflows today, and later by other CI/CD or platform integrations without changing the decision engine.

That same contract now carries both static posture and live release-readiness gates such as active freezes, incidents, canary health, and rollback viability.

The comment is now only one view of the product. Veridion also emits a first-class machine contract at `veridion-decision.json` so downstream workflow steps can gate, route approvals, and audit accepted risk without scraping prose.

`veridion-result.json` and `veridion-decision.json` are intentionally different:

- `veridion-result.json` is the full execution envelope from the action runner
- `veridion-decision.json` is the stable machine-facing automation contract

Consumers should build automation against `veridion-decision.json`, not the larger runner envelope.

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
  "trust_memory": {},
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
- Deployment trust over security-only framing
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
- [Automation Guide](docs/AUTOMATION_GUIDE.md)
- [AWS Deployment Pattern](docs/AWS.md)
- [Decision History](docs/DECISION_HISTORY.md)
- [Non-GitHub Producers](docs/NON_GITHUB.md)
- [GitLab Adapter](docs/GITLAB.md)
- [Policy Simulation](docs/POLICY_SIMULATION.md)
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
- A versioned `decision contract` for downstream workflow automation and gating
- Live runtime release gates for freezes, incidents, alert pressure, canary health, and rollback viability
- Accepted-risk lifecycle states, renewals, and expiry pressure in the decision contract
- Policy pack metadata and side-by-side policy simulation
- Trust memory signals for repeated no-go decisions, overrides, accepted-risk backlog, and low decision quality
- GitLab merge-request metadata and note adapters
- Starter policy packs for application teams, platform teams, and regulated services

The current MVP has also been validated in an external canary repository with:

- a clean docs-only `GO`
- a deliberately risky dependency/ingress/IAM `NO GO`
- a middle-path `CONDITIONAL GO` scenario for product tuning
- an accepted-risk `CONDITIONAL GO` where suppressed findings remain visible

That means the current product already handles more than vulnerability status alone. It reasons about release posture, operational context, approvals, and accepted risk together.

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

Each suppression can now carry lifecycle metadata such as exception ID, status, owner, approver, review timestamp, ticket, and expiry so accepted risk remains auditable instead of becoming silent ignore state.

Optional AI wording can sit on top of the deterministic decision engine. If you configure a provider, Veridion still decides deterministically and only uses the model to rewrite structured threat facts into shorter operator-facing English.

For an OpenAI-backed setup in GitHub Actions, add:

- repository variable: `VERIDION_COMMENT_SUMMARY_PROVIDER=openai`
- repository variable: `VERIDION_COMMENT_SUMMARY_MODEL=gpt-5-mini`
- repository secret: `VERIDION_COMMENT_SUMMARY_API_KEY`

OpenAI's model guide says to choose a smaller variant such as `gpt-5-mini` when you are optimizing for latency and cost, which fits this wording-only layer well: [OpenAI Models](https://developers.openai.com/api/docs/models).

For downstream automation, the action now exposes:

- `gate_status`: `pass`, `review`, or `block`
- `decision_allowed`: whether the configured gate permits the final verdict
- `required_approvals_json`
- `required_next_steps_json`
- `blocking_reasons_json`
- `blocking_categories_json`
- `accepted_risk_present`
- `decision_contract_path`
- `approval_gate_status`
- `approval_gate_allowed`
- `stale_approvals_json`
- `approval_head_sha`
- `decision_event_path`
- `sink_delivery_summary_json`

Optional integrations on top of the decision contract now include:

- GitHub reviewer requests from role-based approval maps
- GitHub approval satisfaction checks for mapped approval roles
- approval enforcement for unsatisfied required approvals
- durable decision-event artifacts and append-only history logs
- local decision-history analytics by repository, policy pack, and gate outcome
- pluggable decision-event sinks for object stores, databases, buses, and webhook collectors
- outbound webhook delivery of the decision contract
- generic CI producers that build `operational-context.json` without GitHub event payloads
- policy simulation across multiple policy packs before changing live enforcement

Most users do not need all of those.

Practical default:

- core Veridion install
- deterministic decision engine
- no LLM configured
- local artifacts in CI

Recommended first production control-plane path:

- S3 as centralized event storage
- local or Athena-based history analysis
- optional AI wording only if the team wants it

For contributor/local development only, an editable install also works:

```bash
python3 -m pip install -e /path/to/veridion
```

Optional integration installs:

```bash
python3 -m pip install "veridion[aws]"
python3 -m pip install "veridion[gcp]"
python3 -m pip install "veridion[db]"
python3 -m pip install "veridion[events]"
```

These extras are only needed when you want the matching sink or provider. The core decision engine does not require them.

These metadata-driven AI signals are currently non-scoring by default. Historical posture, trust-baseline posture, runtime gates, and trust-memory pressure can now affect score, gating, approvals, and required actions depending on the selected policy pack.

The current product direction beyond the GitHub wedge is:

- approval satisfaction and enforcement
- runtime release gating from live operational state
- accepted-risk lifecycle governance
- policy simulation and rollout management
- portable adapter surfaces such as GitLab and generic CI

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
