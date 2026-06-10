# Veridion

Veridion is a release decision engine for introduced dependency risk.

Website: `https://getveridion.com`
Docs: `https://getveridion.com/docs/`

The product is not "AI for DevOps" and it is not another scanner wrapper. The v1 wedge is release decision governance: a GitHub-native system that determines whether a pull request introduced unacceptable dependency risk, explains why, and recommends the next action.

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

Veridion is the trust and governance layer between software-delivery signals and release actions.

As engineering organizations adopt faster dependency updates, automated remediation, AI-assisted coding, and increasingly automated deployment systems, they need a control layer that answers one question reliably:

Should this change ship?

That is a broader question than "is this vulnerable?"

The broader product direction is a release decision operating layer: a semantic
integration fabric where tests, scanners, runtime signals, approvals, and custom
platform checks can be declared, validated, normalized, and routed into one
governed decision contract.

## Product Wedge

The v1 product is a GitHub-native release decision engine for introduced dependency risk.

Core responsibilities:

- Generate or consume SBOM and vulnerability signals from Syft, Grype, and Trivy
- Compare current dependency risk against a baseline
- Separate introduced dependency risk from pre-existing backlog
- Evaluate severity and policy through clear release rules
- Produce a release decision: `GO`, `CONDITIONAL GO`, or `NO GO`
- Explain the decision in a PR comment with recommended actions

Security matters inside this model, but Veridion is not a security scanner or a remediation engine.
It is the decision layer that decides whether scanner signals should block or condition a release action.

The implementation already contains broader release-governance primitives such as operational context, approval satisfaction, accepted-risk lifecycle state, decision history, policy simulation, and hosted control-plane foundations. Those are expansion paths. They are not required to understand or adopt the v1 wedge.

The comment is now only one view of the product. Veridion also emits a first-class machine contract at `veridion-decision.json` so downstream workflow steps can gate, route approvals, and audit accepted risk without scraping prose.

`veridion-result.json` and `veridion-decision.json` are intentionally different:

- `veridion-result.json` is the full execution envelope from the action runner
- `veridion-decision.json` is the stable machine-facing automation contract

Consumers should build automation against `veridion-decision.json`, not the larger runner envelope.

For v1, start without operational context. Feed current and baseline Syft, Grype, and Trivy reports into the action and let the decision focus on introduced dependency risk.

V1 example output:

```text
DECISION: NO GO

WHY:
- Introduced critical vulnerability in a runtime dependency
- Finding was not present in the baseline reports
- No active accepted-risk exception applies

CONFIDENCE: HIGH

RECOMMENDATIONS:
- Block release until the dependency is upgraded or an exception is approved
- Review the vulnerable package with the security owner
```

## Principles

- Introduced risk over legacy noise
- Clear release rules over magic scoring
- Signal quality over AI certainty
- Dependency risk as the v1 wedge
- Explainable decisions over opaque scoring
- Fast installation over platform-heavy onboarding
- Trustworthy output over shallow breadth

## Initial Architecture

```text
GitHub PR
  -> GitHub Action
  -> SBOM and Vulnerability Signals
  -> Normalization Layer
  -> Baseline Comparison
  -> Policy Decision Engine
  -> PR Comment
  -> Machine Decision Contract
```

## Repo Docs

- [Quickstart](docs/QUICKSTART.md)
- [Evaluation Guide](docs/EVALUATION_GUIDE.md)
- [Evaluation Checklist](docs/EVALUATION_CHECKLIST.md)
- [Evidence Gateway](docs/EVIDENCE_GATEWAY.md)
- [Evidence Gateway Quickstart](docs/EVIDENCE_QUICKSTART.md)
- [MVP Readiness](docs/MVP_READINESS.md)
- [Design Partner Guide](docs/DESIGN_PARTNER.md)
- [Design-Partner Trial Kit](docs/TRIAL_KIT.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [One-Pager](docs/ONE_PAGER.md)
- [V1 Release Governance Wedge](docs/roadmap/V1_RELEASE_GOVERNANCE.md)
- [Product Security Pipeline Insights](docs/roadmap/PRODSEC_PIPELINE_INSIGHTS.md)
- [V1 Canary Matrix](docs/CANARY_MATRIX.md)
- [V1 Release Readiness](docs/V1_READINESS.md)
- [Automation Guide](docs/AUTOMATION_GUIDE.md)
- [Testing Strategy](docs/TESTING_STRATEGY.md)
- [Support](SUPPORT.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [License](LICENSE)
- [Releasing](RELEASING.md)

Expansion material exists for later policy rollout, event sinks, hosted, and non-GitHub paths, but it is not the first-install route.

## Current Focus

V1 design-partner readiness:

- Keep the public product wedge narrow: introduced dependency risk governance
- Prove the expansion path through the Evidence Gateway, not bespoke customer features
- Make the GitHub Action install path boring and reproducible
- Keep default decisions clear, explainable, and conservative
- Use Syft, Grype, and Trivy as the primary v1 signal sources
- Treat hosted control-plane, runtime, and AI work as expansion paths

## Current State

The current v1 path includes:

- A working composite GitHub Action with deterministic outputs
- Syft, Grype, and Trivy normalization for dependency and vulnerability signals
- Introduced-only dependency comparison with baseline suppression
- Cross-scanner dependency deduplication
- Policy-aware release decisions and PR comment rendering
- GitHub PR comment create/update support
- A versioned `decision contract` for downstream workflow gating
- Accepted-risk lifecycle states, renewals, and expiry pressure in the decision contract
- A narrow `dependency-risk-v1` policy pack for first installs
- Smoke and PR-commenting workflow examples aligned to the v1 wedge
- A native `veridion-evidence.json` contract for release evidence
- `veridion-evidence` commands for catalog, validation, producer manifests, translation, and ingestion
- Seed producer manifests and an Evidence Gateway workflow example for non-security release evidence

The repo also contains expansion capabilities such as Semgrep normalization, operational context, approval satisfaction, decision history, policy simulation, runtime gates, hosted-service foundations, and GitLab adapters. Those are deliberately not the v1 default.

The current MVP has also been validated in an external canary repository with:

- a clean docs-only `GO`
- a dependency-risk `CONDITIONAL GO` from introduced high-severity dependency risk
- a dependency-risk `NO GO` from introduced critical dependency risk
- an accepted-risk `CONDITIONAL GO` where suppressed findings remain visible

That means the current implementation already handles more than vulnerability status alone. For v1, the default product story stays narrower: introduced dependency risk first, broader release posture second.

## Fastest Install Path

For the shortest path to a first install:

1. Install Veridion from GitHub in the repo where you want to bootstrap:

```bash
python3 -m pip install "git+https://github.com/veridionhq/veridion.git@v1.0.4"
```

2. Run:

```bash
veridion-bootstrap \
  --preset dependency-risk-v1 \
  --repo-id your-org/your-repo \
  --service-id your-service \
  --team-id your-team
```

3. Start with [docs/QUICKSTART.md](docs/QUICKSTART.md)
4. Use [examples/policy-packs/dependency-risk-v1.yaml](examples/policy-packs/dependency-risk-v1.yaml) as the default v1 policy
5. Treat `operational-context.json`, hosted history, and cloud sinks as expansion paths, not first-install requirements

Bootstrap also creates `.veridion/suppressions.json` so teams have a first-class accepted-risk feedback loop instead of ad hoc ignore behavior.

Each suppression can now carry lifecycle metadata such as exception ID, status, owner, approver, review timestamp, ticket, and expiry so accepted risk remains auditable instead of becoming silent ignore state.

For downstream automation, the action now exposes:

- `gate_status`: `pass`, `review`, or `block`
- `decision_allowed`: whether the configured gate permits the final verdict
- `required_approvals_json`
- `required_next_steps_json`
- `blocking_reasons_json`
- `blocking_categories_json`
- `accepted_risk_present`
- `decision_contract_path`
- `decision_event_path`

Optional expansion integrations on top of the decision contract include:

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

V1 practical default:

- core Veridion install
- deterministic decision engine
- no LLM configured
- local artifacts in CI
- no hosted service
- no cloud sink

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

These metadata-driven AI signals are currently non-scoring by default. For v1, keep them out of the default product story. Historical posture, trust-baseline posture, runtime gates, and trust-memory pressure can affect score, gating, approvals, and required actions only when a selected policy pack opts into that broader release-governance behavior.
