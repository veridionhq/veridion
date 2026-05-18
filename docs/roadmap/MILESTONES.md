# Milestones

This roadmap converts the product thesis into shipping checkpoints with explicit exit criteria.

## M0: Foundation

Target:
Establish category framing, repository structure, and engineering operating standards.

Scope:

- Core README and docs
- Delivery plan and milestone map
- Testing strategy
- Initial package layout
- Initial CI/test harness

Exit criteria:

- Repo has a clear source of truth for product and engineering direction
- Every future implementation task can map back to a milestone
- The project has a default test workflow before feature work expands

## M1: Normalization and Inputs

Target:
Build the input pipeline that turns scanner output and change context into a stable internal model.

Scope:

- Ingestion contracts for Trivy, Grype, Syft, and Semgrep
- Unified finding schema
- PR diff parsing
- Dependency and lockfile change detection
- IaC change classification

Exit criteria:

- Different tool outputs map into one normalized schema
- Fixtures exist for representative scanner payloads
- Introduced-versus-existing findings can be distinguished

## M2: Introduced-Only Intelligence

Target:
Make the product usable by filtering noise and isolating the delta introduced by the current change.

Scope:

- Baseline comparison model
- Existing debt suppression
- Ownership-aware attribution
- Service and repo metadata inputs

Exit criteria:

- PR output emphasizes new risk rather than historical backlog
- Test fixtures prove baseline suppression behavior
- Edge cases for renamed files, lockfile churn, and partial diffs are covered

Status:

- Complete for baseline suppression, rename/delete handling, and cross-scanner dedup-aware comparison
- Partially complete for attribution: lightweight AI-origin metadata signals, historical trust signals, runtime/ownership context, and learned trust-baseline posture are now surfaced, but richer service graph data is still pending

## M3: RDI Scoring and Decision Engine

Target:
Turn normalized signals into an explainable release decision.

Scope:

- Risk feature extraction
- Weighted scoring model
- Policy YAML parsing
- Decision thresholds
- Confidence scoring
- Recommendation generation

Exit criteria:

- The same input set always yields deterministic output
- Decision reasons are traceable to concrete signals
- Policy overrides and approval requirements are test-covered

## M4: PR Comment Experience

Target:
Deliver the product through a crisp and useful PR comment.

Scope:

- Comment formatter
- Severity and confidence presentation
- Why-this-matters narrative
- Recommendation block
- Update/replace behavior for repeated runs

Exit criteria:

- The comment is easy to scan in real PRs
- Engineers can understand the decision without opening raw scanner logs
- Snapshot tests protect formatting regressions

Status:

- Complete for deterministic rendering, marker-based replacement, and GitHub upsert lifecycle
- AI-attribution, historical trust signals, runtime/ownership context, and trust-baseline posture now appear in the comment, recommendation, and approval path as non-scoring context
- Follow-up remains to convert current exact-string tests into dedicated snapshot artifacts if we want a formal snapshot harness

## M5: GitHub Action MVP

Target:
Package the engine as an installable GitHub Action with minimal setup.

Scope:

- Container action wiring
- Inputs/outputs contract
- Sample workflow
- Repo permissions model
- Basic documentation for installation

Exit criteria:

- A test repository can install and run the action successfully
- Action output is stable across repeated runs
- Failure modes are explicit and actionable

Status:

- Complete on `main` for composite action execution, explicit outputs, smoke workflow validation, PR comment posting, artifact upload, and the versioned `operational-context` integration contract
- Complete for starter policy packs and first-install quickstart docs
- Complete for first external install and canary validation across `GO`, `CONDITIONAL GO`, `NO GO`, and accepted-risk exception scenarios
- Follow-up remains around broader runner compatibility and wider live install validation outside the current canary path

## M6: Trust Loop

Target:
Close the loop on accuracy, adoption, and false positives.

Scope:

- Review feedback capture
- Suppression and tuning inputs
- Basic operational telemetry
- Decision acceptance tracking

Exit criteria:

- The team can measure false positives and decision acceptance
- Product improvements can be prioritized from usage data instead of intuition alone

Status:

- Started on `main` with repo-local accepted-risk suppressions, visible exception reporting, and expiration-aware suppression governance
- Follow-up remains for stronger policy controls over suppressions, richer review-feedback capture, and real decision acceptance telemetry

## M7: Approval Satisfaction and Enforcement

Target:
Move from approval requirements to verifiable approval state.

Scope:

- Role-to-reviewer mapping contracts
- GitHub approval satisfaction checks
- Unsatisfied approval outputs and contract enrichment
- Approval-state aware workflow examples

Exit criteria:

- Veridion can say both who must approve and whether those mapped approvals are currently satisfied
- Unsatisfied approvals are machine-readable without scraping PR comments
- Approval-state checks are demonstrated in automation examples and tests

Status:

- Started on `develop` with mapped GitHub reviewer requests and approval satisfaction checks for role-mapped pull requests
- Follow-up remains for broader change-management integrations, richer team-resolution semantics, and policy enforcement based on satisfied versus pending approvals

## M8: Runtime Release Gates

Target:
Incorporate live release-readiness signals beyond static metadata.

Scope:

- Deployment freeze windows
- Active incidents and alert state
- Canary or staged rollout health
- Rollback viability checks

Exit criteria:

- Veridion can ingest live runtime readiness state and include it in gating decisions
- Runtime blockers are reflected in the machine decision contract and recommendations

Status:

- Started on `develop` with first-class runtime gate fields in `operational-context.json` for deployment freezes, active incidents, alert state, canary health, and rollback viability
- Decisioning now escalates hard runtime blockers to `NO GO` and review-only runtime degradation to `CONDITIONAL GO`
- Follow-up remains for deeper live system integrations such as incident-management adapters, freeze-calendar ingestion, and real canary telemetry sources

## M9: Accepted-Risk Lifecycle

Target:
Turn suppressions into a governed exception workflow.

Scope:

- Exception proposal and renewal lifecycle
- Owner and approver verification
- Expiration enforcement and audit trail

Exit criteria:

- Accepted risk is managed as a first-class workflow rather than repo-local ignore state
- Exception state is queryable and auditable over time

Status:

- Started on `develop` with lifecycle-aware accepted-risk exceptions: explicit IDs, statuses, renewal tracking, expiry pressure, and audit events in `veridion-decision.json`
- Proposed and rejected exceptions now remain visible instead of silently suppressing findings, while approved and renewal-pending exceptions stay machine-auditable
- Follow-up remains for external exception systems, approver identity verification against real org systems, and long-lived audit storage beyond repo-local JSON

## M10: Multi-Surface Adapters

Target:
Make the decision engine portable beyond GitHub Actions.

Scope:

- Additional CI/CD adapters
- External deployment and release system hooks
- Shared operational-context ingestion contracts

Exit criteria:

- The same decision engine can run through multiple adapter surfaces with a stable contract

Status:

- Started on `develop` with GitLab merge-request adapters for metadata building and note upsert, alongside the existing generic CLI and webhook surfaces
- `operational-context.json` remains the shared integration contract across GitHub, GitLab, and generic CI environments
- Follow-up remains for deeper first-party adapters such as Jenkins, Buildkite, Argo, and deployment-controller-native hooks

## M11: Policy Productization and Trust Memory

Target:
Evolve from repo-local config into an organizational trust control plane.

Scope:

- Policy templates and override management
- Policy simulation and rollout history
- Longitudinal service, team, and dependency trust memory

Exit criteria:

- Teams can manage policy as product surface, not just YAML files
- Veridion can reason across historical trust state, not only per-change snapshots

Status:

- Started on `develop` with policy-pack metadata, a policy simulation CLI, and trust-memory signals carried through `operational-context.json`, analysis, decisioning, and `veridion-decision.json`
- Policy simulation can now compare named packs side by side before changing live enforcement
- Trust memory can now escalate decisions based on repeated no-go outcomes, repeated policy overrides, accepted-risk backlog, and low recent decision quality
- Follow-up remains for policy rollout history storage, org-wide pack catalogs, UI/API management of overrides, and deeper longitudinal trust sources beyond repo-local JSON

## M12: Enforcement and Decision History

Target:
Turn release intelligence into enforceable workflow control with durable decision records.

Scope:

- Approval-satisfaction enforcement
- Final-state decision event artifacts
- Append-only decision history logs
- Replay-friendly history contract for later rollout analysis

Exit criteria:

- Unsatisfied required approvals can fail automation without ad hoc shell glue
- Veridion can emit a durable decision event capturing the final enforced release state
- Decision history can be appended over time for replay, policy rollout comparison, and trust-memory backfill

Status:

- Started on `develop` with approval enforcement outputs and a post-verification decision-event artifact
- Decision events can now be appended to an NDJSON history log so later systems can replay or aggregate release outcomes
- Approval freshness now invalidates stale approvals after new commits instead of treating old approvals as current control state
- Local decision-history analytics now summarize verdict, approval-gate, blocking-category, and policy-pack trends from the NDJSON event log
- File-backed history replay now works across NDJSON logs, single decision-event files, and exported event-object trees such as S3-synced partitions
- File-backed service and export surfaces now exist for org-scope analytics snapshots and HTTP consumption without introducing a database-backed backend yet
- Multi-tenant config, bearer-token auth, and timestamped materialization runs now exist as the first hosted-history control-plane layer
- SQLite-backed multi-tenant event storage now exists as the first persistent hosted backend, and scheduled materialization can emit per-tenant warehouse query packs
- Follow-up remains for stronger service-grade databases, deeper authz, warehouse-native scheduled execution, and long-range pack rollout analytics over larger history sets

## Execution Notes

- Finish one milestone to a defensible level before widening scope.
- Every milestone should end with working code, tests, and documentation updates.
- No milestone is complete if the behavior cannot be demonstrated with fixtures or reproducible examples.
