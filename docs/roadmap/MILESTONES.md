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

- Complete on `main` for composite action execution, explicit outputs, smoke workflow validation, PR comment posting, and artifact upload
- Follow-up remains around broader runner compatibility and live install validation outside the repo itself

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

## Execution Notes

- Finish one milestone to a defensible level before widening scope.
- Every milestone should end with working code, tests, and documentation updates.
- No milestone is complete if the behavior cannot be demonstrated with fixtures or reproducible examples.
