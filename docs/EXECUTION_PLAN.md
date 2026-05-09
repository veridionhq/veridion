# Execution Plan

## Mission

Build the operational trust control plane for autonomous software delivery, starting with Release Decision Intelligence (RDI).

The near-term goal is not to sell a broad platform. The goal is to produce a product that engineers install voluntarily because it improves release confidence immediately.

## Product Thesis

Autonomous engineering increases delivery speed and also increases uncertainty:

- Who or what produced the change?
- What new risk did it introduce?
- How risky is the deployment context?
- Should the change ship now?

Existing tools answer fragments of this problem. Veridion should answer the decision itself.

## What We Are Building First

An AI-aware release decision engine that runs in GitHub Actions and comments on pull requests with:

- A normalized risk summary
- An introduced-only view of change risk
- An RDI score from 0 to 100
- A release decision (`GO`, `CONDITIONAL GO`, `NO GO`)
- Confidence level
- Recommended actions

## Phase Plan

### Phase 0: Category Definition

Objective:
Define the category and operating thesis before overbuilding.

Deliverables:

- Clear positioning language
- Core use case definition
- Product principles
- Open source versus proprietary boundary
- Initial docs and roadmap

Exit criteria:

- A concise explanation of the category survives technical scrutiny
- The wedge is narrow enough to ship in 60 to 90 days
- The decisioning model is explainable to engineers and buyers

### Phase 1: MVP

Objective:
Ship a GitHub Action that provides immediate value with minimal setup.

Core capabilities:

- Scanner orchestration
- Finding normalization
- Introduced-only intelligence
- Lightweight policy evaluation
- RDI scoring and decisioning
- PR comment rendering
- Lightweight AI-attribution from PR metadata
- Lightweight historical trust signals from optional metadata
- Lightweight trust-baseline posture from optional metadata

Inputs:

- Static security findings
- PR diffs
- Dependency and lockfile changes
- IaC changes
- Ownership metadata
- Deployment target and service criticality

Lightweight signals:

- Prior failures
- Prior rollback frequency
- Sensitive repository tags
- Flaky service markers
- Low-coverage or weak-rollback service baselines

Exit criteria:

- Installable in a single repository with low friction
- Produces stable output on representative PRs
- Avoids flooding users with pre-existing debt
- Has a measurable false-positive review loop

### Phase 2: Product-Market Fit

Objective:
Prove that teams trust the release decisions enough to use them repeatedly.

Expansion areas:

- Historical deployment intelligence
- Runtime feedback loops
- Incident and rollback correlation
- Team and service trust profiles
- AI-change attribution signals

Exit criteria:

- Repeat usage by the same teams
- Decision acceptance metrics
- Visible incident-avoidance examples
- Improving precision with real deployment history

### Phase 3: Platform Expansion

Objective:
Move from PR intelligence into runtime governance and operational enforcement.

Expansion areas:

- Dynamic approval requirements
- Risk-based deploy blocking
- Progressive delivery intelligence
- Kubernetes enforcement points
- Rollback automation hooks

Exit criteria:

- Veridion participates in real deployment control paths
- Policy decisions can be enforced, not only suggested

### Phase 4: Autonomous Engineering Governance

Objective:
Become the trust, policy, and runtime governance layer for AI-driven software delivery.

Expansion areas:

- Autonomous system permissions and trust boundaries
- Runtime governance across delivery pipelines
- Operational auditability
- Long-term deployment intelligence graph

## MVP Technical Shape

### Core Components

1. Scanner orchestration
2. Unified finding schema
3. Change attribution and introduced-only diffing
4. Risk feature extraction
5. RDI scoring and policy engine
6. PR comment formatter

### Suggested Initial Implementation

- Language: Python
- Packaging: container-based GitHub Action
- Storage: local artifacts first, lightweight persistent store later
- Hosting for future services: Lambda, ECS, or other low-ops runtime

## Open Source Boundary

Open source candidates:

- Scanner orchestration
- Finding normalization
- Basic reporting surfaces
- Example policy configuration

Proprietary core:

- Decisioning logic
- Historical intelligence
- Trust scoring models
- Policy learning
- Runtime governance

## Engineering Rules

- Build the narrowest slice that proves the decisioning value
- Keep every scoring decision explainable
- Default to introduced-only context when possible
- Add new signals visibly before they affect score
- Treat false positives as a top-level product risk
- Require tests for every meaningful code change
- Keep docs aligned with implementation, not separate from it

Current implementation note:

- AI-attribution and historical trust signals are non-scoring today. They influence reporting, recommendations, and approval requirements, not the numeric RDI score.
- AI-attribution, historical trust signals, and learned trust-baseline posture are non-scoring by default today. They influence reporting, recommendations, and approval requirements before they affect the numeric RDI score.
- Metadata-driven approval rules are now policy-configurable, so operational governance can evolve through policy before it is baked into score semantics.
- The first contextual scoring hooks are policy-controlled and opt-in. Default policy leaves the base RDI model unchanged, including AI-origin, runtime, deployment-window, and ownership penalties unless explicitly configured.
