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
