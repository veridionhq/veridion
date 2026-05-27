# Design Partner Guide

This document is for teams evaluating Veridion in a real repository.

## Best First Fit

Veridion is a strong fit for teams that:

- already use GitHub pull request workflows
- already run dependency or container vulnerability scanners
- care about release safety, not just scanner output
- have meaningful dependency risk in PRs
- want introduced risk separated from pre-existing backlog
- want release decisions to be more explainable

## Recommended Pilot Shape

Start narrow.

Use Veridion in one repository where:

- pull requests are frequent
- dependency changes happen regularly
- security review already exists in some form
- the team will actually compare Veridion’s output with human judgment

Do not start with a broad multi-repo rollout.

## Minimum Pilot Loop

For a first pilot:

1. Install Veridion in one repository.
2. Run it on several low-risk and high-risk PRs.
3. Compare the output with real reviewer expectations.
4. Tune only:

- policy thresholds for introduced dependency risk
- accepted-risk suppressions

Avoid changing the core model immediately.

## What Success Looks Like

A successful early pilot should show at least one of these:

- clearer review decisions than scanner output alone
- reduced noise from pre-existing issues
- better explanation of why a change was blocked or conditioned
- faster alignment between application and security reviewers

## What To Avoid

Do not judge Veridion only by:

- whether it finds every issue
- whether every score number feels perfect
- whether it replaces human judgment entirely

The product is a trust and decision layer.
Its value is in prioritization, explanation, and governance.

## Current Capability Summary

Today Veridion can:

- normalize Syft, Grype, and Trivy dependency signals
- isolate introduced dependency risk from existing debt
- apply policy-driven release decisions
- render clear PR comments with next actions
- govern accepted-risk suppressions with visible exceptions and expiry

The repo also contains broader release-governance capabilities such as Semgrep normalization, operational context, approval satisfaction, decision history, runtime gates, and hosted-control-plane foundations. Do not make those the first design-partner evaluation unless the dependency-risk wedge is already trusted.

## Current Limits

Today Veridion does not yet provide:

- full runtime enforcement
- service-graph-grade dependency mapping
- learned organizational trust from long operational history
- polished self-serve enterprise onboarding at scale

It is best evaluated as a release decision wedge, not a finished platform.
