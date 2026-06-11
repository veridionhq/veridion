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
4. Tune only policy thresholds for introduced dependency risk and accepted-risk suppressions.

Avoid changing the core model immediately.

## Expansion Pilot Loop

After the dependency-risk decision is trusted, add one release signal through the
Evidence Gateway.

Good candidates:

- JUnit or e2e test output
- GitHub check runs
- load test summary
- incident or alert state
- an internal platform validation result

The design partner should be able to provide:

- a producer manifest that declares the signal surface
- one raw output file or API response sample
- the expected release behavior when the evidence passes, fails, or is missing

Success means the design partner can connect the signal without Veridion core
code changing for that company.

## Trial Package

Use these docs as the design-partner package:

- [One-Pager](ONE_PAGER.md)
- [Quickstart](QUICKSTART.md)
- [Design-Partner Trial Kit](TRIAL_KIT.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Evaluation Checklist](EVALUATION_CHECKLIST.md)
- [Evidence Gateway](EVIDENCE_GATEWAY.md)
- [MVP Readiness](MVP_READINESS.md)
- [V1 Canary Matrix](CANARY_MATRIX.md)
- [V1 Release Readiness](V1_READINESS.md)

The first trial should produce at least three real PR examples:

- a clean dependency or docs-only change that should `GO`
- a high-severity introduced dependency risk that should be `CONDITIONAL GO`
- a critical introduced dependency risk or accepted-risk case that forces a clear governance decision

## What Success Looks Like

A successful early pilot should show at least one of these:

- clearer review decisions than scanner output alone
- reduced noise from pre-existing issues
- better explanation of why a change was blocked or conditioned
- faster alignment between application and security reviewers
- proof that one non-security release signal can be integrated through evidence rather than custom product work

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
- ingest native release evidence from external producers
- validate producer manifests and evidence conformance

The repo also contains broader release-governance capabilities such as Semgrep normalization, operational context, approval satisfaction, decision history, runtime gates, and hosted-control-plane foundations. Do not make those the first design-partner evaluation unless the dependency-risk wedge is already trusted.

## Current Limits

Today Veridion does not yet provide:

- full runtime enforcement
- service-graph-grade dependency mapping
- learned organizational trust from long operational history
- polished self-serve enterprise onboarding at scale

It is best evaluated as a release decision wedge, not a finished platform.
