# Veridion One-Pager

## What It Is

Veridion is the release decision operating layer.

It starts with a narrow, painful wedge: deciding whether a GitHub pull request
introduced unacceptable dependency risk. It expands through the Evidence Gateway:
a semantic integration layer where tests, scanners, runtime signals, approvals,
and custom platform checks can be declared, validated, normalized, and routed
into one governed release decision.

## The Problem

Every engineering organization has release gates:

- security scans
- unit, integration, e2e, smoke, load, and migration tests
- runtime health and canary checks
- incident and alert state
- approval and exception workflows
- internal platform validation

No two organizations compose those gates the same way.

Most tools produce signals. Teams still need to decide:

```text
Should this change ship?
If yes, under what conditions?
If no, exactly why not?
Who can approve or override it?
What evidence supported the decision?
```

## The Wedge

Veridion v1 answers one narrow question better than scanner output alone:

```text
Did this PR introduce unacceptable dependency risk?
```

It does that by:

- consuming Syft, Grype, and Trivy reports
- comparing current reports against baseline reports
- separating introduced risk from existing backlog
- applying explicit release policy
- preserving accepted-risk visibility
- producing `GO`, `CONDITIONAL GO`, or `NO GO`
- emitting `veridion-decision.json` for automation

## The Expansion

The wedge creates natural pull for the broader product:

```text
Can we feed in e2e tests?
Can we feed load test results?
Can we feed PagerDuty incidents?
Can we feed GitHub checks?
Can our internal platform emit release evidence?
```

The Evidence Gateway makes that possible without a custom feature for every
company.

Core primitives:

- `veridion-evidence catalog`: canonical signal meaning
- `veridion-evidence validate`: evidence contract validation
- `veridion-evidence validate-producer`: adapter declaration validation
- `veridion-evidence ingest`: translate, validate, conform, and write evidence
- policy `require_evidence`: organization-defined release requirements

## The Moat

The hard-to-copy layer is not the `GO` or `NO GO` label.

The moat is the semantic integration fabric:

```text
producer manifest + raw output
  -> translate
  -> validate native evidence
  -> check producer conformance
  -> veridion-evidence.json
  -> governed release decision
```

Once an organization’s release evidence flows through Veridion, the product
becomes the system of record for release decision semantics.

## What Has Been Proven

Current proof points:

- introduced dependency-risk `GO`
- introduced dependency-risk `CONDITIONAL GO`
- introduced dependency-risk `NO GO`
- accepted-risk `CONDITIONAL GO`
- native evidence contract
- JUnit and GitHub check translators
- producer manifests and conformance checks
- policy-required evidence
- evidence surfaced in PR comments and action outputs
- evidence canary workflow for failed and missing required evidence

## Best Initial Buyer

Early platform, security, infrastructure, DevOps, or engineering productivity
teams that:

- already have release gates across multiple systems
- already review risky PRs manually
- already run scanners or CI validation
- want fewer bespoke release workflows
- want decisions, approvals, and audit tied to evidence

## Category

Veridion is not:

- a scanner wrapper
- a test runner
- an observability tool
- a deployment platform
- an AI code review tool
- a generic DevOps dashboard

Veridion is:

**the release decision operating layer for fragmented software delivery signals**
