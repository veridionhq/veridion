# MVP Readiness

This document defines the product bar for an MVP that can support serious
customer discovery and fundraising conversations.

The goal is not to prove Veridion is a complete platform. The goal is to prove
that Veridion can become a large, differentiated release decision company.

## Thesis

Organizations already have many release gates:

- security scans
- unit, integration, e2e, smoke, load, and migration tests
- runtime health and canary checks
- incident and alert state
- approval and exception workflows
- custom internal platform validation

No two organizations compose those gates the same way. Veridion should not add a
bespoke feature for every customer. Veridion should give every organization a
way to describe its release evidence, validate it, and route it through one
governed decision contract.

The MVP must prove this:

```text
Veridion can start with a painful wedge and expand into the semantic integration
layer for release decisions.
```

## Fundraising-Grade MVP Bar

The MVP is strong enough when it demonstrates all of the following.

### 1. Urgent Wedge

Veridion can answer one narrow question better than scanner output alone:

```text
Did this PR introduce unacceptable dependency risk?
```

Minimum proof:

- installs into a GitHub repository without platform-heavy onboarding
- consumes Syft, Grype, and Trivy evidence
- compares current reports against baseline reports
- separates introduced dependency risk from existing backlog
- produces `GO`, `CONDITIONAL GO`, or `NO GO`
- explains the decision in a PR comment
- emits `veridion-decision.json` for automation

### 2. Expansion Pull

The wedge should naturally make teams ask to connect more release signals:

- JUnit or e2e test results
- GitHub check runs
- load and performance tests
- runtime health and incident state
- approval state
- custom internal validation systems

Minimum proof:

- native `veridion-evidence.json` contract exists
- first-party translators exist for common formats
- required failed evidence can block release
- required missing or uncertain evidence can condition release
- policy can require evidence by type or by specific evidence name
- evidence appears in the decision contract

### 3. Integration Moat

The hard-to-copy product surface is the release evidence integration layer.

Minimum proof:

- canonical evidence catalog defines shared status and type meanings
- producer manifests declare what each integration can emit
- emitted evidence can be validated independently
- emitted evidence can be checked against producer conformance
- `veridion-evidence ingest` supports the local adapter lifecycle:

```text
producer manifest + raw output
  -> translate
  -> validate native evidence
  -> check producer conformance
  -> veridion-evidence.json
  -> release decision
```

### 4. Credible Decision Layer

Decisions do not need to cover every enterprise workflow yet, but they must feel
trustworthy.

Minimum proof:

- policy is explicit, deterministic, and explainable
- accepted-risk exceptions stay visible
- required approvals and next steps are machine-readable
- downstream systems can consume the decision contract without scraping comments
- test coverage protects core contracts

## What Not To Build Yet

Avoid turning the MVP into a bespoke enterprise platform too early.

Do not prioritize:

- custom UI for every buyer
- deep hosted control plane before the local contract is trusted
- one-off integrations that cannot generalize through producer manifests
- opaque AI scoring
- broad runtime enforcement before evidence semantics are stable

## MVP Proof Checklist

- [ ] First install completes in under 30 minutes
- [ ] Dependency-risk `GO`, `CONDITIONAL GO`, `NO GO`, and accepted-risk scenarios work
- [ ] `veridion-decision.json` is stable enough for workflow gates
- [ ] `veridion-evidence catalog` exposes canonical signal meaning
- [ ] `veridion-evidence validate` validates emitted evidence
- [ ] `veridion-evidence validate-producer` validates adapter declarations
- [ ] `veridion-evidence ingest` runs the full local ingestion lifecycle
- [ ] At least one non-security signal, such as JUnit or GitHub checks, can affect the release decision
- [ ] Evidence canary workflow proves failed required evidence -> `NO GO`
- [ ] Evidence canary workflow proves missing required evidence -> `CONDITIONAL GO`
- [ ] A platform engineer can write a custom producer without changing Veridion core code
- [ ] Design partners understand both the narrow wedge and the larger release-decision OS thesis

## The Standard

The MVP should make a serious platform, security, or infrastructure leader say:

```text
This starts with a real release pain we have today, and I can see how it becomes
the operating layer for all of our release evidence.
```
