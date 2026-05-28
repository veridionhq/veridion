# V1 Release Governance Wedge

This document is the strategic reset for the next execution phase.

Veridion is not another scanner, observability tool, or AI copilot. The long-term category is a decision and governance layer for modern software delivery and autonomous infrastructure systems.

The v1 wedge is intentionally narrower:

**GitHub-native release decision governance for introduced dependency risk.**

## Core Question

Veridion v1 answers:

**Did this pull request introduce unacceptable dependency risk?**

That question is deliberately smaller than:

- Is the whole application secure?
- Is the service operationally healthy?
- Should every automated infrastructure action proceed?
- Can Veridion govern every AI agent action?

Those broader questions remain part of the long-term category, but they are not the v1 surface.

## What V1 Is

V1 is a GitHub-native release decision engine that:

- generates or consumes SBOM and vulnerability signals
- compares current dependency state against a baseline
- identifies introduced versus pre-existing dependency risk
- evaluates the introduced risk against simple policy
- outputs an explainable release decision
- posts a clear PR comment
- emits a stable machine-readable decision contract

Decision outputs:

- `GO`
- `CONDITIONAL GO`
- `NO GO`

## What V1 Is Not

V1 is not:

- a vulnerability scanner
- an observability dashboard
- a DevOps AI assistant
- a SIEM
- a compliance platform
- a generic AI governance tool
- a full hosted control plane

Syft, Grype, Trivy, Semgrep, Snyk, Wiz, Datadog, and related systems produce signals.

Veridion decides whether those signals should block or condition a release action.

## Strict V1 Inputs

The default v1 path should optimize around:

- SBOM generation
- dependency diffing
- vulnerability analysis
- introduced versus pre-existing risk

Primary tools:

- Syft
- Grype
- Trivy

Semgrep and broader change-surface analysis can remain supported, but they should not be required to understand the v1 product.

## Strict V1 Workflow

```text
PR opened
  -> generate current and baseline SBOM/vulnerability reports
  -> compare dependency risk against baseline
  -> identify introduced vulnerabilities
  -> evaluate severity and policy
  -> output GO, CONDITIONAL GO, or NO GO
  -> post explainable PR comment
  -> emit veridion-decision.json
```

## V1 Decision Principle

Avoid magic scoring systems in the public v1 story.

The implementation can keep a score internally, but the product should feel rule-driven and inspectable:

```text
Introduced CRITICAL vulnerability -> NO GO
Introduced HIGH vulnerability -> CONDITIONAL GO
No introduced severe dependency risk -> GO
```

The user should understand the decision without trusting an opaque model.

## Explainability Requirements

Every v1 decision must make these clear:

- what dependency changed
- what vulnerability was introduced
- whether it was introduced or pre-existing
- why the decision triggered
- whether the baseline and scanner signals were trustworthy enough
- what must happen next

Confidence should describe signal quality, not AI certainty.

Examples:

- high confidence: current and baseline reports are present and attribution is clean
- medium confidence: findings are change-relevant but baseline attribution is incomplete
- low confidence: key reports are missing or attribution is degraded

## Architecture Direction

The repo should continue to use the control-plane architecture:

```text
signal ingestion
  -> normalization
  -> contextual evaluation
  -> decision engine
  -> explanation layer
  -> action layer
```

That architecture supports the future category without forcing the future category into the v1 user experience.

## Public Messaging

Preferred v1 language:

- release decision engine
- release governance
- introduced dependency risk
- operational trust
- deployment confidence
- explainable release decisions

Avoid leading public messaging with:

- autonomous governance platform
- AI infrastructure brain
- self-governing systems
- universal operational intelligence
- generic AI governance

The broader vision can appear as an expansion path, not the headline promise.

## Strategic Expansion Path

Internally, the long-term path remains:

```text
Release Governance
  -> Operational Governance
  -> AI Agent Governance
  -> Autonomous Infrastructure Governance
```

The core insight remains:

**Tools detect problems. Veridion decides whether those problems matter operationally.**

## Immediate Execution Rules

Until the v1 wedge is design-partner ready:

- do not add new adapter surfaces unless they unblock the v1 pilot
- do not make hosted control-plane features the default install path
- do not require AI wording or AI-origin signals
- do not add score penalties unless the behavior is easy to explain in one sentence
- prefer dependency-risk demos over broad infrastructure-risk demos
- keep default policy conservative, transparent, and low-noise

## V1 Exit Criteria

The v1 wedge is ready when a design partner can:

- install it in one GitHub repo without custom engineering support
- run it on real PRs with current and baseline Syft, Grype, and Trivy signals
- see introduced dependency risk separated from legacy backlog
- understand why each decision was `GO`, `CONDITIONAL GO`, or `NO GO`
- use `veridion-decision.json` in downstream automation without scraping prose
- manage accepted-risk exceptions without making risk disappear silently
- say whether the decision matched human reviewer judgment
