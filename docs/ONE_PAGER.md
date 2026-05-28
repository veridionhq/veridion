# Veridion One-Pager

## What It Is

Veridion is a GitHub-native release decision engine for introduced dependency risk.

It determines whether a pull request introduced unacceptable dependency risk by combining:

- SBOM and vulnerability signals
- baseline comparison
- introduced versus pre-existing attribution
- simple policy-driven release decisions
- accepted-risk governance

Security scanners produce signals. Veridion decides whether those signals should block or condition a release.

## What Problem It Solves

Most tools stop at finding issues.

Teams still need to decide:

- did this PR introduce a vulnerable dependency?
- was the risk already present in the baseline?
- what policy applies to the introduced risk?
- what needs to happen next?

Veridion turns that into a decision artifact:

- `GO`
- `CONDITIONAL GO`
- `NO GO`

Scanner and remediation systems focus on finding and fixing vulnerabilities.
Veridion answers a different question:

**Should this change safely reach production?**

## Why It Matters Now

AI is increasing:

- code velocity
- deployment frequency
- dependency update volume
- automated remediation

Faster than organizations are increasing:

- governance
- operational understanding
- release trust

That gap is the opportunity.

The bottleneck is no longer just vulnerability discovery.
It is deciding whether newly introduced dependency risk should block a release.

## What V1 Does

- runs as a GitHub Action
- normalizes Syft, Grype, and Trivy dependency signals
- isolates introduced dependency risk from legacy vulnerability backlog
- applies clear policy-driven release decisions
- renders an explainable PR decision comment
- governs accepted-risk suppressions with visible reason and expiry

The implementation also supports broader release-governance signals, but those are expansion paths. The first product wedge is introduced dependency risk.

## What Has Been Proven

The current MVP has been validated in an external canary repository with:

- a `GO` case
- a `CONDITIONAL GO` case from real introduced dependency risk
- a `NO GO` case from dependency risk
- an accepted-risk `CONDITIONAL GO` case where suppressions remain visible

## Best Initial Buyer

Early platform, security, DevOps, or engineering productivity teams that:

- already review risky PRs manually
- already run dependency or container vulnerability scanners
- want clearer release decisions
- care about release governance

## Category

Veridion is not:

- a scanner wrapper
- an AI AppSec product
- a vulnerability remediation tool
- an AI code review tool
- a generic DevOps dashboard

Veridion is:

**the release decision layer for introduced dependency risk**
