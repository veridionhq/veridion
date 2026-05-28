# V1 Release Readiness

This checklist defines what must stay true for Veridion v1.

## Scope Freeze

V1 evaluates introduced dependency risk in GitHub pull requests.

In scope:

- Syft SBOM input
- Grype vulnerability input
- Trivy vulnerability input
- current versus baseline report comparison
- introduced versus existing dependency-risk attribution
- simple release decisions: `GO`, `CONDITIONAL GO`, `NO GO`
- accepted-risk, false-positive, no-exposure, and risk-reduction exceptions
- explainable PR comments
- `veridion-decision.json` as the machine-facing contract

Out of scope for default v1:

- Semgrep as a required signal
- runtime trust gates
- hosted history or hosted control-plane setup
- AI summarization or AI-origin scoring
- broad operational-governance policy packs
- opaque weighted scoring as the public decision model

Those capabilities can exist as expansion paths, but the default install must remain dependency-risk governance.

## Default Rules

```text
Introduced CRITICAL dependency risk -> NO GO
Introduced HIGH dependency risk -> CONDITIONAL GO
No introduced severe dependency risk -> GO
Accepted-risk suppressions present -> CONDITIONAL GO
Baseline unavailable with findings -> CONDITIONAL GO with degraded confidence
```

## Release Checklist

- package version matches `pyproject.toml` and `src/veridion/__init__.py`
- `pytest` passes
- release workflow succeeds for the tag
- canary `smoke/go` produces `GO`
- canary `smoke/conditional` produces `CONDITIONAL GO`
- canary `smoke/no-go` produces `NO GO`
- canary `smoke/accepted-risk` produces `CONDITIONAL GO`
- PR comments do not show `RDI Score`
- comments do not lead with runtime, hosted, or AI framing
- decision contract includes report evidence and scan provenance
- accepted-risk records include reason taxonomy

## Design-Partner Entry Criteria

A design-partner repo is ready when it can provide:

- pull requests with dependency changes
- current and baseline Syft, Grype, and Trivy reports
- one owner who can judge whether the decision is operationally correct
- a way to track accepted-risk exceptions

Do not require hosted services, cloud sinks, or LLM credentials for the first trial.

## Next Hardening After V1

Prioritize:

- clearer artifact/debug output when scanner reports are missing or malformed
- stricter report-health explanations
- smoother accepted-risk review workflow
- optional SARIF or compact JSON summaries for external systems

Avoid expanding the default product story until the v1 dependency-risk loop is trusted.
