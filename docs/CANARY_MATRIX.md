# V1 Canary Matrix

This matrix is the acceptance check for the v1 dependency-risk wedge.

The canary repository is wired to `veridion@develop` and uses the `dependency-risk-v1` policy. The goal is to keep the product behavior narrow, explainable, and aligned with the v1 rules.

## Expected Outcomes

| Scenario | Branch | Expected decision | Why |
| --- | --- | --- | --- |
| Clean change | `smoke/go` | `GO` | No introduced dependency findings |
| High dependency risk | `smoke/conditional` | `CONDITIONAL GO` | Introduces high-severity dependency risk, but no critical dependency risk |
| Critical dependency risk | `smoke/no-go` | `NO GO` | Introduces critical dependency risk |
| Accepted risk | `smoke/accepted-risk` | `CONDITIONAL GO` | Findings are suppressed by accepted-risk policy, but remain visible |

## Comment Contract

V1 PR comments should show:

- final decision
- confidence
- introduced, existing, unattributed, and suppressed finding counts
- what must happen next when review or blocking is required
- why the decision was allowed, needs review, or is blocked
- key dependency threats when findings are present

V1 PR comments should not lead with:

- RDI score
- runtime blast radius
- staging rollout instructions
- hosted control-plane language
- AI-origin or operational intelligence framing

## Current Decision Rules

```text
No introduced severe dependency risk -> GO
Introduced HIGH dependency risk -> CONDITIONAL GO
Introduced CRITICAL dependency risk -> NO GO
Accepted-risk suppressions present -> CONDITIONAL GO
Baseline unavailable with findings -> CONDITIONAL GO with degraded confidence
```

## Regression Signals

Treat these as product regressions:

- clean dependency changes produce release-control instructions
- high-only dependency risk becomes `NO GO`
- critical introduced dependency risk becomes `CONDITIONAL GO`
- accepted risk reads like a pristine `GO`
- all-zero provided baseline reports are treated as missing baseline
- v1 comments reintroduce score-first or runtime-first explanations
- `veridion-decision.json` omits report evidence, scan provenance, or accepted-risk reason types
