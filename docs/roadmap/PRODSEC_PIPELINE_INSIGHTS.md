# Product Security Pipeline Insights

This note captures reusable product lessons from an internal product-security scanning pipeline review. It is intentionally generalized: Veridion should borrow the operating model, not company-specific code, names, infrastructure, or tickets.

## Useful Patterns For Veridion

The strongest patterns are:

- scanner outputs are durable artifacts, not just CI logs
- scan metadata matters: commit, timestamp, branch, actor, and scanner versions
- exception changes should be re-evaluatable without re-running every scanner
- vulnerability gates and threat gates are separate concerns
- accepted-risk and ticket state are enrichment layers, not scanner facts
- dashboard/export formats are downstream consumers of the decision artifact
- SBOM enrichment improves governance, but should not block the v1 dependency-risk install path

## V1 Product Takeaways

For the v1 dependency-risk wedge, the immediate Veridion implications are:

- keep current and baseline report health visible in the machine contract
- make baseline attribution explicit enough for automation to trust or question decisions
- keep accepted-risk exceptions auditable and separate from scanner findings
- preserve scanner/tool provenance for later confidence improvements
- avoid coupling the default install to Jira, Splunk, S3, Slack, LLMs, or vendor-specific scanners

## Added To The Product

The decision contract now includes an `evidence` section:

```json
{
  "evidence": {
    "attribution": {
      "trusted": true,
      "mode": "trusted",
      "likely_cause": ""
    },
    "reports": {
      "current_tools": ["grype", "syft", "trivy"],
      "baseline_tools": ["grype", "syft", "trivy"],
      "missing_baseline_tools": [],
      "zero_finding_baseline_tools": [],
      "current": {},
      "baseline": {}
    }
  }
}
```

That gives downstream systems a stable place to inspect signal quality without scraping the PR comment.

## Backlog Candidates

These are useful, but not required before the v1 wedge is trusted:

- scanner version provenance in report diagnostics
- recheck mode that re-applies suppressions/policy to existing raw reports
- optional license-risk policy pack built from enriched SBOM data
- optional threat-intelligence enrichment for KEV or exploitability context
- optional durable event sink recipes for teams that already centralize security telemetry

## Boundary

Do not move vendor-specific ticketing, dashboard, or cloud-storage assumptions into the v1 default path.

The v1 product should remain:

```text
current reports + baseline reports + dependency policy + accepted-risk file
  -> explainable release decision
  -> PR comment
  -> veridion-decision.json
```
