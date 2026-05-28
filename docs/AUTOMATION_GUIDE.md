# Automation Guide

Veridion now emits a machine-facing decision contract at `veridion-decision.json` and a matching set of GitHub Action outputs. The PR comment is presentation. Automation should consume the contract and outputs directly.

`veridion-result.json` is still available, but it serves a different purpose:

- `veridion-result.json`: full runner envelope, analysis payload, comment text, and embedded decision contract
- `veridion-decision.json`: stable machine-facing contract for gates, approvals, and external integrations

If you are writing workflow logic for the v1 dependency-risk wedge, prefer `veridion-decision.json`.

Important product boundary:

- Veridion does not require an external LLM
- Veridion does not require S3, Athena, or any cloud provider by default

Those are optional integration layers on top of the deterministic core.

## Core outputs

- `gate_status`: `pass`, `review`, or `block`
- `decision_allowed`: whether the configured gate allows the verdict
- `confidence`: signal-quality confidence for the decision
- `required_next_steps_json`
- `blocking_reasons_json`
- `blocking_categories_json`
- `accepted_risk_present`
- `decision_contract_path`
- `decision_event_path`

## Decision contract

The action writes `veridion-decision.json` by default when `decision-contract-path` is set.

Key fields:

- `decision.verdict`
- `decision.gate_status`
- `decision.decision_allowed`
- `decision.blocking_categories`
- `evidence.attribution.trusted`
- `evidence.attribution.mode`
- `evidence.reports.current_tools`
- `evidence.reports.baseline_tools`
- `evidence.reports.missing_baseline_tools`
- `evidence.reports.zero_finding_baseline_tools`
- `evidence.reports.current.<tool>.sha256`
- `evidence.reports.baseline.<tool>.sha256`
- `evidence.scan.metadata`
- `evidence.scan.recheck_only`
- `actions.required_next_steps`
- `accepted_risk.governance_gaps`

## Scanner provenance

When reports are provided, Veridion records basic provenance for each current and baseline report:

- report path
- SHA-256 hash
- file size
- normalized finding count
- inventory record count

You can also provide scan-level metadata:

```yaml
scan-metadata-path: veridion-scan-metadata.json
```

Recommended metadata shape:

```json
{
  "commit_hash": "abc123...",
  "commit_short": "abc123",
  "branch": "feature/dependency-update",
  "scan_timestamp": "2026-05-27T00:00:00Z",
  "scanner_versions": {
    "syft": "1.20.0",
    "grype": "0.110.0",
    "trivy": "0.69.3"
  }
}
```

## Recheck existing reports

Use recheck mode when scanner outputs already exist and you only want to re-apply current policy and accepted-risk suppressions.

```yaml
recheck-only: "true"
scan-metadata-path: veridion-scan-metadata.json
```

Recheck mode validates that `scan-metadata-path` contains a `commit_hash` matching the current commit. In GitHub Actions this defaults to `GITHUB_SHA`. You can override it explicitly:

```yaml
expected-commit: ${{ github.sha }}
```

This is useful for exception review loops: update `.veridion/suppressions.json`, reuse the same raw scanner reports, and regenerate the decision/comment/contract without rerunning Syft, Grype, or Trivy.

## Gate a deploy

For a hard deploy gate, let the action fail the job itself:

```yaml
- name: Run Veridion RDI
  id: run-rdi
  uses: veridionhq/veridion@v1.0.1
  with:
    diff-path: pr.diff
    reports: ${{ vars.VERIDION_REPORTS }}
    baseline-reports: ${{ vars.VERIDION_BASELINE_REPORTS }}
    policy-path: .veridion/policy.yaml
    suppression-path: .veridion/suppressions.json
    decision-contract-path: veridion-decision.json
    enforce-decision: "true"
    allowed-decisions: "GO"
```

That setup blocks `CONDITIONAL GO` and `NO GO`.

If you want `CONDITIONAL GO` to pass but still be visible, use:

```yaml
allowed-decisions: "GO,CONDITIONAL GO"
```

For v1, use this to gate introduced dependency risk. Runtime release gates and broader operational context are expansion paths.

## V1 override discipline

Keep first-install override behavior explicit:

- `accepted_risk`: the risk is real and accepted for a bounded period
- `false_positive`: the scanner finding is incorrect
- `no_exposure`: the package or code is present but not reachable in this context
- `risk_reduction`: compensating controls reduce practical severity

Use `.veridion/suppressions.json` for those cases. Do not use broad ignore rules as a substitute for accepted-risk governance.

## Expansion: approval routing

The action can now optionally request GitHub reviewers when you provide an approval map.

Example approval map:

```json
{
  "schema_version": 1,
  "roles": {
    "platform_owner": { "teams": ["platform-team"] },
    "security_owner": { "teams": ["security-team"] },
    "service_owner": { "users": ["service-owner"] },
    "sre_owner": { "teams": ["sre-team"] }
  }
}
```

Action inputs:

- `request-approvals: "true"`
- `approval-map-path: .veridion/approval-map.json`

Example:

```yaml
- name: Fail if approvals are required
  if: ${{ steps.run-rdi.outputs.required_approvals_json != '[]' }}
  shell: bash
  run: |
    echo "Required approvals: ${{ steps.run-rdi.outputs.required_approvals_json }}"
    exit 1
```

This is useful when an external system maps Veridion roles to real reviewers or change-management approvals.

Outputs:

- `approval_request_status`
- `requested_reviewers_json`
- `missing_approval_mappings_json`

## Expansion: approval satisfaction

The action can also evaluate whether mapped approval roles are currently satisfied on the pull request.

Action inputs:

- `verify-approvals: "true"`
- `approval-map-path: .veridion/approval-map.json`

Outputs:

- `approval_satisfaction_status`
- `approvals_satisfied`
- `satisfied_approvals_json`
- `unsatisfied_approvals_json`
- `stale_approvals_json`
- `approval_head_sha`
- `approval_state_json`
- `approval_gate_status`
- `approval_gate_allowed`

When `decision-contract-path` is set, the same approval satisfaction state is written back into `veridion-decision.json` under `automation`.

If you want approval state to become enforceable instead of informational, set:

- `verify-approvals: "true"`
- `enforce-approval-satisfaction: "true"`

That makes unsatisfied or unmapped required approvals fail the workflow without adding a separate shell gate step.

Veridion also treats approvals as stale when the latest approval predates the current pull request head commit. Stale approvals are exposed separately from merely pending approvals so downstream systems can distinguish:

- no approval yet
- stale approval after new commits
- unmapped approval role

## Consume accepted-risk governance

Accepted risk is visible in both `veridion-result.json` and `veridion-decision.json`.

Use:

- `accepted_risk_present`
- `accepted_risk.governance_gaps`
- `accepted_risk.suppressed_findings`
- `accepted_risk.exceptions`
- `accepted_risk.lifecycle_events`
- `accepted_risk.pending_review`
- `accepted_risk.renewal_pending`
- `accepted_risk.expiring_soon`

to distinguish:

- a clean change
- a change with reviewed accepted risk
- a change with incomplete suppression governance metadata
- a change with pending exception proposals or renewals

Accepted-risk lifecycle statuses:

- `proposed`: request exists but does not suppress findings yet
- `approved`: active accepted-risk exception
- `renewal_requested`: active exception that needs renewal review
- `rejected`: closed exception request that no longer suppresses findings

Accepted-risk reason types:

- `accepted_risk`: risk is real and intentionally accepted for a bounded period
- `false_positive`: scanner finding is incorrect
- `no_exposure`: vulnerable code or package is present but not reachable in this context
- `risk_reduction`: compensating controls reduce practical severity

For `risk_reduction`, include `reduced_severity` as `critical`, `high`, `medium`, or `low`. Veridion records this taxonomy in the decision contract so exception review can distinguish real accepted risk from no-exposure and false-positive cases.

## Harden accepted-risk governance

You can make incomplete suppression metadata a policy blocker:

```yaml
require_complete_accepted_risk_metadata: true
```

You can also drive approval requirements from accepted-risk conditions:

```yaml
require_security_owner_for:
  - accepted_risk_present
  - accepted_risk_governance_gap
```

## Expansion: decision events

Veridion now emits a machine-readable decision event artifact after approval verification so history captures the final enforced state, not just the raw runner verdict.

Outputs:

- `decision_event_path`
- `decision_history_path`

Inputs:

- `decision-event-path`
- `decision-history-path`

## Expansion: canonical event sinks

The canonical transport surface is now `veridion-decision-event.json`.

Action inputs:

- `decision-sinks`
- `fail-on-sink-error`

Output fields:

- `sink_delivery_summary_json`
- `sink_delivery_failures_json`

Supported sink kinds include local files, webhooks, and optional cloud or database destinations:

- `local-file:path=/abs/path/event.json`
- `local-ndjson:path=/abs/path/history.ndjson`
- `webhook:url=https://...`
- `veridion-service:url=https://hosted.example.com,tenant=acme,token=...`
- `s3:bucket=...,prefix=...,region=...`
- `postgres:dsn=...,table=...`
- `redshift:dsn=...,table=...`
- `bigquery:project=...,dataset=...,table=...`
- `snowflake:account=...,user=...,password=...,database=...,schema=...,table=...`
- `kafka:bootstrap_servers=host1:9092;host2:9092,topic=...`
- `eventbridge:bus=...,region=...`
- `pubsub:project=...,topic=...`

Providers requiring cloud/database SDKs use lazy imports and fail clearly if the matching dependency is not installed in the execution environment.

For v1, start without a hosted or cloud sink. Add a sink only after the PR decision loop is trusted.

You can deliver the decision contract to an external system:

```yaml
webhook-url: ${{ secrets.VERIDION_WEBHOOK_URL }}
webhook-token: ${{ secrets.VERIDION_WEBHOOK_TOKEN }}
webhook-event-type: veridion.rdi.decision.v1
```

Output:

- `webhook_delivery_status`

## Reference workflows

- [examples/workflows/rdi.yml](../examples/workflows/rdi.yml)
- [examples/workflows/deploy-gate.yml](../examples/workflows/deploy-gate.yml)
- [Decision History](./DECISION_HISTORY.md)
