# Automation Guide

Veridion now emits a machine-facing decision contract at `veridion-decision.json` and a matching set of GitHub Action outputs. The PR comment is presentation. Automation should consume the contract and outputs directly.

`veridion-result.json` is still available, but it serves a different purpose:

- `veridion-result.json`: full runner envelope, analysis payload, comment text, and embedded decision contract
- `veridion-decision.json`: stable machine-facing contract for gates, approvals, and external integrations

If you are writing workflow logic, approval routing, or webhook consumers, prefer `veridion-decision.json`.

Important product boundary:

- Veridion does not require an external LLM
- Veridion does not require S3, Athena, or any cloud provider by default

Those are optional integration layers on top of the deterministic core.

## Core outputs

- `gate_status`: `pass`, `review`, or `block`
- `decision_allowed`: whether the configured gate allows the verdict
- `required_approvals_json`
- `required_next_steps_json`
- `blocking_reasons_json`
- `blocking_categories_json`
- `accepted_risk_present`
- `decision_contract_path`
- `decision_event_path`
- `sink_delivery_summary_json`

## Decision contract

The action writes `veridion-decision.json` by default when `decision-contract-path` is set.

Key fields:

- `decision.verdict`
- `decision.gate_status`
- `decision.decision_allowed`
- `decision.blocking_categories`
- `actions.required_approvals`
- `actions.required_approval_labels`
- `actions.required_next_steps`
- `accepted_risk.governance_gaps`
- `signals.runtime.runtime_safety_checks`
- `signals.runtime.active_runtime_gates`

## Runtime release gates

Live runtime-readiness gates now flow through the same decision contract.

Runtime fields Veridion understands:

- `deployment_freeze_active`
- `active_incident`
- `active_incident_severity`
- `alert_state`
- `canary_health`
- `rollback_viability`

These are surfaced in:

- `signals.runtime.active_runtime_gates`
- `decision.blocking_categories`
- `actions.required_next_steps`

Examples:

- active freeze or blocked rollback path can force `NO GO`
- degraded canary health or unverified rollback path can force `CONDITIONAL GO`

## Gate a deploy

For a hard deploy gate, let the action fail the job itself:

```yaml
- name: Run Veridion RDI
  id: run-rdi
  uses: veridionhq/veridion@main
  with:
    diff-path: pr.diff
    reports: ${{ vars.VERIDION_REPORTS }}
    baseline-reports: ${{ vars.VERIDION_BASELINE_REPORTS }}
    policy-path: .veridion/policy.yaml
    trust-profile-source-path: .veridion/trust-profile.source.json
    trust-catalog-source-path: .veridion/trust-catalog.source.json
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

## Enforce approval routing

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

## Verify approval satisfaction

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

## Emit decision events

Veridion now emits a machine-readable decision event artifact after approval verification so history captures the final enforced state, not just the raw runner verdict.

Outputs:

- `decision_event_path`
- `decision_history_path`

Inputs:

- `decision-event-path`
- `decision-history-path`

## Deliver canonical events to sinks

The canonical transport surface is now `veridion-decision-event.json`.

Action inputs:

- `decision-sinks`
- `fail-on-sink-error`

Output fields:

- `sink_delivery_summary_json`
- `sink_delivery_failures_json`

Supported sink kinds:

- `local-file:path=/abs/path/event.json`
- `local-ndjson:path=/abs/path/history.ndjson`
- `webhook:url=https://...`
- `s3:bucket=...,key=...,region=...`
- `postgres:dsn=...,table=...`
- `redshift:dsn=...,table=...`
- `bigquery:project=...,dataset=...,table=...`
- `snowflake:account=...,user=...,password=...,database=...,schema=...,table=...`
- `kafka:bootstrap_servers=host1:9092;host2:9092,topic=...`
- `eventbridge:bus=...,region=...`
- `pubsub:project=...,topic=...`

Providers requiring cloud/database SDKs use lazy imports and fail clearly if the matching dependency is not installed in the execution environment.

Recommended first production sink:

- S3 as the central append-only event store

See:

- [AWS Deployment Pattern](./AWS.md)

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
