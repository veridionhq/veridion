# Automation Guide

Veridion now emits a machine-facing decision contract at `veridion-decision.json` and a matching set of GitHub Action outputs. The PR comment is presentation. Automation should consume the contract and outputs directly.

`veridion-result.json` is still available, but it serves a different purpose:

- `veridion-result.json`: full runner envelope, analysis payload, comment text, and embedded decision contract
- `veridion-decision.json`: stable machine-facing contract for gates, approvals, and external integrations

If you are writing workflow logic, approval routing, or webhook consumers, prefer `veridion-decision.json`.

## Core outputs

- `gate_status`: `pass`, `review`, or `block`
- `decision_allowed`: whether the configured gate allows the verdict
- `required_approvals_json`
- `required_next_steps_json`
- `blocking_reasons_json`
- `blocking_categories_json`
- `accepted_risk_present`
- `decision_contract_path`

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
- `approval_state_json`

When `decision-contract-path` is set, the same approval satisfaction state is written back into `veridion-decision.json` under `automation`.

## Consume accepted-risk governance

Accepted risk is visible in both `veridion-result.json` and `veridion-decision.json`.

Use:

- `accepted_risk_present`
- `accepted_risk.governance_gaps`
- `accepted_risk.suppressed_findings`

to distinguish:

- a clean change
- a change with reviewed accepted risk
- a change with incomplete suppression governance metadata

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
