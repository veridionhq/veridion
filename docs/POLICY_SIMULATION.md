# Policy Simulation

Policy simulation is an expansion workflow. It is useful after the v1 dependency-risk wedge is producing trusted decisions.

Veridion can compare multiple policy packs against the same change and scanner results.

This is the safest way to tune policy before changing live release enforcement.

## What it does

The simulator:

- builds one normalized analysis bundle
- evaluates multiple named policy packs against it
- emits side-by-side verdicts, reasons, and required actions

## Example

```bash
python3 -m veridion.policy.simulator \
  --diff-path pr.diff \
  --report trivy=artifacts/trivy.json \
  --report grype=artifacts/grype.json \
  --report syft=artifacts/syft.json \
  --policy-set v1=examples/policy-packs/dependency-risk-v1.yaml \
  --policy-set app=examples/policy-packs/application-team.yaml \
  --output-path policy-simulation.json
```

Output fields:

- policy-pack metadata
- final verdict / score / gate status
- blocking reasons
- required next steps
- blocking categories

## Why it matters

This gives teams a path to:

- compare pack strictness before rollout
- pilot new policy packs against real changes
- tune thresholds and approvals without breaking production workflows
