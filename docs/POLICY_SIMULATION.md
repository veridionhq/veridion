# Policy Simulation

Veridion can now compare multiple policy packs against the same change, scanner results, and operational context.

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
  --report semgrep=artifacts/semgrep.json \
  --report grype=artifacts/grype.json \
  --report syft=artifacts/syft.json \
  --policy-set app=examples/policy-packs/application-team.yaml \
  --policy-set platform=examples/policy-packs/platform-team.yaml \
  --policy-set regulated=examples/policy-packs/regulated-service.yaml \
  --operational-context-path operational-context.json \
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
