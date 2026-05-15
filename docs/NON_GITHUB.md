# Non-GitHub Producers

Veridion's portable input contract is `operational-context.json`.

You do not need GitHub event payloads to use Veridion. Any CI/CD system can:

1. emit scanner reports
2. emit a unified diff
3. build a versioned `operational-context.json`
4. run the Veridion CLI directly

If you are specifically targeting GitLab merge requests, use the dedicated adapter docs:

- [GitLab Adapter](./GITLAB.md)

## Build operational context from normalized sections

The builder now supports direct section inputs:

```bash
python3 -m veridion.action.operational_context_builder \
  --metadata-path metadata.json \
  --historical-path historical.json \
  --runtime-path runtime.json \
  --ownership-path ownership.json \
  --trust-baseline-path trust-baseline.json \
  --trust-memory-path trust-memory.json \
  --trust-profile-metadata-path trust-profile-metadata.json \
  --source generic-ci \
  --output-path operational-context.json
```

Each input file should contain one normalized top-level object for that section.

Reference script:

- [examples/non-github/build-operational-context.sh](../examples/non-github/build-operational-context.sh)

## Build normalized runtime context from live sources

If your runtime readiness signals come from deployment systems rather than a pre-normalized JSON file, use the runtime-source builder first.

Example:

```bash
python3 -m veridion.action.runtime_context_builder \
  --incident-path incident.json \
  --freeze-path freeze.json \
  --alerts-path alerts.json \
  --canary-path canary.json \
  --rollback-path rollback.json \
  --environment production \
  --deployment-window after_hours \
  --public-exposure true \
  --blast-radius high \
  --rollout-strategy canary \
  --output-path runtime.json
```

Reference script:

- [examples/non-github/build-runtime-context.sh](../examples/non-github/build-runtime-context.sh)

## Run Veridion without GitHub Actions

Once you have:

- `pr.diff`
- scanner JSON reports
- `operational-context.json`

run:

```bash
python3 -m veridion.action \
  --diff-path pr.diff \
  --report trivy=artifacts/trivy.json \
  --report semgrep=artifacts/semgrep.json \
  --report grype=artifacts/grype.json \
  --report syft=artifacts/syft.json \
  --baseline-report trivy=artifacts/baseline-trivy.json \
  --baseline-report semgrep=artifacts/baseline-semgrep.json \
  --baseline-report grype=artifacts/baseline-grype.json \
  --baseline-report syft=artifacts/baseline-syft.json \
  --policy-path .veridion/policy.yaml \
  --operational-context-path operational-context.json \
  --comment-path veridion-pr-comment.md \
  --json-output-path veridion-result.json \
  --decision-contract-path veridion-decision.json
```
