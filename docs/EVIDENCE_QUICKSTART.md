# Evidence Gateway Quickstart

This quickstart shows how to feed one non-security release signal into Veridion.

Use this after the dependency-risk quickstart when you want to prove that
organization-specific validation can flow into the same release decision without
custom Veridion code.

## 1. Choose A Producer

Start with JUnit XML because most CI systems can emit it.

Use the seed producer manifest:

```bash
examples/evidence/producers/junit.json
```

Validate it:

```bash
veridion-evidence validate-producer \
  --input examples/evidence/producers/junit.json \
  --summary
```

## 2. Produce Test Evidence

Run tests with JUnit output:

```bash
python3 -m pytest tests --junitxml=test-results/junit.xml
```

## 3. Ingest Evidence

Translate, validate, and check producer conformance in one step:

```bash
veridion-evidence ingest \
  --producer examples/evidence/producers/junit.json \
  --format junit \
  --input test-results/junit.xml \
  --output veridion-evidence.json \
  --name "unit test suite" \
  --required \
  --repo your-org/your-repo \
  --commit "$GITHUB_SHA" \
  --summary
```

## 4. Require Evidence In Policy

Policy can require evidence by type:

```yaml
require_evidence:
  - test_result
```

Or by type and name:

```yaml
require_evidence:
  - test_result:unit test suite
```

If required evidence is missing or uncertain, Veridion returns
`CONDITIONAL GO`. If required evidence fails, Veridion returns `NO GO`.

## 5. Pass Evidence To The Action

```yaml
- uses: veridionhq/veridion@v1
  with:
    diff-path: pr.diff
    policy-path: .veridion/policy.yaml
    evidence-paths: |
      veridion-evidence.json
```

The action emits:

- `release_evidence_json`
- `blocking_evidence_json`
- `review_evidence_json`
- `missing_required_evidence_json`

The full decision contract includes evidence under `release_evidence`.

## Expected Outcomes

- JUnit passed and required by policy -> no evidence block
- JUnit failed and required by policy -> `NO GO`
- JUnit missing and required by policy -> `CONDITIONAL GO`

That is the core adapter loop:

```text
producer manifest + raw output
  -> ingest
  -> validate
  -> conform
  -> veridion-evidence.json
  -> release decision
```

## Canary Proof

Use `examples/workflows/evidence-canary.yml` as the proof workflow for two core
Evidence Gateway scenarios:

- failed required evidence -> `NO GO`
- missing required evidence -> `CONDITIONAL GO`

The workflow uploads `veridion-decision.json`, `veridion-result.json`,
`veridion-pr-comment.md`, and the evidence bundle when present.
