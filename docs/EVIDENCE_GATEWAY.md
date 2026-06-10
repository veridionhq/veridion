# Evidence Gateway

Veridion is a trusted release decision system. Scanner findings, test results,
runtime readiness, approval state, and operational checks are evidence. Veridion
normalizes that evidence into one contract before evaluating policy.

The integration layer is a first-class product surface. Decisions become
straightforward only after evidence from different systems can be trusted,
validated, compared, and routed through the same contract.

The core job is to get the right release signals into Veridion with consistent
meaning. Everything else, including policy evaluation, approval routing, audit,
and reporting, depends on that semantic layer being reliable.

The default v1 wedge remains introduced dependency risk. Native release evidence
is the expansion path that lets teams bring other gates into the same decision
without replacing their CI, test, scanner, observability, or deployment systems.

## Native Evidence Contract

`veridion-evidence.json` can contain either a single evidence item or an evidence
bundle.

Bundle example:

```json
{
  "schema_version": 1,
  "subject": {
    "repo": "acme/payments-api",
    "pull_request": 42,
    "commit": "abc123",
    "service": "payments-api",
    "environment": "staging"
  },
  "evidence": [
    {
      "evidence_type": "test_result",
      "category": "test",
      "name": "checkout e2e",
      "status": "failed",
      "severity": "high",
      "required": true,
      "summary": "Checkout flow failed in staging",
      "details_url": "https://github.com/acme/payments-api/actions/runs/123456",
      "observed_at": "2026-06-09T20:30:00Z",
      "valid_for_commit": true,
      "source": {
        "provider": "github_actions",
        "workflow": "e2e.yml",
        "run_id": "123456"
      }
    }
  ]
}
```

Single item example:

```json
{
  "evidence_type": "runtime_signal",
  "category": "runtime",
  "name": "canary health",
  "status": "degraded",
  "required": true,
  "source": {
    "provider": "argo_rollouts"
  }
}
```

## Signal Vocabulary

Adapters should use Veridion's canonical vocabulary for statuses, evidence
types, categories, and severities. This prevents each integration from inventing
its own meaning for words like `failed`, `missing`, `degraded`, or `unsatisfied`.

```bash
veridion-evidence catalog
```

The catalog is machine-readable JSON and can be written to disk:

```bash
veridion-evidence catalog --output evidence-catalog.json
```

The current first-class evidence types are:

- `test_result`
- `ci_check`
- `runtime_signal`
- `security_finding`
- `approval_state`
- `change_signal`
- `policy_state`

## Decision Semantics

For the first gateway slice, Veridion applies conservative semantics only when
evidence is marked `required` or when policy requires that evidence.

- Required evidence with `failed`, `blocked`, `unhealthy`, `invalid`,
  `unsatisfied`, or `expired` status produces `NO GO`.
- Required evidence with `warning`, `degraded`, `missing`, `unknown`, `skipped`,
  or `stale` status produces `CONDITIONAL GO`.
- Passing or informational evidence is preserved in the decision contract but
  does not change the verdict by itself.

This keeps the entry path predictable: teams opt evidence into release gating by
marking it required.

Policy can also require evidence centrally:

```yaml
require_evidence:
  - test_result
  - ci_check:required checks
```

Selectors use either `evidence_type` or `evidence_type:name`.

- If required evidence is present and failed, blocked, unhealthy, invalid,
  unsatisfied, or expired, the decision becomes `NO GO`.
- If required evidence is missing, warning, degraded, unknown, skipped, or stale,
  the decision becomes `CONDITIONAL GO`.
- If required evidence is present and passed, healthy, satisfied, valid, detected,
  or not_detected, it does not block by itself.

## GitHub Action Input

Pass one or more native evidence files with `evidence-paths`:

```yaml
- uses: veridionhq/veridion@v1
  with:
    diff-path: pr.diff
    reports: |
      syft=syft.json
      grype=grype.json
      trivy=trivy.json
    baseline-reports: |
      syft=baseline-syft.json
      grype=baseline-grype.json
      trivy=baseline-trivy.json
    evidence-paths: |
      veridion-evidence.json
```

The normalized evidence is emitted in `veridion-decision.json` under
`release_evidence`.

## Translators

The native evidence contract is the integration boundary. Translators can be
implemented in any language as long as they emit `veridion-evidence.json`.
First-party translators are convenience tools for common local formats.

Translate JUnit XML:

```bash
veridion-evidence translate junit \
  --input junit.xml \
  --output veridion-evidence.json \
  --required \
  --repo acme/payments-api \
  --commit "$GITHUB_SHA"
```

Translate GitHub check-runs JSON:

```bash
veridion-evidence translate github-checks \
  --input check-runs.json \
  --output veridion-evidence.json \
  --required \
  --repo acme/payments-api \
  --commit "$GITHUB_SHA"
```

This keeps the core engine stable while allowing adapters to live close to the
systems that produce evidence. A platform team can write a Go, Node, Rust, Java,
or Bash translator for an internal release system without changing Veridion's
decision engine.

## Ingestion Lifecycle

For normal adapter use, prefer `ingest` over calling `translate` and `validate`
as separate steps. `ingest` validates the producer manifest, translates raw
source output, validates native evidence, checks producer conformance, and writes
the final bundle.

```bash
veridion-evidence ingest \
  --producer examples/evidence/producers/junit.json \
  --format junit \
  --input junit.xml \
  --output veridion-evidence.json \
  --name "unit test suite" \
  --required \
  --repo acme/payments-api \
  --commit "$GITHUB_SHA" \
  --summary
```

This is the local adapter lifecycle:

```text
producer manifest + raw output
  -> translate
  -> validate native evidence
  -> check producer conformance
  -> veridion-evidence.json
  -> release decision
```

## Producer Validation

Every adapter should be able to prove that it emits valid native evidence before
the decision engine consumes it.

```bash
veridion-evidence validate \
  --input veridion-evidence.json \
  --summary
```

Validation fails fast on malformed evidence and can be run inside producer CI.
With `--summary`, the command reports item counts, required blocking evidence,
required review evidence, and status/type breakdowns.

This is the contract test for the ecosystem: first-party translators, internal
platform adapters, and future partner integrations should all pass it.

## Producer Manifests

An evidence producer can declare what signals it emits before any evidence is
ingested. This makes integrations discoverable and keeps adapter behavior aligned
with the canonical vocabulary.

Example producer manifest:

```json
{
  "schema_version": 1,
  "producer": {
    "id": "github-actions",
    "display_name": "GitHub Actions",
    "version": "1.0.0",
    "owner": "platform"
  },
  "emits": [
    {
      "evidence_type": "test_result",
      "statuses": ["passed", "failed", "skipped"],
      "subject_keys": ["repo", "commit", "pull_request"]
    },
    {
      "evidence_type": "ci_check",
      "statuses": ["passed", "failed", "unknown"],
      "subject_keys": ["repo", "commit"]
    }
  ]
}
```

Validate it:

```bash
veridion-evidence validate-producer \
  --input evidence-producer.json \
  --summary
```

The producer manifest is the adapter contract. It answers: who is producing the
signal, what evidence types can it emit, which statuses are possible, and which
subject identifiers should be attached.

Seed manifests live in `examples/evidence/producers/`:

- `junit.json`
- `github-checks.json`
- `datadog-runtime.json`
- `pagerduty-incidents.json`

An end-to-end GitHub Actions example lives at
`examples/workflows/evidence-gateway.yml`.

An example policy pack that requires release evidence lives at
`examples/policy-packs/evidence-gateway.yaml`.

## Product Direction

The gateway should grow in this order:

1. Native Veridion evidence JSON.
2. Producer validation so adapters can prove contract compatibility.
3. Producer manifests so integrations can declare their release-signal surface.
4. Local translators for common formats such as JUnit, GitHub check runs, and
   generic CI summaries.
5. Hosted ingestion for organizations that want evidence history, replay, and
   cross-repository release governance.

The goal is not to build every integration first. The goal is to give every tool
one stable way to tell Veridion what it knows about release readiness.
