# Demo Script

This is a five-minute walkthrough for design partners, early buyers, and
fundraising conversations.

## 1. Category

Open with the problem:

```text
Every organization has release gates, but every organization wires them
differently. Tests, scanners, runtime health, approvals, incidents, and internal
platform checks all produce signals. Veridion turns those fragmented signals
into one governed release decision.
```

Positioning:

```text
Veridion is the release decision operating layer.
```

## 2. Wedge

Start narrow:

```text
The first wedge is introduced dependency risk in GitHub pull requests.
Scanner output is noisy because it mixes new risk with legacy backlog.
Veridion compares current evidence against baseline evidence and decides whether
the PR should proceed.
```

Show:

- `GO`
- `CONDITIONAL GO`
- `NO GO`
- accepted-risk `CONDITIONAL GO`

Artifacts:

- PR comment
- `veridion-decision.json`

## 3. Evidence Gateway

Show why the product expands:

```text
The same evidence model works for tests, checks, runtime signals, approvals,
and internal validation.
```

Run or show:

```bash
veridion-evidence catalog
veridion-evidence validate-producer --input examples/evidence/producers/junit.json --summary
veridion-evidence ingest \
  --producer examples/evidence/producers/junit.json \
  --format junit \
  --input test-results/junit.xml \
  --output veridion-evidence.json \
  --name "unit test suite" \
  --required \
  --repo acme/payments-api \
  --commit "$GITHUB_SHA" \
  --summary
```

Explain:

```text
The product is not a pile of one-off integrations. Producers declare what they
emit. Evidence validates. Conformance proves the adapter is speaking Veridion's
language.
```

## 4. Policy

Show organization-specific requirements:

```yaml
require_evidence:
  - test_result:unit test suite
```

Explain:

```text
This lets every organization define its own release requirements without custom
Veridion core code.
```

Expected behavior:

- required failed evidence -> `NO GO`
- required missing evidence -> `CONDITIONAL GO`
- required passing evidence -> no evidence block

## 5. Decision Contract

Show `veridion-decision.json`:

- `decision.verdict`
- `decision.gate_status`
- `decision_requirements`
- `release_evidence`
- `actions.required_next_steps`

Explain:

```text
The PR comment is the human view. The decision contract is the platform API.
```

## 6. Canary Proof

Use `veridion-canary`:

- workflow: `.github/workflows/evidence-canary.yml`
- scenarios:
  - `failed-required-evidence` -> `NO GO`
  - `missing-required-evidence` -> `CONDITIONAL GO`

Artifacts:

- `veridion-decision.json`
- `veridion-result.json`
- `veridion-pr-comment.md`
- `veridion-evidence.json` when present

## 7. Closing

Close with the thesis:

```text
The release decision itself is not the moat. The moat is making every release
signal enter the system with consistent meaning.
```
