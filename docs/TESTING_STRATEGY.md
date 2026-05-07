# Testing Strategy

## Standard

Testing is part of implementation, not a cleanup phase after implementation.

Every meaningful code change should ship with verification in the same change set. The default path is:

1. Add or update fixtures for the scenario.
2. Add or update tests that describe the intended behavior.
3. Implement or adjust the code.
4. Run the relevant tests immediately.
5. Update docs if behavior or contracts changed.

## Test Pyramid

### 1. Unit Tests

Use for:

- Parsers
- Schema normalization
- Risk feature extraction
- Policy evaluation
- Scoring logic
- Formatting helpers

Requirements:

- Fast
- Deterministic
- High signal on failures

### 2. Fixture-Based Contract Tests

Use for:

- Scanner payload normalization
- PR diff parsing
- Baseline comparison behavior
- Policy file parsing
- Decision output stability

Requirements:

- Realistic sample inputs
- Versioned fixtures
- Explicit assertions on normalized structure and decision outputs

### 3. Snapshot Tests

Use for:

- PR comment rendering
- Human-readable decision summaries

Requirements:

- Keep snapshots small and meaningful
- Review snapshot updates carefully for accidental UX regressions

### 4. Integration Tests

Use for:

- End-to-end decision flow from inputs to comment output
- GitHub Action input/output boundaries
- Multi-tool ingestion paths

Requirements:

- Focus on critical flows
- Avoid excessive brittleness

## Quality Gates By Milestone

### M0

- Docs reviewed for consistency
- Basic CI test command defined once code exists

### M1

- Parser and normalization unit tests
- Fixture contracts for each supported tool

### M2

- Baseline suppression tests
- Edge-case tests for diff handling

### M3

- Deterministic scoring tests
- Policy override tests
- Recommendation generation tests

### M4

- Snapshot tests for PR comments
- Regression tests for decision summaries

### M5

- Action integration tests
- Happy path and failure path coverage

## Non-Negotiables

- No scoring rule without tests
- No parser without fixtures
- No PR comment change without snapshot review
- No policy behavior without explicit contract coverage
- No milestone marked complete without reproducible verification

## Suggested Initial Layout

```text
tests/
  fixtures/
    scanners/
    diffs/
    policies/
    decisions/
  unit/
  contract/
  integration/
  snapshots/
```

## Review Checklist For Every PR

- Does the change add or modify behavior?
- Where is the test that proves it?
- Are fixtures realistic and minimal?
- Is the output deterministic?
- Did docs need an update?
- Does the change reduce or increase false-positive risk?
