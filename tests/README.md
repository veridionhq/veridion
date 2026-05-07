# Tests

This directory follows the testing model defined in [docs/TESTING_STRATEGY.md](../docs/TESTING_STRATEGY.md).

Expected layout:

```text
tests/
  fixtures/
  unit/
  contract/
  integration/
  snapshots/
```

Rules:

- Add fixtures before implementing parser and normalization behavior.
- Keep unit tests fast and deterministic.
- Use snapshots only for human-facing output such as PR comments.
