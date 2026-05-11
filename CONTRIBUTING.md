# Contributing

Veridion is being built as infrastructure, so contributions should favor clarity, explainability, and deterministic behavior over cleverness.

## Before opening changes

1. Read [README.md](README.md).
2. Prefer a focused change over a broad refactor.
3. Keep the product wedge intact:
   PR-level deployment trust decisions first.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m pytest
```

## Change expectations

- Preserve introduced-risk semantics.
- Preserve explainable output.
- Add or update tests for behavior changes.
- Avoid product sprawl that widens beyond the current wedge.

## Pull requests

PRs should explain:

- what changed
- why it changed
- how behavior was validated
- any policy or decision-output implications
