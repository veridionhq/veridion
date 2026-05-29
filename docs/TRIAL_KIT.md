# Design-Partner Trial Kit

Use this kit for the first Veridion v1 evaluation in a real repository.

## Goal

Validate one narrow question:

```text
Did this pull request introduce unacceptable dependency risk?
```

Do not evaluate hosted control planes, runtime gates, AI wording, or broad operational governance in the first trial.

## Install

Install the stable v1 release:

```bash
python3 -m pip install "git+https://github.com/veridionhq/veridion.git@v1.0.2"
```

Bootstrap the target repo:

```bash
veridion-bootstrap \
  --preset dependency-risk-v1 \
  --repo-id your-org/your-repo \
  --service-id your-service \
  --team-id your-team
```

Commit the generated files:

- `.github/workflows/veridion-rdi.yml`
- `.veridion/policy.yaml`
- `.veridion/suppressions.json`
- `.veridion/README.md`

## Trial PRs

Run at least these cases:

- clean change: docs-only or dependency-neutral change
- high dependency risk: introduce a vulnerable high-severity dependency
- critical dependency risk: introduce a vulnerable critical dependency
- accepted risk: add an approved suppression for a known finding

Expected decisions:

```text
Clean change -> GO
Introduced HIGH dependency risk -> CONDITIONAL GO
Introduced CRITICAL dependency risk -> NO GO
Accepted-risk suppression present -> CONDITIONAL GO
```

## What To Capture

For each PR, capture:

- PR URL
- Veridion PR comment
- `veridion-decision.json`
- `veridion-result.json` if deeper debugging is needed
- whether the decision matched human reviewer judgment
- what was confusing or missing

## Evaluation Questions

- Did Veridion separate introduced risk from existing backlog?
- Did the decision feel rule-driven and explainable?
- Did confidence reflect report and baseline quality?
- Did the PR comment make the next action obvious?
- Did accepted risk remain visible and auditable?
- Would this team leave the workflow installed?

## Success Criteria

The trial is successful when:

- the workflow installs without custom plumbing
- scanners run on both head and base
- the four expected outcomes are reproducible
- reviewers understand why each decision happened
- no one needs a hosted service, cloud sink, or LLM to complete the trial

## First Outside-Install Result

The first controlled outside install used `veridionhq/veridion-v1-install-smoke` with Veridion `v1.0.1`.

Observed results:

| Scenario | Decision | Confidence | Key result |
| --- | --- | --- | --- |
| Bootstrap install PR | `GO` | `HIGH` | `0` introduced findings, `3` existing findings |
| `smoke/conditional` | `CONDITIONAL GO` | `HIGH` | introduced `urllib3 1.25.8` high/medium dependency risk |
| `smoke/no-go` | `NO GO` | `HIGH` | introduced critical `PyYAML 5.3.1` dependency risk |
| `smoke/accepted-risk` | `CONDITIONAL GO` | `HIGH` | `20` findings suppressed and accepted risk remained visible |

This validated the most important v1 behavior outside the Veridion codebase: introduced risk is separated from existing backlog, and accepted risk is visible rather than treated as a pristine `GO`.

## Follow-Up Package

Review these docs during or after the trial:

- [Quickstart](QUICKSTART.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Evaluation Checklist](EVALUATION_CHECKLIST.md)
- [V1 Release Readiness](V1_READINESS.md)
- [Canary Matrix](CANARY_MATRIX.md)
