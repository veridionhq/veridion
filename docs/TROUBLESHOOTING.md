# Troubleshooting

This guide covers first-run issues for the v1 dependency-risk workflow.

## The action cannot post a PR comment

Check workflow permissions:

```yaml
permissions:
  contents: read
  pull-requests: write
```

Also verify these action inputs are present:

```yaml
github-token: ${{ secrets.GITHUB_TOKEN }}
repository: ${{ github.repository }}
pull-request-number: ${{ github.event.pull_request.number }}
```

## Confidence is MEDIUM

Confidence describes signal quality, not release severity.

Common causes:

- baseline reports are missing
- baseline reports normalized to zero findings while current reports contain findings
- the diff is very small and there are no meaningful scanner findings
- report attribution is suspicious or incomplete

Open `veridion-decision.json` and inspect:

- `decision.confidence`
- `decision.confidence_ceiling_reason`
- `evidence.attribution.mode`
- `evidence.reports.missing_baseline_tools`
- `evidence.reports.zero_finding_baseline_tools`

## Findings look introduced but should be existing

Verify the baseline scan ran against the pull request base commit.

The generated workflow should use:

```bash
git worktree add --detach ../veridion-base "${{ github.event.pull_request.base.sha }}"
```

Then scanner outputs should be mapped as:

```yaml
baseline-reports: |
  trivy=artifacts/baseline-trivy.json
  grype=artifacts/baseline-grype.json
  syft=artifacts/baseline-syft.json
```

## Reports are empty

Confirm each scanner wrote the expected file:

- `artifacts/trivy.json`
- `artifacts/grype.json`
- `artifacts/syft.json`
- `artifacts/baseline-trivy.json`
- `artifacts/baseline-grype.json`
- `artifacts/baseline-syft.json`

Then check report health in `veridion-decision.json`:

- `evidence.reports.current.<tool>.size_bytes`
- `evidence.reports.current.<tool>.normalized_findings`
- `evidence.reports.current.<tool>.inventory_records`
- `evidence.reports.current.<tool>.sha256`

## The workflow fails when adding the baseline worktree

Use full history checkout:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Without full history, the base commit may not be available locally.

## Accepted risk does not suppress a finding

Check `.veridion/suppressions.json`.

The rule must match the finding with one or more stable fields:

- `rule_id`
- `finding_type`
- `package_name`
- `package_version`

The rule must also be active:

- `status` is `approved`
- `expires_on` is not in the past

Rules with `status: proposed`, `renewal_requested`, or `rejected` do not behave like clean approved suppressions.

## Accepted risk appears as CONDITIONAL GO

This is expected. V1 does not treat accepted risk as a pristine `GO`.

Accepted-risk suppressions remain visible so reviewers can see:

- how many findings were suppressed
- why they were suppressed
- whether the exception has expiry or governance gaps

## The comment mentions baseline attribution

Baseline attribution appears when Veridion cannot fully prove introduced versus existing risk.

Fix the scanner baseline first. Do not tune policy around broken attribution.

## The install feels too broad

Use only the default v1 path:

- `dependency-risk-v1` preset
- Syft, Grype, and Trivy
- no `operational-context-path`
- no approval map
- no hosted service sink
- no LLM configuration

Those expansion paths should wait until the dependency-risk loop is trusted.

## Bootstrap refuses to overwrite files

Bootstrap protects existing files by default so it does not erase policy or accepted-risk exceptions.

For a full regeneration, use:

```bash
veridion-bootstrap \
  --preset dependency-risk-v1 \
  --repo-id your-org/your-repo \
  --service-id your-service \
  --team-id your-team \
  --force
```

For the safer common case, refresh only the workflow:

```bash
veridion-bootstrap \
  --preset dependency-risk-v1 \
  --repo-id your-org/your-repo \
  --service-id your-service \
  --team-id your-team \
  --only workflow \
  --force
```

Use the workflow-only path when `.veridion/suppressions.json` already contains real exceptions.
