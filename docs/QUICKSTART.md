# Quickstart

This is the shortest path to a usable Veridion install in a GitHub repository.

The default v1 path is intentionally narrow: decide whether a pull request introduced unacceptable dependency risk. Start there before enabling broader release-governance features.

## 1. Install Veridion

For a GitHub-hosted install:

```bash
python3 -m pip install "git+https://github.com/veridionhq/veridion.git@v1.0.1"
```

Then the CLIs are available as:

```bash
veridion-bootstrap --help
veridion-rdi --help
```

If you prefer module execution after install, this also works:

```bash
python3 -m veridion.action.bootstrap --help
```

For contributor/local development only:

```bash
python3 -m pip install -e /path/to/veridion
```

Optional integration extras:

```bash
python3 -m pip install "veridion[aws]"
python3 -m pip install "veridion[gcp]"
python3 -m pip install "veridion[db]"
python3 -m pip install "veridion[events]"
```

These are optional. The default deterministic GitHub Action path does not require them.

## 2. Bootstrap the repo

Run:

```bash
veridion-bootstrap \
  --preset dependency-risk-v1 \
  --repo-id your-org/your-repo \
  --service-id your-service \
  --team-id your-team
```

This creates:

- `.veridion/policy.yaml`
- `.veridion/suppressions.json`
- `.veridion/README.md`
- `.github/workflows/veridion-rdi.yml`

Use broader presets later only when you are ready to evaluate operational context and approval behavior.

## 3. Choose or adjust the policy pack

Start with the v1 dependency-risk policy:

- [Dependency Risk V1](../examples/policy-packs/dependency-risk-v1.yaml)

This policy keeps the first install focused on introduced dependency risk:

- introduced critical dependency risk -> `NO GO`
- introduced high dependency risk -> `CONDITIONAL GO`
- no introduced severe dependency risk -> `GO`

## 4. Add accepted-risk suppressions only when needed

Use `.veridion/suppressions.json` for findings that are known and intentionally accepted for a limited period.

Example:

```json
{
  "schema_version": 1,
  "suppressions": [
    {
      "exception_id": "AR-2026-001",
      "status": "approved",
      "rule_id": "CVE-2024-1234",
      "package_name": "urllib3",
      "package_version": "1.25.8",
      "reason_type": "accepted_risk",
      "reason": "temporary exception until upstream vendor patch",
      "owner": "platform-security",
      "approved_by": "security-owner",
      "ticket": "SEC-1234",
      "created_at": "2026-05-13T00:00:00Z",
      "reviewed_at": "2026-05-13T01:00:00Z",
      "expires_on": "2026-06-30"
    }
  ]
}
```

Lifecycle fields:

- `exception_id`
- `reason_type`: `accepted_risk`, `false_positive`, `no_exposure`, or `risk_reduction`
- `status`: `proposed`, `approved`, `renewal_requested`, or `rejected`
- `reviewed_at`
- `renewal_of` for renewal requests
- `reduced_severity` when `reason_type` is `risk_reduction`

Rules with `status: proposed` do not suppress findings yet. They remain visible until approved.

If you want suppressions to block release when audit metadata is incomplete, set:

```yaml
require_complete_accepted_risk_metadata: true
```

## 5. Add the workflow

Start from:

- [examples/workflows/rdi.yml](../examples/workflows/rdi.yml)

The bootstrap command already creates `.github/workflows/veridion-rdi.yml`.

The generated workflow uses:

```yaml
uses: veridionhq/veridion@v1.0.1
```

If you want to adapt the example manually, minimal edits are:

- point `policy-path` at your chosen policy pack
- keep the current and baseline Syft, Grype, and Trivy report mappings
- omit `operational-context-path` for the v1 dependency-risk path

## 6. Open a PR

The workflow will:

- generate a diff artifact
- run scanners on head and base
- produce a Veridion decision and PR comment
- emit `veridion-decision.json` for downstream automation

## 7. Tune only after first runs

Do not customize everything up front.

First review:

- false positives
- introduced versus pre-existing dependency attribution
- whether `GO`, `CONDITIONAL GO`, and `NO GO` match reviewer judgment
- whether the confidence level reflects report and baseline quality
- whether the chosen policy pack is too strict or too loose

Then tune:

- accepted-risk suppressions
- policy behavior only after reviewing real PRs

## Expansion Integrations

The v1 dependency-risk wedge does not require AI wording, S3, Athena, hosted services, or a cloud provider.

Optional expansion paths exist for teams that later want centralized history, external event sinks, broader operational context, or model-assisted wording on top of deterministic decisions.

Important:

- users do not need their own LLM to use Veridion
- users do not need S3 or Athena to use Veridion
- users do not need the hosted control plane to evaluate the v1 dependency-risk wedge

Those are optional integrations after the basic PR decision loop is trusted.

## Install Notes

- `operational-context.json` is the portable integration contract for broader release-governance scenarios. Do not feed it into the v1 workflow until the dependency-risk loop is trusted.
- GitHub is currently the reference v1 producer, not the only intended environment.
- If you want the lowest-friction first install, do not edit the scoring model yet. Start with introduced dependency risk, baseline quality, and accepted-risk handling first.
- If the first run is confusing, use [Troubleshooting](TROUBLESHOOTING.md) before changing policy.
