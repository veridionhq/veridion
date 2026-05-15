# Quickstart

This is the shortest path to a usable Veridion install in a GitHub repository.

## 1. Install Veridion

For a GitHub-hosted install:

```bash
python3 -m pip install "git+https://github.com/veridionhq/veridion.git@main"
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
  --preset application-team \
  --repo-id your-org/your-repo \
  --service-id your-service \
  --team-id your-team
```

This creates:

- `.veridion/policy.yaml`
- `.veridion/trust-profile.source.json`
- `.veridion/trust-catalog.source.json`
- `.veridion/suppressions.json`
- `.github/workflows/veridion-rdi.yml`

Use `--preset platform-team` or `--preset regulated-service` when those better match the repo.

## 3. Choose or adjust the policy pack

Start with one of these presets:

- [Application Team](../examples/policy-packs/application-team.yaml)
- [Platform Team](../examples/policy-packs/platform-team.yaml)
- [Regulated Service](../examples/policy-packs/regulated-service.yaml)

If you are unsure, start with `application-team.yaml`.

## 4. Add repo-local trust inputs

Create:

- `.veridion/trust-profile.source.json`
- optionally `.veridion/trust-catalog.source.json`

You can start from:

- [trust-profile.source.json](../examples/trust/trust-profile.source.json)
- [trust-catalog.source.json](../examples/trust/trust-catalog.source.json)

The bootstrap command already creates these files. Adjust them for your repo after the first scaffold.

## 5. Add accepted-risk suppressions only when needed

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
- `status`: `proposed`, `approved`, `renewal_requested`, or `rejected`
- `reviewed_at`
- `renewal_of` for renewal requests

Rules with `status: proposed` do not suppress findings yet. They remain visible until approved.

If you want suppressions to block release when audit metadata is incomplete, set:

```yaml
require_complete_accepted_risk_metadata: true
```

## 6. Add the workflow

Start from:

- [examples/workflows/rdi.yml](../examples/workflows/rdi.yml)

The bootstrap command already creates `.github/workflows/veridion-rdi.yml`.

If you want to adapt the example manually, minimal edits are:

- point `policy-path` at your chosen policy pack
- point `--config-path` and `--catalog-path` at your repo-local `.veridion/` files
- keep `operational-context.json` as the action input

## 7. Open a PR

The workflow will:

- generate a diff artifact
- build a trust profile artifact
- build a versioned `operational-context.json`
- run scanners on head and base
- produce a Veridion decision and PR comment
- emit `veridion-decision.json` for downstream automation

## 8. Tune only after first runs

Do not customize everything up front.

First review:

- false positives
- approval noise
- rollout guidance
- whether the chosen policy pack is too strict or too loose

Then tune:

- `require_*_for`
- score penalties
- trust profile posture values

## Optional AI wording layer

Veridion can optionally rewrite its structured threat facts into shorter English using a model provider, while still keeping the decision and policy logic deterministic.

For an OpenAI-backed setup in GitHub Actions, add:

- repository variable: `VERIDION_COMMENT_SUMMARY_PROVIDER=openai`
- repository variable: `VERIDION_COMMENT_SUMMARY_MODEL=gpt-5-mini`
- repository secret: `VERIDION_COMMENT_SUMMARY_API_KEY`

The workflow example already passes these optional inputs through when they are present.

Supported providers today:

- OpenAI-compatible
- Anthropic / Claude
- AWS Bedrock

If no provider is configured, or if the model response is invalid, Veridion falls back to deterministic rendering automatically.

Important:

- users do not need their own LLM to use Veridion
- users do not need S3 or Athena to use Veridion

Those are optional integrations for teams that want centralized storage, analytics, or AI wording.

## Install Notes

- `operational-context.json` is the portable integration contract. Other CI/CD systems should emit that same artifact instead of duplicating Veridion internals.
- GitHub is currently the reference producer, not the only intended environment.
- The composite action can build operational context internally from `.veridion/trust-profile.source.json` and `.veridion/trust-catalog.source.json`. External repos do not need local Veridion Python modules in CI.
- If you want the lowest-friction first install, do not edit the scoring model yet. Start with approvals and recommendations first.
