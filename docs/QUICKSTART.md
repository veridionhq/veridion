# Quickstart

This is the shortest path to a usable Veridion install in a GitHub repository.

## 1. Choose a policy pack

Start with one of these presets:

- [Application Team](../examples/policy-packs/application-team.yaml)
- [Platform Team](../examples/policy-packs/platform-team.yaml)
- [Regulated Service](../examples/policy-packs/regulated-service.yaml)

If you are unsure, start with `application-team.yaml`.

## 2. Add repo-local trust inputs

Create:

- `.veridion/trust-profile.source.json`
- optionally `.veridion/trust-catalog.source.json`

You can start from:

- [trust-profile.source.json](../examples/trust/trust-profile.source.json)
- [trust-catalog.source.json](../examples/trust/trust-catalog.source.json)

The repo-local file should describe durable posture for the repo, service, and team. It is not PR-specific.

## 3. Add the workflow

Start from:

- [examples/workflows/rdi.yml](../examples/workflows/rdi.yml)

Minimal edits:

- point `policy-path` at your chosen policy pack
- point `--config-path` and `--catalog-path` at your repo-local `.veridion/` files
- keep `operational-context.json` as the action input

## 4. Open a PR

The workflow will:

- generate a diff artifact
- build a trust profile artifact
- build a versioned `operational-context.json`
- run scanners on head and base
- produce a Veridion decision and PR comment

## 5. Tune only after first runs

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

## Install Notes

- `operational-context.json` is the portable integration contract. Other CI/CD systems should emit that same artifact instead of duplicating Veridion internals.
- GitHub is currently the reference producer, not the only intended environment.
- If you want the lowest-friction first install, do not edit the scoring model yet. Start with approvals and recommendations first.
