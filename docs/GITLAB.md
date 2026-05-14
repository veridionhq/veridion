# GitLab Adapter

Veridion now includes first-class GitLab adapter helpers in addition to the GitHub Action wedge.

Current GitLab surfaces:

- merge request metadata builder
- merge request note upsert
- generic CLI execution against scanner reports, diffs, and `operational-context.json`

## Build merge request metadata

From a GitLab merge request event payload:

```bash
python3 -m veridion.adapters.gitlab_merge_request_metadata \
  --event-path gitlab-event.json \
  --output-path mr-metadata.json \
  --base-ref "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
```

This produces the same metadata contract Veridion already consumes on GitHub:

- `title`
- `body`
- `labels`
- `commits`

## Run Veridion in GitLab CI

Once you have:

- `mr.diff`
- scanner JSON reports
- `operational-context.json`
- optionally `mr-metadata.json`

run the same engine CLI:

```bash
python3 -m veridion.action \
  --diff-path mr.diff \
  --report trivy=artifacts/trivy.json \
  --report semgrep=artifacts/semgrep.json \
  --report grype=artifacts/grype.json \
  --report syft=artifacts/syft.json \
  --policy-path .veridion/policy.yaml \
  --operational-context-path operational-context.json \
  --metadata-path mr-metadata.json \
  --comment-path veridion-pr-comment.md \
  --json-output-path veridion-result.json \
  --decision-contract-path veridion-decision.json
```

## Upsert a merge request note

Use the GitLab adapter to create or update the Veridion note on the merge request:

```bash
python3 -m veridion.adapters.gitlab_note \
  --gitlab-api-url "https://gitlab.example.com/api/v4" \
  --project-id "$CI_PROJECT_ID" \
  --merge-request-iid "$CI_MERGE_REQUEST_IID" \
  --gitlab-token "$GITLAB_TOKEN" \
  --comment-path veridion-pr-comment.md
```

The note adapter uses the same Veridion marker identifiers as GitHub, so repeated runs update the existing note instead of spamming new comments.

## Reference pipeline

- [examples/gitlab/.gitlab-ci.yml](../examples/gitlab/.gitlab-ci.yml)
