# AWS Deployment Pattern

AWS is the first recommended production path for centralized Veridion decision history.

That does not mean every Veridion user needs AWS.

The product works without:

- S3
- Athena
- Bedrock
- any external LLM

AWS becomes useful when a team wants:

- centralized decision-event storage
- queryable release history
- object-store durability
- future analytics over large event volumes

## Recommended AWS architecture

Use three layers:

1. canonical event contract
2. S3 as system of record
3. Athena or a warehouse as system of insight

Recommended first production path:

- `veridion-decision-event.json` as the canonical event
- S3 sink for persistent storage
- Athena on top of the S3 event layout for historical queries

## Optional dependency install

For AWS sinks and Bedrock support:

```bash
python3 -m pip install "veridion[aws]"
```

For local development from the repo:

```bash
python3 -m pip install -e ".[aws]"
```

## Recommended S3 layout

Use partition-friendly keys:

```text
s3://<bucket>/veridion/events/repo=<owner_repo>/year=YYYY/month=MM/day=DD/verdict=<verdict>/ts=<timestamp>-pr=<number>.json
```

Example:

```text
s3://veridion-prod-events/veridion/events/repo=acme_service-a/year=2026/month=05/day=14/verdict=conditional-go/ts=2026-05-14T12:00:00Z-pr=42.json
```

This keeps the object store:

- append-only
- date-partitioned
- Athena-friendly
- easy to mirror into Snowflake or other warehouses later

## Example sink config

```yaml
decision-sinks: |
  s3:bucket=veridion-prod-events,prefix=veridion/events,region=us-west-2
  local-ndjson:path=veridion-decision-history.ndjson
```

If you omit `key`, Veridion derives the recommended partitioned layout automatically from the canonical decision event. You can still provide a fully explicit `key=` when you need a custom object path.

## Minimal IAM policy

For an S3-only sink path, the action role typically needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::veridion-prod-events/veridion/events/*"
      ]
    }
  ]
}
```

If you later query with Athena, you will also need the normal Athena/Glue/S3 read permissions for that query environment.

## Athena direction

Athena is not required to use Veridion.

It is the recommended first query layer because it gives:

- replay over historical decisions
- policy pack / version trend analysis
- blocker-category aggregation
- approval freshness trend analysis

without introducing a separate OLTP database as the first system of record.

Example external table shape:

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS veridion_decision_events (
  payload string
)
PARTITIONED BY (
  repo string,
  year string,
  month string,
  day string,
  verdict string
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://veridion-prod-events/veridion/events/';
```

The first production goal is simple:

- write canonical events to S3
- partition by repo/date/verdict
- query trends in Athena
- only add a database later if you need interactive product APIs or mutable workflow state

## Replay over S3-backed history

You do not need a new reader protocol to replay centralized history.

Recommended first path:

1. write canonical decision events to S3
2. sync a prefix or partition locally
3. run `decision_history` over the exported object tree

Example:

```bash
aws s3 sync "s3://veridion-prod-events/veridion/events/repo=acme_service-a/" /tmp/veridion-s3-history

python3 -m veridion.action.decision_history \
  --history-path /tmp/veridion-s3-history \
  --since 2026-05-01T00:00:00Z
```

Helper script:

- [examples/aws/replay-s3-history.sh](../examples/aws/replay-s3-history.sh)
- [examples/aws/run-history-service.sh](../examples/aws/run-history-service.sh)

## Athena query examples

If you want a generated starter pack instead of hand-writing SQL:

```bash
python3 -m veridion.action.athena_queries \
  --database analytics \
  --table veridion_decision_events \
  --s3-location s3://veridion-prod-events/veridion/events/ \
  --output-path /tmp/veridion-athena-queries.json
```

Reference helper:

- [examples/aws/build-athena-queries.sh](../examples/aws/build-athena-queries.sh)

Count verdicts by day:

```sql
SELECT
  day,
  json_extract_scalar(payload, '$.decision.verdict') AS verdict,
  COUNT(*) AS events
FROM veridion_decision_events
GROUP BY 1, 2
ORDER BY 1, 2;
```

Compare policy pack versions by repository:

```sql
SELECT
  repo,
  json_extract_scalar(payload, '$.policy.pack_id') AS pack_id,
  json_extract_scalar(payload, '$.policy.pack_version') AS pack_version,
  COUNT(*) AS events
FROM veridion_decision_events
GROUP BY 1, 2, 3
ORDER BY 1, 2, 3;
```

## Bedrock and LLMs

Bedrock is optional.

Veridion does not require an LLM to make release decisions.
The decision engine remains deterministic.
An LLM only rewrites structured facts into shorter operator-facing wording when configured.

So an AWS-based deployment can choose:

- S3 only
- S3 + Athena
- S3 + Athena + Bedrock

depending on how much of the optional AI and analytics surface the team wants.
