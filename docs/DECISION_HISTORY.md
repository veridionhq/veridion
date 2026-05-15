# Decision History

Veridion decision events are useful only if they can be queried over time.

The action can now:

- write `veridion-decision-event.json` for the current run
- append the same event to an NDJSON history log
- analyze that history for verdict, approval-gate, and policy-pack trends

## Build history over time

When you configure:

- `decision-event-path`
- `decision-history-path`

each run emits one current event and optionally appends it to the history log.

## Analyze a history log

```bash
python3 -m veridion.action.decision_history \
  --history-path veridion-decision-history.ndjson \
  --output-path decision-history-analytics.json
```

The analytics output includes:

- verdict counts
- gate-status counts
- approval-gate counts
- top blocking categories
- policy pack / version breakdown
- stale approval event counts

## Filter for rollout analysis

Example:

```bash
python3 -m veridion.action.decision_history \
  --history-path veridion-decision-history.ndjson \
  --repository acme/service-a \
  --policy-pack-id platform-team
```

This is the current local replay surface for pack-version rollout analysis before centralized history storage exists.
