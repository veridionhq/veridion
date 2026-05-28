# Evaluation Checklist

Use this during design-partner trials or internal product reviews.

## Setup

- External install completed without custom plumbing
- Bootstrap generated repo-local policy and suppression files
- Workflow ran successfully in a real pull request

## Decision Quality

- Low-risk PR produced a credible `GO`
- Medium dependency-risk PR produced a credible `CONDITIONAL GO`
- Critical introduced dependency-risk PR produced a credible `NO GO`
- Accepted-risk PR remained visible and did not read as pristine

## Output Quality

- Primary drivers were easy to scan
- Required security review felt justified when dependency risk was introduced
- Required next steps were actionable
- Contextual risk did not overwhelm the dependency-risk decision

## Policy Quality

- Policy defaults were usable without deep tuning
- Dependency-risk decisions were neither too weak nor too noisy
- Decisions felt rule-driven rather than like an unexplained scoring model

## Operational Trust

- Introduced dependency risk was clearly separated from pre-existing noise
- Baseline quality and attribution confidence were clear
- Accepted-risk exceptions stayed auditable and used an explicit reason type
- Nothing important disappeared silently

## Follow-Up Questions

- What felt too harsh?
- What felt too soft?
- What important context was missing?
- Which recommendations were actually useful?
- Would the team keep this installed?
