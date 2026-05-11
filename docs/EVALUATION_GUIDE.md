# Evaluation Guide

This guide is for engineers, platform teams, and design partners evaluating Veridion as a product rather than as a codebase.

## What Veridion Should Prove

Veridion is useful if it can answer one question better than existing tooling:

**Should this change ship?**

That means an evaluation should focus on:

- whether Veridion isolates introduced risk from legacy noise
- whether it understands the change surface and blast radius
- whether the policy and approval requirements feel credible
- whether the recommended next steps are actionable
- whether exceptions and accepted risk stay visible without creating chaos

## What To Test

Use at least four pull request scenarios:

1. Low-risk change

- docs-only or harmless application code cleanup
- expected result: `GO`

2. Real but non-blocking change

- one or two meaningful findings, or moderate operational context
- expected result: `CONDITIONAL GO`

3. Clearly unsafe change

- high-severity or critical introduced risk
- public exposure, risky dependency changes, or dangerous infra changes
- expected result: `NO GO`

4. Accepted-risk change

- known issue with an explicit temporary suppression
- expected result: not a pristine `GO`
- accepted risk should remain visible in score, reasons, and comment output

## What Good Output Looks Like

A strong Veridion comment should:

- explain the decision in a few seconds
- make the primary drivers obvious
- separate direct blockers from contextual amplifiers
- show required approvals clearly
- prescribe next steps, not just surface risk

Red flags:

- scanner noise dominates the decision
- legacy issues are mixed with introduced issues
- accepted risk disappears completely
- required actions are vague or repetitive
- low-risk changes are blocked without a clear reason

## Current Proven Scenarios

The current MVP has already been validated in an external canary repository with:

- a docs-only `GO`
- a risk-based `CONDITIONAL GO`
- a high-risk dependency and infra `NO GO`
- an accepted-risk `CONDITIONAL GO` with explicit suppression visibility

This is enough to evaluate the current wedge honestly.

## Questions To Ask During Evaluation

- Would a developer trust this comment in a real PR?
- Would a reviewer know what to do next?
- Would platform or security teams agree with the approval requirements?
- Does the decision feel too harsh, too soft, or appropriately conservative?
- Is the setup simple enough that a team would actually install it?

## What Veridion Is Not Trying To Be Yet

Veridion is not yet a full deployment control plane.

It is currently:

- a release decision engine
- a portable policy and context layer
- a GitHub Action wedge

It is not yet:

- a broad runtime enforcement system
- a full service graph
- a historical incident intelligence platform
- a universal self-serve enterprise product

## What To Share Back

The most valuable feedback is concrete:

- screenshots of decisions that felt wrong
- outputs that felt noisy or incomplete
- approval requirements that were missing or excessive
- operational context that should have been inferred but was not
- exception flows that felt too easy or too rigid

That is the fastest path to improving decision trust.
