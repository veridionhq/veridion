"""GitHub approval satisfaction evaluation for Veridion approval roles."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from veridion.action.github_approvals import ApprovalMap, parse_approval_map
from veridion.action.github_comment import _github_request_with_headers, _next_link


@dataclass(frozen=True)
class ReviewRecord:
    reviewer: str
    state: str


@dataclass(frozen=True)
class ApprovalRoleState:
    role: str
    status: str
    approved_by: tuple[str, ...] = ()
    pending_users: tuple[str, ...] = ()
    pending_teams: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class ApprovalSatisfactionResult:
    status: str
    approvals_satisfied: bool
    satisfied_roles: tuple[str, ...]
    unsatisfied_roles: tuple[str, ...]
    role_states: tuple[ApprovalRoleState, ...]


@dataclass(frozen=True)
class ApprovalGateEvaluation:
    status: str
    allowed: bool


class GitHubApprovalStateError(RuntimeError):
    """Raised when approval-state evaluation fails."""

    pass


def evaluate_required_approval_state(
    *,
    repository: str,
    pull_request_number: int,
    github_token: str,
    required_approvals: tuple[str, ...],
    approval_map: ApprovalMap,
) -> ApprovalSatisfactionResult:
    """Evaluate whether mapped approval roles are currently satisfied on a PR."""

    if not required_approvals:
        return ApprovalSatisfactionResult(
            status="not_required",
            approvals_satisfied=True,
            satisfied_roles=(),
            unsatisfied_roles=(),
            role_states=(),
        )

    latest_reviews = _latest_review_states(
        _fetch_pull_request_reviews(
            repository=repository,
            pull_request_number=pull_request_number,
            github_token=github_token,
        )
    )
    owner = repository.split("/", maxsplit=1)[0]
    team_cache: dict[str, tuple[str, ...]] = {}
    role_states: list[ApprovalRoleState] = []

    for role in required_approvals:
        target = approval_map.roles.get(role)
        if target is None:
            role_states.append(
                ApprovalRoleState(
                    role=role,
                    status="unmapped",
                    note="no reviewer mapping is configured for this approval role",
                )
            )
            continue

        approved_users = [user for user in target.users if latest_reviews.get(user) == "APPROVED"]
        pending_users = [user for user in target.users if latest_reviews.get(user) != "APPROVED"]

        approved_team_members: list[str] = []
        pending_teams: list[str] = []
        for team in target.teams:
            members = team_cache.get(team)
            if members is None:
                members = _fetch_team_members(
                    repository_owner=owner,
                    team_slug=team,
                    github_token=github_token,
                )
                team_cache[team] = members
            team_approvers = [member for member in members if latest_reviews.get(member) == "APPROVED"]
            if team_approvers:
                approved_team_members.extend(team_approvers)
            else:
                pending_teams.append(team)

        approved_by = tuple(dict.fromkeys(approved_users + approved_team_members))
        if approved_by:
            role_states.append(
                ApprovalRoleState(
                    role=role,
                    status="satisfied",
                    approved_by=approved_by,
                    pending_users=tuple(pending_users),
                    pending_teams=tuple(pending_teams),
                )
            )
        else:
            role_states.append(
                ApprovalRoleState(
                    role=role,
                    status="pending",
                    pending_users=tuple(pending_users),
                    pending_teams=tuple(pending_teams),
                )
            )

    satisfied_roles = tuple(state.role for state in role_states if state.status == "satisfied")
    unsatisfied_roles = tuple(state.role for state in role_states if state.status != "satisfied")
    approvals_satisfied = not unsatisfied_roles

    if approvals_satisfied:
        status = "satisfied"
    elif any(state.status == "unmapped" for state in role_states):
        status = "unmapped"
    else:
        status = "pending"

    return ApprovalSatisfactionResult(
        status=status,
        approvals_satisfied=approvals_satisfied,
        satisfied_roles=satisfied_roles,
        unsatisfied_roles=unsatisfied_roles,
        role_states=tuple(role_states),
    )


def enrich_decision_contract(
    decision_contract: dict[str, object],
    result: ApprovalSatisfactionResult,
) -> dict[str, object]:
    """Attach approval satisfaction state to the machine-facing decision contract."""

    automation = decision_contract.setdefault("automation", {})
    if not isinstance(automation, dict):
        raise GitHubApprovalStateError("decision contract automation section must be an object")
    automation["approval_satisfaction_status"] = result.status
    automation["approvals_satisfied"] = result.approvals_satisfied
    automation["satisfied_approvals"] = list(result.satisfied_roles)
    automation["unsatisfied_approvals"] = list(result.unsatisfied_roles)
    automation["approval_state"] = [asdict(state) for state in result.role_states]
    return decision_contract


def evaluate_approval_gate(
    result: ApprovalSatisfactionResult,
    *,
    enforce: bool,
) -> ApprovalGateEvaluation:
    """Interpret approval satisfaction as a stable gate decision."""

    if not enforce:
        return ApprovalGateEvaluation(status="disabled", allowed=True)
    if result.status == "not_required":
        return ApprovalGateEvaluation(status="not_required", allowed=True)
    if result.approvals_satisfied:
        return ApprovalGateEvaluation(status="satisfied", allowed=True)
    if result.status == "unmapped":
        return ApprovalGateEvaluation(status="unmapped", allowed=False)
    return ApprovalGateEvaluation(status="blocked", allowed=False)


def enrich_decision_contract_with_approval_gate(
    decision_contract: dict[str, object],
    gate: ApprovalGateEvaluation,
) -> dict[str, object]:
    automation = decision_contract.setdefault("automation", {})
    if not isinstance(automation, dict):
        raise GitHubApprovalStateError("decision contract automation section must be an object")
    automation["approval_gate_status"] = gate.status
    automation["approval_gate_allowed"] = gate.allowed
    return decision_contract


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate GitHub approval satisfaction for Veridion approval roles")
    parser.add_argument("--repository", required=True, help="owner/repo")
    parser.add_argument("--pull-request-number", required=True, type=int, help="Pull request number")
    parser.add_argument("--github-token", required=True, help="GitHub token")
    parser.add_argument("--required-approvals-json", required=True, help="JSON array of required Veridion approval roles")
    parser.add_argument("--approval-map-path", required=True, help="Path to approval-map JSON")
    parser.add_argument("--decision-contract-path", help="Optional path to veridion-decision.json for in-place enrichment")
    parser.add_argument("--enforce-approvals", default="false", help="Whether unsatisfied approvals should fail the gate")
    args = parser.parse_args(argv)

    try:
        required_approvals = tuple(_parse_required_approvals_json(args.required_approvals_json))
        approval_map = parse_approval_map(json.loads(Path(args.approval_map_path).read_text()))
        result = evaluate_required_approval_state(
            repository=args.repository,
            pull_request_number=args.pull_request_number,
            github_token=args.github_token,
            required_approvals=required_approvals,
            approval_map=approval_map,
        )
        gate = evaluate_approval_gate(result, enforce=args.enforce_approvals.strip().lower() == "true")
        if args.decision_contract_path:
            contract_path = Path(args.decision_contract_path)
            contract = json.loads(contract_path.read_text())
            contract = enrich_decision_contract(contract, result)
            contract = enrich_decision_contract_with_approval_gate(contract, gate)
            contract_path.write_text(json.dumps(contract, indent=2) + "\n")
    except Exception as exc:
        raise SystemExit(str(exc))

    _write_github_outputs(result, gate)
    print(
        json.dumps(
            {
                "status": result.status,
                "approvals_satisfied": result.approvals_satisfied,
                "approval_gate_status": gate.status,
                "approval_gate_allowed": gate.allowed,
                "satisfied_roles": list(result.satisfied_roles),
                "unsatisfied_roles": list(result.unsatisfied_roles),
                "role_states": [asdict(state) for state in result.role_states],
            }
        )
    )
    return 0


def _fetch_pull_request_reviews(
    *,
    repository: str,
    pull_request_number: int,
    github_token: str,
) -> tuple[ReviewRecord, ...]:
    url = f"https://api.github.com/repos/{repository}/pulls/{pull_request_number}/reviews?per_page=100"
    reviews: list[ReviewRecord] = []

    while url:
        payload, headers = _github_request_with_headers(url=url, method="GET", github_token=github_token)
        if isinstance(payload, list):
            reviews.extend(_parse_review_records(payload))
        url = _next_link(headers.get("Link"))

    return tuple(reviews)


def _fetch_team_members(
    *,
    repository_owner: str,
    team_slug: str,
    github_token: str,
) -> tuple[str, ...]:
    url = f"https://api.github.com/orgs/{repository_owner}/teams/{team_slug}/members?per_page=100"
    members: list[str] = []

    while url:
        payload, headers = _github_request_with_headers(url=url, method="GET", github_token=github_token)
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict) and isinstance(item.get("login"), str):
                    members.append(item["login"])
        url = _next_link(headers.get("Link"))

    return tuple(dict.fromkeys(members))


def _parse_review_records(payload: list[object]) -> tuple[ReviewRecord, ...]:
    records: list[ReviewRecord] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        user = item.get("user")
        state = item.get("state")
        if not isinstance(user, dict) or not isinstance(user.get("login"), str) or not isinstance(state, str):
            continue
        records.append(ReviewRecord(reviewer=user["login"], state=state.upper()))
    return tuple(records)


def _latest_review_states(reviews: tuple[ReviewRecord, ...]) -> dict[str, str]:
    latest: dict[str, str] = {}
    for review in reviews:
        latest[review.reviewer] = review.state
    return latest


def _parse_required_approvals_json(text: str) -> tuple[str, ...]:
    payload = json.loads(text)
    if not isinstance(payload, list) or any(not isinstance(item, str) for item in payload):
        raise ValueError("required-approvals-json must be a JSON array of strings")
    return tuple(item.strip() for item in payload if item.strip())


def _write_github_outputs(result: ApprovalSatisfactionResult, gate: ApprovalGateEvaluation) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        return

    with Path(github_output).open("a", encoding="utf-8") as handle:
        handle.write(f"approval_satisfaction_status={result.status}\n")
        handle.write(f"approvals_satisfied={str(result.approvals_satisfied).lower()}\n")
        handle.write(f"approval_gate_status={gate.status}\n")
        handle.write(f"approval_gate_allowed={str(gate.allowed).lower()}\n")
        handle.write(f"satisfied_approvals_json={json.dumps(list(result.satisfied_roles))}\n")
        handle.write(f"unsatisfied_approvals_json={json.dumps(list(result.unsatisfied_roles))}\n")
        handle.write(f"approval_state_json={json.dumps([asdict(state) for state in result.role_states])}\n")


if __name__ == "__main__":
    raise SystemExit(main())
