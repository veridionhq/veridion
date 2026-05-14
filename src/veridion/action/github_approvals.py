"""GitHub PR reviewer request bridge for Veridion approval roles."""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

_GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class ReviewerTarget:
    users: tuple[str, ...] = ()
    teams: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApprovalMap:
    roles: dict[str, ReviewerTarget]


@dataclass(frozen=True)
class ApprovalRequestResult:
    requested_users: tuple[str, ...]
    requested_teams: tuple[str, ...]
    missing_roles: tuple[str, ...]
    status: str


class GitHubApprovalError(RuntimeError):
    """Raised when approval-routing operations fail or inputs are invalid."""

    pass


def request_required_approvals(
    *,
    repository: str,
    pull_request_number: int,
    github_token: str,
    required_approvals: tuple[str, ...],
    approval_map: ApprovalMap,
) -> ApprovalRequestResult:
    """Request PR reviewers mapped from Veridion approval roles."""

    requested_users: list[str] = []
    requested_teams: list[str] = []
    missing_roles: list[str] = []

    for role in required_approvals:
        target = approval_map.roles.get(role)
        if target is None:
            missing_roles.append(role)
            continue
        requested_users.extend(target.users)
        requested_teams.extend(target.teams)

    users = tuple(dict.fromkeys(requested_users))
    teams = tuple(dict.fromkeys(requested_teams))
    missing = tuple(dict.fromkeys(missing_roles))

    if users or teams:
        _request_reviewers(
            repository=repository,
            pull_request_number=pull_request_number,
            github_token=github_token,
            users=users,
            teams=teams,
        )
        status = "requested_with_missing_mappings" if missing else "requested"
    else:
        status = "missing_mappings" if missing else "no_reviewers_required"

    return ApprovalRequestResult(
        requested_users=users,
        requested_teams=teams,
        missing_roles=missing,
        status=status,
    )


def parse_approval_map(payload: dict[str, object]) -> ApprovalMap:
    """Parse role-to-reviewer mapping JSON."""

    if not payload:
        return ApprovalMap(roles={})

    if payload.get("schema_version") != 1:
        raise ValueError("approval map schema_version must be 1")

    raw_roles = payload.get("roles")
    if not isinstance(raw_roles, dict):
        raise ValueError("approval map roles must be an object")

    roles: dict[str, ReviewerTarget] = {}
    for role, raw_target in raw_roles.items():
        if not isinstance(role, str) or not role.strip():
            raise ValueError("approval map role keys must be non-empty strings")
        if not isinstance(raw_target, dict):
            raise ValueError(f"approval map role target must be an object: {role}")
        users = _string_list(raw_target.get("users"))
        teams = _string_list(raw_target.get("teams"))
        if not users and not teams:
            raise ValueError(f"approval map role must define users or teams: {role}")
        roles[role.strip()] = ReviewerTarget(users=users, teams=teams)

    return ApprovalMap(roles=roles)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Request GitHub PR reviewers from Veridion approval roles")
    parser.add_argument("--repository", required=True, help="owner/repo")
    parser.add_argument("--pull-request-number", required=True, type=int, help="Pull request number")
    parser.add_argument("--github-token", required=True, help="GitHub token")
    parser.add_argument("--required-approvals-json", required=True, help="JSON array of required Veridion approval roles")
    parser.add_argument("--approval-map-path", required=True, help="Path to approval-map JSON")
    args = parser.parse_args(argv)

    try:
        required_approvals = tuple(_parse_required_approvals_json(args.required_approvals_json))
        approval_map = parse_approval_map(json.loads(Path(args.approval_map_path).read_text()))
        result = request_required_approvals(
            repository=args.repository,
            pull_request_number=args.pull_request_number,
            github_token=args.github_token,
            required_approvals=required_approvals,
            approval_map=approval_map,
        )
    except Exception as exc:
        raise SystemExit(str(exc))

    _write_github_outputs(result)
    print(
        json.dumps(
            {
                "status": result.status,
                "requested_users": list(result.requested_users),
                "requested_teams": list(result.requested_teams),
                "missing_roles": list(result.missing_roles),
            }
        )
    )
    return 0


def _request_reviewers(
    *,
    repository: str,
    pull_request_number: int,
    github_token: str,
    users: tuple[str, ...],
    teams: tuple[str, ...],
) -> dict[str, Any]:
    url = _build_requested_reviewers_url(repository, pull_request_number)
    return _github_request(
        url=url,
        method="POST",
        github_token=github_token,
        body={"reviewers": list(users), "team_reviewers": list(teams)},
    )


def _github_request(
    *,
    url: str,
    method: str,
    github_token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "veridion-rdi",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    # URL is constrained to the GitHub API host by _build_requested_reviewers_url().
    req = request.Request(url=url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req) as response:
            payload = response.read().decode("utf-8")
        return json.loads(payload) if payload else {}
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8") if exc.fp else ""
        detail = _extract_error_message(payload) or exc.reason
        raise GitHubApprovalError(f"GitHub API {method} {url} failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise GitHubApprovalError(f"GitHub API {method} {url} failed: {exc.reason}") from exc


def _build_requested_reviewers_url(repository: str, pull_request_number: int) -> str:
    normalized_repository = repository.strip()
    if not _GITHUB_REPOSITORY_RE.fullmatch(normalized_repository):
        raise GitHubApprovalError("repository must be in owner/repo format")
    if pull_request_number <= 0:
        raise GitHubApprovalError("pull request number must be positive")
    return f"https://api.github.com/repos/{normalized_repository}/pulls/{pull_request_number}/requested_reviewers"


def _parse_required_approvals_json(text: str) -> tuple[str, ...]:
    payload = json.loads(text)
    if not isinstance(payload, list) or any(not isinstance(item, str) for item in payload):
        raise ValueError("required-approvals-json must be a JSON array of strings")
    return tuple(item.strip() for item in payload if item.strip())


def _string_list(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("approval map users/teams must be arrays of strings")
    return tuple(item.strip() for item in value if item.strip())


def _extract_error_message(payload: str) -> str | None:
    if not payload:
        return None
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return payload.strip() or None

    if isinstance(parsed, dict):
        message = parsed.get("message")
        if isinstance(message, str):
            return message
    return None


def _write_github_outputs(result: ApprovalRequestResult) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        return

    with Path(github_output).open("a", encoding="utf-8") as handle:
        handle.write(f"approval_request_status={result.status}\n")
        handle.write(f"requested_reviewers_json={json.dumps({'users': list(result.requested_users), 'teams': list(result.requested_teams)})}\n")
        handle.write(f"missing_approval_mappings_json={json.dumps(list(result.missing_roles))}\n")


if __name__ == "__main__":
    raise SystemExit(main())
