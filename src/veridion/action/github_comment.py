"""GitHub PR comment upsert bridge for Veridion action output."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

from veridion.report import CommentRecord, select_comment_upsert


@dataclass(frozen=True)
class CommentUpsertResult:
    """Outcome of a PR comment create-or-update operation."""

    comment_id: int
    mode: str
    body: str


class GitHubCommentError(RuntimeError):
    """Raised when GitHub comment operations fail or inputs are invalid."""

    pass


def upsert_pr_comment(
    *,
    repository: str,
    pull_request_number: int,
    github_token: str,
    body: str,
) -> CommentUpsertResult:
    """Fetch existing PR comments and update or create the Veridion comment."""

    comments = _fetch_issue_comments(
        repository=repository,
        issue_number=pull_request_number,
        github_token=github_token,
    )
    comment_id = select_comment_upsert(comments)

    if comment_id is None:
        created = _create_issue_comment(
            repository=repository,
            issue_number=pull_request_number,
            github_token=github_token,
            body=body,
        )
        return CommentUpsertResult(comment_id=created["id"], mode="created", body=created["body"])

    updated = _update_issue_comment(
        repository=repository,
        comment_id=comment_id,
        github_token=github_token,
        body=body,
    )
    return CommentUpsertResult(comment_id=updated["id"], mode="updated", body=updated["body"])


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for PR comment upsert."""

    parser = argparse.ArgumentParser(description="Upsert Veridion PR comment through GitHub API")
    parser.add_argument("--repository", required=True, help="owner/repo")
    parser.add_argument("--pull-request-number", required=True, type=int, help="Pull request number")
    parser.add_argument("--github-token", required=True, help="GitHub token")
    parser.add_argument("--comment-path", required=True, help="Path to rendered PR comment markdown")
    args = parser.parse_args(argv)
    _validate_comment_inputs(
        repository=args.repository,
        pull_request_number=args.pull_request_number,
        github_token=args.github_token,
        comment_path=args.comment_path,
    )

    body = Path(args.comment_path).read_text()
    result = upsert_pr_comment(
        repository=args.repository,
        pull_request_number=args.pull_request_number,
        github_token=args.github_token,
        body=body,
    )
    _write_github_outputs(result)
    print(json.dumps({"comment_id": result.comment_id, "mode": result.mode}))
    return 0


def _fetch_issue_comments(*, repository: str, issue_number: int, github_token: str) -> list[CommentRecord]:
    url = f"https://api.github.com/repos/{repository}/issues/{issue_number}/comments?per_page=100"
    comments: list[CommentRecord] = []

    while url:
        payload, headers = _github_request_with_headers(url=url, method="GET", github_token=github_token)
        comments.extend(_parse_comment_records(payload))
        url = _next_link(headers.get("Link"))

    return comments


def _create_issue_comment(
    *,
    repository: str,
    issue_number: int,
    github_token: str,
    body: str,
) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repository}/issues/{issue_number}/comments"
    return _github_request(url=url, method="POST", github_token=github_token, body={"body": body})


def _update_issue_comment(
    *,
    repository: str,
    comment_id: int,
    github_token: str,
    body: str,
) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repository}/issues/comments/{comment_id}"
    return _github_request(url=url, method="PATCH", github_token=github_token, body={"body": body})


def _github_request(
    *,
    url: str,
    method: str,
    github_token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    payload, _ = _github_request_with_headers(
        url=url,
        method=method,
        github_token=github_token,
        body=body,
    )
    return payload


def _github_request_with_headers(
    *,
    url: str,
    method: str,
    github_token: str,
    body: dict[str, Any] | None = None,
) -> tuple[Any, dict[str, str]]:
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

    req = request.Request(url=url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req) as response:
            payload = response.read().decode("utf-8")
            response_headers = dict(response.headers.items())
        try:
            parsed = json.loads(payload) if payload else {}
        except json.JSONDecodeError as exc:
            raise GitHubCommentError(f"unexpected non-JSON response from {url}") from exc
        return parsed, response_headers
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8") if exc.fp else ""
        detail = _extract_error_message(payload) or exc.reason
        raise GitHubCommentError(f"GitHub API {method} {url} failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise GitHubCommentError(f"GitHub API {method} {url} failed: {exc.reason}") from exc


def _write_github_outputs(result: CommentUpsertResult) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        return

    with Path(github_output).open("a", encoding="utf-8") as handle:
        handle.write(f"comment_id={result.comment_id}\n")
        handle.write(f"comment_mode={result.mode}\n")


def _validate_comment_inputs(
    *,
    repository: str,
    pull_request_number: int,
    github_token: str,
    comment_path: str,
) -> None:
    if "/" not in repository or repository.startswith("/") or repository.endswith("/"):
        raise GitHubCommentError("repository must be in owner/repo format")
    if pull_request_number <= 0:
        raise GitHubCommentError("pull request number must be greater than zero")
    if not github_token.strip():
        raise GitHubCommentError("github token is required for PR comment upsert")
    if not Path(comment_path).exists():
        raise GitHubCommentError(f"comment path does not exist: {comment_path}")


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


def _parse_comment_records(payload: Any) -> list[CommentRecord]:
    if not isinstance(payload, list):
        return []

    return [
        CommentRecord(
            comment_id=item["id"],
            author_login=item["user"]["login"],
            body=item["body"],
        )
        for item in payload
        if isinstance(item, dict)
        and isinstance(item.get("id"), int)
        and isinstance(item.get("body"), str)
        and isinstance(item.get("user"), dict)
        and isinstance(item["user"].get("login"), str)
    ]


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None

    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        if not section.startswith("<") or ">" not in section:
            continue
        return section[1 : section.index(">")]

    return None


if __name__ == "__main__":
    raise SystemExit(main())
