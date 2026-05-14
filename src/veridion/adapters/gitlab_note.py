"""GitLab merge request note upsert bridge for Veridion comment output."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import quote, urlsplit, urlunsplit

from veridion.report import CommentRecord, select_comment_upsert


@dataclass(frozen=True)
class GitLabNoteUpsertResult:
    """Outcome of a merge-request note create-or-update operation."""

    note_id: int
    mode: str
    body: str


class GitLabNoteError(RuntimeError):
    """Raised when GitLab note operations fail or inputs are invalid."""

    pass


def upsert_merge_request_note(
    *,
    gitlab_api_url: str,
    project_id: str,
    merge_request_iid: int,
    gitlab_token: str,
    body: str,
) -> GitLabNoteUpsertResult:
    """Fetch existing MR notes and update or create the Veridion note."""

    api_root = _validate_gitlab_api_url(gitlab_api_url)
    validated_project_id = _validate_project_id(project_id)
    _validate_merge_request_iid(merge_request_iid)
    _validate_token(gitlab_token)

    notes = _fetch_merge_request_notes(
        api_root=api_root,
        project_id=validated_project_id,
        merge_request_iid=merge_request_iid,
        gitlab_token=gitlab_token,
    )
    note_id = select_comment_upsert(notes, bot_logins=("gitlab-bot", "veridion-bot"))

    if note_id is None:
        created = _create_merge_request_note(
            api_root=api_root,
            project_id=validated_project_id,
            merge_request_iid=merge_request_iid,
            gitlab_token=gitlab_token,
            body=body,
        )
        return GitLabNoteUpsertResult(note_id=created["id"], mode="created", body=created["body"])

    updated = _update_merge_request_note(
        api_root=api_root,
        project_id=validated_project_id,
        merge_request_iid=merge_request_iid,
        note_id=note_id,
        gitlab_token=gitlab_token,
        body=body,
    )
    return GitLabNoteUpsertResult(note_id=updated["id"], mode="updated", body=updated["body"])


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for GitLab merge-request note upsert."""

    parser = argparse.ArgumentParser(description="Upsert Veridion merge request note through the GitLab API")
    parser.add_argument("--gitlab-api-url", required=True, help="GitLab API root, e.g. https://gitlab.example.com/api/v4")
    parser.add_argument("--project-id", required=True, help="GitLab numeric project id or URL-encoded path")
    parser.add_argument("--merge-request-iid", required=True, type=int, help="Merge request IID")
    parser.add_argument("--gitlab-token", required=True, help="GitLab API token")
    parser.add_argument("--comment-path", required=True, help="Path to rendered Veridion markdown comment")
    args = parser.parse_args(argv)

    comment_path = Path(args.comment_path)
    if not comment_path.exists():
        raise GitLabNoteError(f"comment path does not exist: {args.comment_path}")

    result = upsert_merge_request_note(
        gitlab_api_url=args.gitlab_api_url,
        project_id=args.project_id,
        merge_request_iid=args.merge_request_iid,
        gitlab_token=args.gitlab_token,
        body=comment_path.read_text(),
    )
    print(json.dumps({"note_id": result.note_id, "mode": result.mode}))
    return 0


def _fetch_merge_request_notes(
    *,
    api_root: str,
    project_id: str,
    merge_request_iid: int,
    gitlab_token: str,
) -> list[CommentRecord]:
    notes: list[CommentRecord] = []
    page = 1

    while True:
        url = (
            f"{api_root}/projects/{quote(project_id, safe='')}/merge_requests/"
            f"{merge_request_iid}/notes?per_page=100&page={page}"
        )
        payload = _gitlab_request(url=url, method="GET", gitlab_token=gitlab_token)
        parsed = _parse_note_records(payload)
        notes.extend(parsed)
        if len(parsed) < 100:
            return notes
        page += 1


def _create_merge_request_note(
    *,
    api_root: str,
    project_id: str,
    merge_request_iid: int,
    gitlab_token: str,
    body: str,
) -> dict[str, Any]:
    url = f"{api_root}/projects/{quote(project_id, safe='')}/merge_requests/{merge_request_iid}/notes"
    return _gitlab_request(url=url, method="POST", gitlab_token=gitlab_token, body={"body": body})


def _update_merge_request_note(
    *,
    api_root: str,
    project_id: str,
    merge_request_iid: int,
    note_id: int,
    gitlab_token: str,
    body: str,
) -> dict[str, Any]:
    url = f"{api_root}/projects/{quote(project_id, safe='')}/merge_requests/{merge_request_iid}/notes/{note_id}"
    return _gitlab_request(url=url, method="PUT", gitlab_token=gitlab_token, body={"body": body})


def _gitlab_request(
    *,
    url: str,
    method: str,
    gitlab_token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    data = None
    headers = {
        "Accept": "application/json",
        "PRIVATE-TOKEN": gitlab_token,
        "User-Agent": "veridion-rdi",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(url=url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req) as response:
            payload = response.read().decode("utf-8")
        try:
            return json.loads(payload) if payload else {}
        except json.JSONDecodeError as exc:
            raise GitLabNoteError(f"unexpected non-JSON response from {url}") from exc
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8") if exc.fp else ""
        detail = _extract_error_message(payload) or exc.reason
        raise GitLabNoteError(f"GitLab API {method} {url} failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise GitLabNoteError(f"GitLab API {method} {url} failed: {exc.reason}") from exc


def _validate_gitlab_api_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme != "https":
        raise GitLabNoteError("gitlab-api-url must use https")
    if not parsed.netloc:
        raise GitLabNoteError("gitlab-api-url must include a hostname")
    if parsed.username or parsed.password:
        raise GitLabNoteError("gitlab-api-url must not contain embedded credentials")
    if parsed.fragment:
        raise GitLabNoteError("gitlab-api-url must not include a fragment")
    path = parsed.path.rstrip("/")
    if not path.endswith("/api/v4"):
        raise GitLabNoteError("gitlab-api-url must point at the GitLab API root ending in /api/v4")
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def _validate_project_id(project_id: str) -> str:
    normalized = project_id.strip()
    if not normalized:
        raise GitLabNoteError("project-id is required")
    return normalized


def _validate_merge_request_iid(value: int) -> None:
    if value <= 0:
        raise GitLabNoteError("merge-request-iid must be greater than zero")


def _validate_token(token: str) -> None:
    if not token.strip():
        raise GitLabNoteError("gitlab token is required for merge request note upsert")


def _extract_error_message(payload: str) -> str | None:
    if not payload:
        return None
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return payload.strip() or None

    if isinstance(parsed, dict):
        for key in ("message", "error"):
            value = parsed.get(key)
            if isinstance(value, str):
                return value
    return None


def _parse_note_records(payload: Any) -> list[CommentRecord]:
    if not isinstance(payload, list):
        return []

    return [
        CommentRecord(
            comment_id=item["id"],
            author_login=item["author"]["username"],
            body=item["body"],
        )
        for item in payload
        if isinstance(item, dict)
        and isinstance(item.get("id"), int)
        and isinstance(item.get("body"), str)
        and isinstance(item.get("author"), dict)
        and isinstance(item["author"].get("username"), str)
    ]


if __name__ == "__main__":
    raise SystemExit(main())
