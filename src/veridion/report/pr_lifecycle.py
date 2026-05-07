"""PR comment lifecycle helpers for create-or-update behavior."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.report.pr_comment import COMMENT_MARKER_END, COMMENT_MARKER_START


@dataclass(frozen=True)
class CommentRecord:
    """Minimal representation of an existing PR comment."""

    comment_id: int
    author_login: str
    body: str


def select_comment_upsert(
    existing_comments: list[CommentRecord],
    *,
    bot_logins: tuple[str, ...] = ("github-actions[bot]", "veridion[bot]"),
) -> int | None:
    """Return the comment id to update, or None when a new comment should be created."""

    matching = [
        comment
        for comment in existing_comments
        if comment.author_login in bot_logins and _is_veridion_comment(comment.body)
    ]
    if not matching:
        return None
    return matching[-1].comment_id


def _is_veridion_comment(body: str) -> bool:
    return COMMENT_MARKER_START in body and COMMENT_MARKER_END in body
