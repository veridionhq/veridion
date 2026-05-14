import io

import pytest

from veridion.adapters import gitlab_note


def test_validate_gitlab_api_url_requires_https_api_root() -> None:
    with pytest.raises(gitlab_note.GitLabNoteError, match="must use https"):
        gitlab_note._validate_gitlab_api_url("http://gitlab.example.com/api/v4")

    with pytest.raises(gitlab_note.GitLabNoteError, match="ending in /api/v4"):
        gitlab_note._validate_gitlab_api_url("https://gitlab.example.com")


def test_parse_note_records_extracts_gitlab_notes() -> None:
    notes = gitlab_note._parse_note_records(
        [
            {
                "id": 7,
                "body": "<!-- veridion:rdi:start -->\nbody\n<!-- veridion:rdi:end -->",
                "author": {"username": "gitlab-bot"},
            }
        ]
    )

    assert notes[0].comment_id == 7
    assert notes[0].author_login == "gitlab-bot"


def test_upsert_merge_request_note_updates_existing_note(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gitlab_note,
        "_fetch_merge_request_notes",
        lambda **kwargs: [
            __import__("veridion.report", fromlist=["CommentRecord"]).CommentRecord(
                comment_id=9,
                author_login="gitlab-bot",
                body="<!-- veridion:rdi:start -->\nold\n<!-- veridion:rdi:end -->",
            )
        ],
    )
    monkeypatch.setattr(
        gitlab_note,
        "_update_merge_request_note",
        lambda **kwargs: {"id": 9, "body": kwargs["body"]},
    )

    result = gitlab_note.upsert_merge_request_note(
        gitlab_api_url="https://gitlab.example.com/api/v4",
        project_id="123",
        merge_request_iid=7,
        gitlab_token="token",
        body="<!-- veridion:rdi:start -->\nnew\n<!-- veridion:rdi:end -->",
    )

    assert result.note_id == 9
    assert result.mode == "updated"


def test_gitlab_request_wraps_http_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b'{"message":"rate limit exceeded"}'

    def fail(req):
        raise __import__("urllib.error").error.HTTPError(
            req.full_url,
            429,
            "Too Many Requests",
            hdrs={},
            fp=io.BytesIO(payload),
        )

    monkeypatch.setattr(gitlab_note.request, "urlopen", fail)

    with pytest.raises(gitlab_note.GitLabNoteError, match="rate limit exceeded"):
        gitlab_note._gitlab_request(
            url="https://gitlab.example.com/api/v4/projects/1/merge_requests/2/notes",
            method="GET",
            gitlab_token="token",
        )
