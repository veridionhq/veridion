from urllib import error

import pytest

from veridion.action import github_comment


def test_validate_comment_inputs_rejects_invalid_repository(tmp_path) -> None:
    comment_path = tmp_path / "comment.md"
    comment_path.write_text("body")

    with pytest.raises(github_comment.GitHubCommentError, match="owner/repo"):
        github_comment._validate_comment_inputs(  # type: ignore[attr-defined]
            repository="invalid",
            pull_request_number=1,
            github_token="token",
            comment_path=str(comment_path),
        )


def test_github_request_wraps_http_errors(monkeypatch) -> None:
    class FakeHttpError(error.HTTPError):
        def __init__(self):
            super().__init__(
                url="https://api.github.com/test",
                code=403,
                msg="Forbidden",
                hdrs=None,
                fp=None,
            )

        def read(self):
            return b'{"message":"rate limit exceeded"}'

    def fake_urlopen(req):
        raise FakeHttpError()

    monkeypatch.setattr(github_comment.request, "urlopen", fake_urlopen)

    with pytest.raises(github_comment.GitHubCommentError, match="rate limit exceeded"):
        github_comment._github_request(  # type: ignore[attr-defined]
            url="https://api.github.com/test",
            method="GET",
            github_token="token",
        )


def test_github_request_wraps_url_errors(monkeypatch) -> None:
    def fake_urlopen(req):
        raise error.URLError("network unavailable")

    monkeypatch.setattr(github_comment.request, "urlopen", fake_urlopen)

    with pytest.raises(github_comment.GitHubCommentError, match="network unavailable"):
        github_comment._github_request(  # type: ignore[attr-defined]
            url="https://api.github.com/test",
            method="GET",
            github_token="token",
        )
