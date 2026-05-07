from veridion.action import github_comment


def test_upsert_pr_comment_creates_when_no_existing_veridion_comment(monkeypatch) -> None:
    calls: list[tuple[str, str, object | None]] = []

    def fake_github_request(*, url: str, method: str, github_token: str, body=None):
        calls.append((method, url, body))
        if method == "POST":
            return {"id": 42, "body": body["body"]}
        raise AssertionError(f"unexpected method {method}")

    def fake_github_request_with_headers(*, url: str, method: str, github_token: str, body=None):
        calls.append((method, url, body))
        if method == "GET":
            return (
                [
                    {
                        "id": 1,
                        "body": "human comment",
                        "user": {"login": "alice"},
                    }
                ],
                {},
            )
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(github_comment, "_github_request", fake_github_request)
    monkeypatch.setattr(github_comment, "_github_request_with_headers", fake_github_request_with_headers)

    result = github_comment.upsert_pr_comment(
        repository="acme/veridion",
        pull_request_number=7,
        github_token="token",
        body="<!-- veridion:rdi:start -->\nbody\n<!-- veridion:rdi:end -->\n",
    )

    assert result.comment_id == 42
    assert result.mode == "created"
    assert calls[0][0] == "GET"
    assert calls[1][0] == "POST"


def test_upsert_pr_comment_updates_existing_veridion_comment(monkeypatch) -> None:
    calls: list[tuple[str, str, object | None]] = []

    def fake_github_request(*, url: str, method: str, github_token: str, body=None):
        calls.append((method, url, body))
        if method == "PATCH":
            return {"id": 11, "body": body["body"]}
        raise AssertionError(f"unexpected method {method}")

    def fake_github_request_with_headers(*, url: str, method: str, github_token: str, body=None):
        calls.append((method, url, body))
        if method == "GET":
            return (
                [
                    {
                        "id": 11,
                        "body": "<!-- veridion:rdi:start -->\nold\n<!-- veridion:rdi:end -->\n",
                        "user": {"login": "github-actions[bot]"},
                    }
                ],
                {},
            )
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(github_comment, "_github_request", fake_github_request)
    monkeypatch.setattr(github_comment, "_github_request_with_headers", fake_github_request_with_headers)

    result = github_comment.upsert_pr_comment(
        repository="acme/veridion",
        pull_request_number=7,
        github_token="token",
        body="<!-- veridion:rdi:start -->\nnew\n<!-- veridion:rdi:end -->\n",
    )

    assert result.comment_id == 11
    assert result.mode == "updated"
    assert calls[0][0] == "GET"
    assert calls[1][0] == "PATCH"


def test_fetch_issue_comments_follows_pagination(monkeypatch) -> None:
    calls: list[str] = []

    def fake_request_with_headers(*, url: str, method: str, github_token: str, body=None):
        calls.append(url)
        if "page=2" in url:
            return (
                [
                    {
                        "id": 2,
                        "body": "second page",
                        "user": {"login": "github-actions[bot]"},
                    }
                ],
                {},
            )
        return (
            [
                {
                    "id": 1,
                    "body": "first page",
                    "user": {"login": "alice"},
                }
            ],
            {"Link": '<https://api.github.com/repos/acme/veridion/issues/7/comments?per_page=100&page=2>; rel="next"'},
        )

    monkeypatch.setattr(github_comment, "_github_request_with_headers", fake_request_with_headers)

    comments = github_comment._fetch_issue_comments(  # type: ignore[attr-defined]
        repository="acme/veridion",
        issue_number=7,
        github_token="token",
    )

    assert tuple(comment.comment_id for comment in comments) == (1, 2)
    assert len(calls) == 2
