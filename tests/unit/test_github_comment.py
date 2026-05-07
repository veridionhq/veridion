from veridion.action import github_comment


def test_upsert_pr_comment_creates_when_no_existing_veridion_comment(monkeypatch) -> None:
    calls: list[tuple[str, str, object | None]] = []

    def fake_github_request(*, url: str, method: str, github_token: str, body=None):
        calls.append((method, url, body))
        if method == "GET":
            return [
                {
                    "id": 1,
                    "body": "human comment",
                    "user": {"login": "alice"},
                }
            ]
        if method == "POST":
            return {"id": 42, "body": body["body"]}
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(github_comment, "_github_request", fake_github_request)

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
        if method == "GET":
            return [
                {
                    "id": 11,
                    "body": "<!-- veridion:rdi:start -->\nold\n<!-- veridion:rdi:end -->\n",
                    "user": {"login": "github-actions[bot]"},
                }
            ]
        if method == "PATCH":
            return {"id": 11, "body": body["body"]}
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(github_comment, "_github_request", fake_github_request)

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
