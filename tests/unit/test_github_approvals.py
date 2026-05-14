from pathlib import Path

from veridion.action import github_approvals


def test_request_required_approvals_maps_roles_to_reviewers(monkeypatch) -> None:
    calls: list[tuple[str, object | None]] = []

    def fake_request(*, url: str, method: str, github_token: str, body=None):
        calls.append((method, body))
        return {}

    monkeypatch.setattr(github_approvals, "_github_request", fake_request)

    result = github_approvals.request_required_approvals(
        repository="acme/veridion",
        pull_request_number=7,
        github_token="token",
        required_approvals=("platform_owner", "security_owner"),
        approval_map=github_approvals.ApprovalMap(
            roles={
                "platform_owner": github_approvals.ReviewerTarget(teams=("platform-team",)),
                "security_owner": github_approvals.ReviewerTarget(users=("alice",)),
            }
        ),
    )

    assert result.status == "requested"
    assert result.requested_users == ("alice",)
    assert result.requested_teams == ("platform-team",)
    assert result.missing_roles == ()
    assert calls == [("POST", {"reviewers": ["alice"], "team_reviewers": ["platform-team"]})]


def test_request_required_approvals_tracks_missing_mappings(monkeypatch) -> None:
    monkeypatch.setattr(github_approvals, "_github_request", lambda **kwargs: {})

    result = github_approvals.request_required_approvals(
        repository="acme/veridion",
        pull_request_number=7,
        github_token="token",
        required_approvals=("platform_owner", "security_owner"),
        approval_map=github_approvals.ApprovalMap(
            roles={
                "platform_owner": github_approvals.ReviewerTarget(teams=("platform-team",)),
            }
        ),
    )

    assert result.status == "requested_with_missing_mappings"
    assert result.missing_roles == ("security_owner",)


def test_parse_approval_map_validates_schema() -> None:
    try:
        github_approvals.parse_approval_map({"schema_version": 2, "roles": {}})
    except ValueError as exc:
        assert "approval map schema_version must be 1" in str(exc)
    else:
        raise AssertionError("expected invalid schema to fail")
