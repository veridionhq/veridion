import pytest

from veridion.adapters.gitlab_merge_request_metadata import build_merge_request_metadata, collect_commit_metadata


def test_build_merge_request_metadata_combines_event_and_commit_context() -> None:
    metadata = build_merge_request_metadata(
        event_payload={
            "object_attributes": {
                "title": "feat: tighten release policy checks",
                "description": "Prepared with Cursor.",
                "labels": ["ai-assisted", "release"],
            }
        },
        commits=[
            {
                "message": "feat: generated with Claude",
                "author_name": "Release Bot",
                "author_email": "bot@example.com",
                "co_authors": ["GitHub Copilot <copilot@github.com>"],
            }
        ],
    )

    assert metadata == {
        "title": "feat: tighten release policy checks",
        "body": "Prepared with Cursor.",
        "labels": ["ai-assisted", "release"],
        "commits": [
            {
                "message": "feat: generated with Claude",
                "author_name": "Release Bot",
                "author_email": "bot@example.com",
                "co_authors": ["GitHub Copilot <copilot@github.com>"],
            }
        ],
    }


def test_build_merge_request_metadata_accepts_comma_delimited_labels() -> None:
    metadata = build_merge_request_metadata(
        event_payload={
            "object_attributes": {
                "title": "feat: ship",
                "description": "Body",
                "labels": "backend, release , ai-assisted",
            }
        }
    )

    assert metadata["labels"] == ["backend", "release", "ai-assisted"]


def test_collect_commit_metadata_wraps_git_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args, **kwargs):
        raise __import__("subprocess").CalledProcessError(128, ["git", "log"])

    monkeypatch.setattr("veridion.adapters.gitlab_merge_request_metadata.subprocess.run", fail)

    with pytest.raises(RuntimeError, match=r"git log failed for range 'origin/main\.\.HEAD'"):
        collect_commit_metadata("main")
