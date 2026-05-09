from veridion.action.metadata_builder import build_pr_metadata, parse_git_log_output
import pytest
from veridion.action.metadata_builder import collect_commit_metadata


def test_parse_git_log_output_extracts_commit_metadata_and_co_authors() -> None:
    raw = (
        "Release Bot\x1fb0t@example.com\x1ffeat: add parser support\n\n"
        "Co-authored-by: GitHub Copilot <copilot@github.com>\n"
        "Co-authored-by: Claude <claude@anthropic.com>\x1e"
        "Engineer\x1feng@example.com\x1ftest: tighten fixtures\x1e"
    )

    commits = parse_git_log_output(raw)

    assert commits == [
        {
            "message": "feat: add parser support\n\nCo-authored-by: GitHub Copilot <copilot@github.com>\nCo-authored-by: Claude <claude@anthropic.com>",
            "author_name": "Release Bot",
            "author_email": "b0t@example.com",
            "co_authors": [
                "GitHub Copilot <copilot@github.com>",
                "Claude <claude@anthropic.com>",
            ],
        },
        {
            "message": "test: tighten fixtures",
            "author_name": "Engineer",
            "author_email": "eng@example.com",
            "co_authors": [],
        },
    ]


def test_build_pr_metadata_combines_event_and_commit_context() -> None:
    metadata = build_pr_metadata(
        event_payload={
            "pull_request": {
                "title": "feat: tighten release policy checks",
                "body": "Prepared with Cursor.",
                "labels": [{"name": "ai-assisted"}, {"name": "release"}],
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


def test_collect_commit_metadata_wraps_git_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args, **kwargs):
        raise __import__("subprocess").CalledProcessError(128, ["git", "log"])

    monkeypatch.setattr("veridion.action.metadata_builder.subprocess.run", fail)

    with pytest.raises(RuntimeError, match=r"git log failed for range 'origin/main\.\.HEAD'"):
        collect_commit_metadata("main")
