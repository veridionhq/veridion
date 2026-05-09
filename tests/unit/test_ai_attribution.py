from veridion.attribution import detect_ai_attribution, parse_pull_request_metadata


def test_detect_ai_attribution_from_pr_and_commit_metadata() -> None:
    metadata = parse_pull_request_metadata(
        {
            "title": "feat: add release policy checks",
            "body": "Drafted with Cursor and reviewed by a human.",
            "labels": ["ai-assisted"],
            "commits": [
                {
                    "message": "feat: generated with Claude to add parser support",
                    "author_name": "Release Bot",
                    "author_email": "bot@example.com",
                    "co_authors": ["GitHub Copilot <copilot@github.com>"],
                },
                {
                    "message": "test: tighten fixtures",
                    "author_name": "Engineer",
                    "author_email": "eng@example.com",
                    "co_authors": [],
                },
            ],
        }
    )

    attribution = detect_ai_attribution(metadata)

    assert attribution.detected is True
    assert attribution.signal_count == 4
    assert attribution.ai_authored_commits == 1
    assert attribution.sources == ("commit_co_author", "commit_message", "pr_body", "pr_label")
    assert attribution.indicators == ("AI-assisted", "Claude", "Copilot", "Cursor")


def test_detect_ai_attribution_returns_empty_summary_without_metadata() -> None:
    attribution = detect_ai_attribution(None)

    assert attribution.detected is False
    assert attribution.signal_count == 0
    assert attribution.ai_authored_commits == 0
    assert attribution.sources == ()
    assert attribution.indicators == ()
