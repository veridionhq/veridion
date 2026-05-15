from veridion.action.operational_context_builder import _has_section_inputs, _resolve_metadata_payload


def test_resolve_metadata_payload_prefers_prebuilt_metadata(monkeypatch) -> None:
    monkeypatch.setattr(
        "veridion.action.operational_context_builder.load_json_file",
        lambda path, label: {"title": "prebuilt"} if label == "metadata" else {"pull_request": {"title": "event"}},
    )

    payload = _resolve_metadata_payload(
        metadata_path="metadata.json",
        event_path="event.json",
        base_ref="main",
        head_ref="HEAD",
    )

    assert payload == {"title": "prebuilt"}


def test_resolve_metadata_payload_builds_from_event_and_commits(monkeypatch) -> None:
    monkeypatch.setattr(
        "veridion.action.operational_context_builder.load_json_file",
        lambda path, label: {
            "pull_request": {
                "title": "feat: tighten release policy checks",
                "body": "Prepared with Cursor.",
                "labels": [{"name": "ai-assisted"}],
            }
        },
    )
    monkeypatch.setattr(
        "veridion.action.operational_context_builder.collect_commit_metadata",
        lambda base_ref, head_ref="HEAD": [
            {
                "message": "feat: generated with Claude",
                "author_name": "Release Bot",
                "author_email": "bot@example.com",
                "co_authors": ["GitHub Copilot <copilot@github.com>"],
            }
        ],
    )

    payload = _resolve_metadata_payload(
        metadata_path=None,
        event_path="event.json",
        base_ref="main",
        head_ref="HEAD",
    )

    assert payload == {
        "title": "feat: tighten release policy checks",
        "body": "Prepared with Cursor.",
        "labels": ["ai-assisted"],
        "commits": [
            {
                "message": "feat: generated with Claude",
                "author_name": "Release Bot",
                "author_email": "bot@example.com",
                "co_authors": ["GitHub Copilot <copilot@github.com>"],
            }
        ],
    }


def test_resolve_metadata_payload_returns_empty_without_inputs() -> None:
    payload = _resolve_metadata_payload(
        metadata_path=None,
        event_path=None,
        base_ref=None,
        head_ref="HEAD",
    )

    assert payload == {}


def test_has_section_inputs_detects_non_github_section_mode() -> None:
    class _Args:
        historical_path = "historical.json"
        runtime_path = None
        ownership_path = None
        trust_baseline_path = None
        trust_memory_path = None
        trust_profile_metadata_path = None

    assert _has_section_inputs(_Args()) is True
