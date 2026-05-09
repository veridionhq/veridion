"""AI-attribution primitives for pull request metadata."""

from veridion.attribution.ai import (
    AiAttribution,
    CommitMetadata,
    PullRequestMetadata,
    detect_ai_attribution,
    parse_pull_request_metadata,
)

__all__ = [
    "AiAttribution",
    "CommitMetadata",
    "PullRequestMetadata",
    "detect_ai_attribution",
    "parse_pull_request_metadata",
]
