"""Human-facing output renderers for release decisions."""

from veridion.report.pr_comment import (
    COMMENT_MARKER_END,
    COMMENT_MARKER_START,
    RenderedComment,
    render_pr_comment,
    render_pr_comment_result,
    wrap_pr_comment,
)
from veridion.report.pr_lifecycle import CommentRecord, select_comment_upsert
from veridion.report.threats import ThreatExplanation, explain_introduced_threats, render_threat_line

__all__ = [
    "COMMENT_MARKER_END",
    "COMMENT_MARKER_START",
    "CommentRecord",
    "RenderedComment",
    "ThreatExplanation",
    "explain_introduced_threats",
    "render_pr_comment",
    "render_pr_comment_result",
    "render_threat_line",
    "select_comment_upsert",
    "wrap_pr_comment",
]
