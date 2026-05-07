"""Normalization interfaces for external scanner inputs."""

from veridion.normalize.grype import normalize_grype_report
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.normalize.semgrep import normalize_semgrep_report
from veridion.normalize.syft import normalize_syft_report
from veridion.normalize.trivy import normalize_trivy_report

__all__ = [
    "NormalizedFinding",
    "NormalizedLocation",
    "normalize_grype_report",
    "normalize_report",
    "normalize_semgrep_report",
    "normalize_syft_report",
    "normalize_trivy_report",
]


def normalize_report(tool_name: str, report: dict[str, object]) -> list[NormalizedFinding]:
    """Dispatch scanner normalization by tool name."""

    normalized_tool = tool_name.strip().lower()
    if normalized_tool == "trivy":
        return normalize_trivy_report(report)
    if normalized_tool == "grype":
        return normalize_grype_report(report)
    if normalized_tool == "semgrep":
        return normalize_semgrep_report(report)
    if normalized_tool == "syft":
        return normalize_syft_report(report)
    raise ValueError(f"unsupported normalization tool: {tool_name}")
