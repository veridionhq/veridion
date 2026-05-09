"""GitHub Action runner for Release Decision Intelligence."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from veridion.analysis import AnalysisBundle, build_analysis_bundle
from veridion.attribution import parse_pull_request_metadata
from veridion.context import parse_historical_signals, parse_ownership_signals, parse_runtime_signals, parse_trust_baseline
from veridion.normalize import NormalizedFinding, normalize_report
from veridion.policy import PolicyDecision, PolicyConfig, evaluate_release, parse_policy_yaml
from veridion.report import render_pr_comment
from veridion.change_context import parse_unified_diff
from veridion.util import plain


@dataclass(frozen=True)
class ActionResult:
    """End-to-end action execution result."""

    bundle: AnalysisBundle
    decision: PolicyDecision
    comment_markdown: str
    comment_identifier: str = "veridion:rdi"

    def to_dict(self) -> dict[str, object]:
        """Convert the result to plain Python objects."""

        return {
            "analysis": self.bundle.to_dict(),
            "decision": plain(asdict(self.decision)),
            "comment_markdown": self.comment_markdown,
            "comment_identifier": self.comment_identifier,
        }


def run_action(
    *,
    diff_text: str,
    current_reports: dict[str, str],
    baseline_reports: dict[str, str] | None = None,
    policy_text: str | None = None,
    metadata_text: str | None = None,
) -> ActionResult:
    """Run the full RDI pipeline from file-backed action inputs."""

    current_findings = _load_findings(current_reports)
    baseline_findings = _load_findings(baseline_reports or {})
    change_context = parse_unified_diff(diff_text)
    policy = parse_policy_yaml(policy_text) if policy_text else PolicyConfig()
    parsed_metadata = json.loads(metadata_text) if metadata_text else {}
    metadata = parse_pull_request_metadata(parsed_metadata) if metadata_text else None
    historical_signals = parse_historical_signals(parsed_metadata) if metadata_text else None
    runtime_signals = parse_runtime_signals(parsed_metadata) if metadata_text else None
    ownership_signals = parse_ownership_signals(parsed_metadata) if metadata_text else None
    trust_baseline = parse_trust_baseline(parsed_metadata) if metadata_text else None

    bundle = build_analysis_bundle(
        current_findings=current_findings,
        baseline_findings=baseline_findings,
        change_context=change_context,
        metadata=metadata,
        historical_signals=historical_signals,
        runtime_signals=runtime_signals,
        ownership_signals=ownership_signals,
        trust_baseline=trust_baseline,
    )
    decision = evaluate_release(bundle, policy)
    comment_markdown = render_pr_comment(bundle, decision)

    return ActionResult(
        bundle=bundle,
        decision=decision,
        comment_markdown=comment_markdown,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint used by the GitHub Action."""

    parser = _build_parser()
    args = parser.parse_args(argv)

    diff_text = Path(args.diff_path).read_text()
    current_reports = _parse_report_mappings(args.report)
    baseline_reports = _parse_report_mappings(args.baseline_report)
    policy_text = Path(args.policy_path).read_text() if args.policy_path else None
    metadata_text = Path(args.metadata_path).read_text() if args.metadata_path else None

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
        metadata_text=metadata_text,
    )

    if args.comment_path:
        Path(args.comment_path).write_text(result.comment_markdown)

    if args.json_output_path:
        Path(args.json_output_path).write_text(json.dumps(result.to_dict(), indent=2) + "\n")

    _write_github_outputs(result, args.comment_path, args.json_output_path)
    print(result.comment_markdown, end="")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Veridion Release Decision Intelligence")
    parser.add_argument("--diff-path", required=True, help="Path to a unified diff file")
    parser.add_argument(
        "--report",
        action="append",
        default=[],
        metavar="TOOL=PATH",
        help="Current scanner report mapping, repeatable",
    )
    parser.add_argument(
        "--baseline-report",
        action="append",
        default=[],
        metavar="TOOL=PATH",
        help="Baseline scanner report mapping, repeatable",
    )
    parser.add_argument("--policy-path", help="Path to a policy YAML file")
    parser.add_argument("--metadata-path", help="Path to optional pull request metadata JSON")
    parser.add_argument("--comment-path", help="Path to write rendered PR comment markdown")
    parser.add_argument("--json-output-path", help="Path to write structured JSON output")
    return parser


def _parse_report_mappings(values: list[str]) -> dict[str, str]:
    mappings: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"invalid report mapping '{value}', expected TOOL=PATH")
        tool, path = value.split("=", maxsplit=1)
        normalized_tool = tool.strip().lower()
        if not normalized_tool or not path.strip():
            raise ValueError(f"invalid report mapping '{value}', expected TOOL=PATH")
        mappings[normalized_tool] = path.strip()
    return mappings


def _load_findings(report_paths: dict[str, str]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for tool_name, path in report_paths.items():
        try:
            report = json.loads(Path(path).read_text())
        except Exception as exc:
            raise RuntimeError(f"failed to load {tool_name} report from {path}") from exc
        findings.extend(normalize_report(tool_name, report))
    return findings


def _write_github_outputs(
    result: ActionResult,
    comment_path: str | None,
    json_output_path: str | None,
) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        return

    lines = [
        f"decision={result.decision.decision}",
        f"score={result.decision.score}",
        f"confidence={result.decision.confidence}",
        f"comment_identifier={result.comment_identifier}",
        f"comment_path={comment_path or ''}",
        f"json_output_path={json_output_path or ''}",
    ]
    if result.decision.required_approvals:
        lines.append(f"required_approvals={','.join(result.decision.required_approvals)}")
    else:
        lines.append("required_approvals=")

    with Path(github_output).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
