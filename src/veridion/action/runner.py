"""GitHub Action runner for Release Decision Intelligence."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from veridion.analysis import AnalysisBundle, build_analysis_bundle
from veridion.context import (
    resolve_operational_context,
    resolve_operational_context_artifact,
)
from veridion.normalize import NormalizedFinding, normalize_report
from veridion.policy import PolicyDecision, PolicyConfig, evaluate_release, parse_policy_yaml
from veridion.report import render_pr_comment
from veridion.suppression import parse_suppressions_payload
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
    operational_context_text: str | None = None,
    metadata_text: str | None = None,
    trust_profile_text: str | None = None,
    suppression_text: str | None = None,
) -> ActionResult:
    """Run the full RDI pipeline from file-backed action inputs."""

    current_findings = _load_findings(current_reports)
    baseline_findings = _load_findings(baseline_reports or {})
    change_context = parse_unified_diff(diff_text)
    policy = parse_policy_yaml(policy_text) if policy_text else PolicyConfig()
    operational_context_payload = _parse_optional_json_text(operational_context_text, label="operational context")
    suppressions_payload = _parse_optional_json_text(suppression_text, label="suppressions")
    suppression_rules = parse_suppressions_payload(suppressions_payload)

    if operational_context_payload:
        if metadata_text or trust_profile_text:
            print(
                "warning: operational-context-path provided; metadata-path and trust-profile-path are ignored",
                file=sys.stderr,
            )
        resolved_context = resolve_operational_context_artifact(
            change_context=change_context,
            operational_context_payload=operational_context_payload,
        )
    else:
        metadata_payload = _parse_optional_json_text(metadata_text, label="metadata")
        trust_profile_payload = _parse_optional_json_text(trust_profile_text, label="trust profile")
        resolved_context = resolve_operational_context(
            change_context=change_context,
            metadata_payload=metadata_payload,
            trust_profile_payload=trust_profile_payload,
        )

    bundle = build_analysis_bundle(
        current_findings=current_findings,
        baseline_findings=baseline_findings,
        change_context=change_context,
        metadata=resolved_context.metadata,
        historical_signals=resolved_context.historical_signals,
        runtime_signals=resolved_context.runtime_signals,
        ownership_signals=resolved_context.ownership_signals,
        trust_profile_metadata=resolved_context.trust_profile_metadata,
        trust_baseline=resolved_context.trust_baseline,
        suppression_rules=suppression_rules,
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
    operational_context_text = Path(args.operational_context_path).read_text() if args.operational_context_path else None
    metadata_text = Path(args.metadata_path).read_text() if args.metadata_path else None
    trust_profile_text = Path(args.trust_profile_path).read_text() if args.trust_profile_path else None
    suppression_text = Path(args.suppression_path).read_text() if args.suppression_path else None

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
        operational_context_text=operational_context_text,
        metadata_text=metadata_text,
        trust_profile_text=trust_profile_text,
        suppression_text=suppression_text,
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
    parser.add_argument("--operational-context-path", help="Path to optional versioned operational-context JSON")
    parser.add_argument("--metadata-path", help="Path to optional pull request metadata JSON")
    parser.add_argument("--trust-profile-path", help="Path to optional trust profile JSON")
    parser.add_argument("--suppression-path", help="Path to optional accepted-risk suppression JSON")
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


def _parse_optional_json_text(text: str | None, *, label: str) -> dict[str, object]:
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} JSON is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} JSON input must contain an object at the top level")
    return payload


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
