"""Policy simulation for comparing policy packs against the same release input."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from veridion.action.runner import _load_findings, _parse_optional_json_text, _parse_report_mappings
from veridion.analysis import build_analysis_bundle
from veridion.change_context import parse_unified_diff
from veridion.context import resolve_operational_context, resolve_operational_context_artifact
from veridion.decision_contract import build_decision_contract, evaluate_gate
from veridion.policy import evaluate_release, parse_policy_pack_yaml
from veridion.report import explain_introduced_threats
from veridion.suppression import parse_suppressions_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulate multiple Veridion policy packs against the same release input")
    parser.add_argument("--diff-path", required=True, help="Path to unified diff")
    parser.add_argument("--report", action="append", default=[], metavar="TOOL=PATH", help="Current scanner report mapping, repeatable")
    parser.add_argument("--baseline-report", action="append", default=[], metavar="TOOL=PATH", help="Baseline scanner report mapping, repeatable")
    parser.add_argument("--policy-set", action="append", default=[], metavar="NAME=PATH", help="Named policy pack mapping, repeatable")
    parser.add_argument("--operational-context-path", help="Path to versioned operational-context JSON")
    parser.add_argument("--metadata-path", help="Path to optional metadata JSON")
    parser.add_argument("--trust-profile-path", help="Path to optional trust profile JSON")
    parser.add_argument("--suppression-path", help="Path to optional suppressions JSON")
    parser.add_argument("--output-path", help="Where to write the simulation JSON")
    args = parser.parse_args(argv)

    policy_sets = _parse_policy_sets(args.policy_set)
    if not policy_sets:
        raise RuntimeError("at least one --policy-set NAME=PATH is required")

    diff_text = Path(args.diff_path).read_text()
    current_reports = _parse_report_mappings(args.report)
    baseline_reports = _parse_report_mappings(args.baseline_report)
    current_findings = _load_findings(current_reports)
    baseline_findings = _load_findings(baseline_reports)
    change_context = parse_unified_diff(diff_text)
    operational_context_text = Path(args.operational_context_path).read_text() if args.operational_context_path else None
    metadata_text = Path(args.metadata_path).read_text() if args.metadata_path else None
    trust_profile_text = Path(args.trust_profile_path).read_text() if args.trust_profile_path else None
    suppression_text = Path(args.suppression_path).read_text() if args.suppression_path else None

    operational_context_payload = _parse_optional_json_text(operational_context_text, label="operational context")
    suppressions_payload = _parse_optional_json_text(suppression_text, label="suppressions")
    suppression_rules = parse_suppressions_payload(suppressions_payload)

    if operational_context_text:
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
        trust_memory_signals=resolved_context.trust_memory_signals,
        suppression_rules=suppression_rules,
    )

    threats = explain_introduced_threats(bundle)
    results: list[dict[str, object]] = []
    for name, path in policy_sets:
        pack = parse_policy_pack_yaml(Path(path).read_text())
        decision = evaluate_release(bundle, pack.config)
        gate = evaluate_gate(decision.decision, allowed_decisions=("GO", "CONDITIONAL GO"))
        contract = build_decision_contract(
            bundle=bundle,
            decision=decision,
            threats=threats,
            comment_identifier="veridion:rdi",
            comment_summary={"mode": "deterministic", "provider": "none", "model": "", "error": ""},
            gate=gate,
            policy_pack_metadata=pack.metadata,
        )
        results.append(
            {
                "name": name,
                "path": path,
                "policy_pack": {
                    "pack_id": pack.metadata.pack_id,
                    "pack_name": pack.metadata.display_name,
                    "pack_version": pack.metadata.version,
                    "pack_owner": pack.metadata.owner,
                    "rollout_stage": pack.metadata.rollout_stage,
                },
                "decision": contract["decision"],
                "reasons": contract["reasons"],
                "actions": contract["actions"],
                "blocking_categories": contract["decision"]["blocking_categories"],
            }
        )

    output = {
        "schema_version": 1,
        "source": "veridion.policy.simulator@1",
        "summary": {
            "changed_files": bundle.summary.changed_files,
            "introduced_findings": bundle.summary.introduced_findings,
            "unattributed_findings": bundle.summary.unattributed_findings,
        },
        "results": results,
    }
    rendered = json.dumps(output, indent=2) + "\n"
    if args.output_path:
        Path(args.output_path).write_text(rendered)
    print(rendered, end="")
    return 0


def _parse_policy_sets(values: list[str]) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for value in values:
        if "=" not in value:
            raise RuntimeError(f"invalid policy set mapping '{value}', expected NAME=PATH")
        name, path = value.split("=", maxsplit=1)
        normalized_name = name.strip()
        normalized_path = path.strip()
        if not normalized_name or not normalized_path:
            raise RuntimeError(f"invalid policy set mapping '{value}', expected NAME=PATH")
        parsed.append((normalized_name, normalized_path))
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
