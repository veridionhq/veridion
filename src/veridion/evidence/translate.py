"""Translate common tool outputs into native Veridion release evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from xml.etree import ElementTree

from veridion.evidence.catalog import evidence_catalog
from veridion.evidence.model import parse_evidence_payload, parse_evidence_text
from veridion.evidence.producer import (
    validate_evidence_against_producer_file,
    validate_producer_manifest_file,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Translate release evidence into Veridion evidence JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate native Veridion evidence JSON")
    validate_parser.add_argument("--input", action="append", required=True, help="Path to evidence JSON, repeatable")
    validate_parser.add_argument("--summary", action="store_true", help="Print validation summary JSON to stdout")

    producer_parser = subparsers.add_parser("validate-producer", help="Validate an evidence producer manifest")
    producer_parser.add_argument("--input", required=True, help="Path to evidence producer manifest JSON")
    producer_parser.add_argument("--summary", action="store_true", help="Print validation summary JSON to stdout")

    catalog_parser = subparsers.add_parser("catalog", help="Print the canonical evidence vocabulary")
    catalog_parser.add_argument("--output", help="Optional path to write the catalog JSON")

    ingest_parser = subparsers.add_parser("ingest", help="Translate, validate, and conform evidence in one step")
    ingest_parser.add_argument("--producer", required=True, help="Path to evidence producer manifest JSON")
    ingest_parser.add_argument("--format", required=True, choices=("junit", "github-checks"), help="Source format")
    ingest_parser.add_argument("--input", action="append", required=True, help="Path to source input, repeatable")
    ingest_parser.add_argument("--output", required=True, help="Path to write Veridion evidence JSON")
    ingest_parser.add_argument("--name", default="", help="Evidence display name")
    ingest_parser.add_argument("--summary", action="store_true", help="Print ingestion summary JSON to stdout")
    _add_common_args(ingest_parser)

    translate_parser = subparsers.add_parser("translate", help="Translate a supported source format")
    translate_subparsers = translate_parser.add_subparsers(dest="format", required=True)

    junit_parser = translate_subparsers.add_parser("junit", help="Translate JUnit XML test results")
    junit_parser.add_argument("--input", action="append", required=True, help="Path to a JUnit XML file, repeatable")
    junit_parser.add_argument("--output", required=True, help="Path to write Veridion evidence JSON")
    junit_parser.add_argument("--name", default="JUnit test results", help="Evidence display name")
    _add_common_args(junit_parser)

    checks_parser = translate_subparsers.add_parser("github-checks", help="Translate GitHub check-runs JSON")
    checks_parser.add_argument("--input", required=True, help="Path to GitHub check-runs JSON")
    checks_parser.add_argument("--output", required=True, help="Path to write Veridion evidence JSON")
    checks_parser.add_argument("--name", default="GitHub checks", help="Evidence display name")
    _add_common_args(checks_parser)

    args = parser.parse_args(argv)
    if args.command == "validate":
        summary = validate_evidence_files(tuple(Path(path) for path in args.input))
        if args.summary:
            print(json.dumps(summary, indent=2))
        return 0
    if args.command == "validate-producer":
        summary = validate_producer_manifest_file(Path(args.input))
        if args.summary:
            print(json.dumps(summary, indent=2))
        return 0
    if args.command == "catalog":
        payload = json.dumps(evidence_catalog(), indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(payload)
        else:
            print(payload, end="")
        return 0
    if args.command == "ingest":
        summary = ingest_evidence(
            producer_path=Path(args.producer),
            source_format=args.format,
            input_paths=tuple(Path(path) for path in args.input),
            output_path=Path(args.output),
            subject=_subject_from_args(args),
            name=args.name,
            required=args.required,
        )
        if args.summary:
            print(json.dumps(summary, indent=2))
        return 0

    subject = _subject_from_args(args)
    if args.format == "junit":
        payload = translate_junit_xml(
            paths=tuple(Path(path) for path in args.input),
            subject=subject,
            name=args.name,
            required=args.required,
        )
    elif args.format == "github-checks":
        payload = translate_github_checks(
            payload=json.loads(Path(args.input).read_text()),
            subject=subject,
            name=args.name,
            required=args.required,
        )
    else:
        raise RuntimeError(f"unsupported evidence translation format: {args.format}")

    Path(args.output).write_text(json.dumps(payload, indent=2) + "\n")
    return 0


def ingest_evidence(
    *,
    producer_path: Path,
    source_format: str,
    input_paths: tuple[Path, ...],
    output_path: Path,
    subject: dict[str, object],
    name: str,
    required: bool,
) -> dict[str, object]:
    """Run the full local evidence ingestion lifecycle."""

    producer_summary = validate_producer_manifest_file(producer_path)
    payload = translate_source(
        source_format=source_format,
        input_paths=input_paths,
        subject=subject,
        name=name,
        required=required,
    )
    evidence = parse_evidence_payload(payload)
    validation_summary = _evidence_summary(evidence, files=1)
    conformance_summary = validate_evidence_against_producer_file(evidence, producer_path)
    output_path.write_text(json.dumps(payload, indent=2) + "\n")
    return {
        "valid": True,
        "producer": producer_summary,
        "evidence": validation_summary,
        "conformance": conformance_summary,
        "output": str(output_path),
    }


def translate_source(
    *,
    source_format: str,
    input_paths: tuple[Path, ...],
    subject: dict[str, object],
    name: str,
    required: bool,
) -> dict[str, object]:
    if source_format == "junit":
        return translate_junit_xml(
            paths=input_paths,
            subject=subject,
            name=name or "JUnit test results",
            required=required,
        )
    if source_format == "github-checks":
        if len(input_paths) != 1:
            raise RuntimeError("github-checks ingestion requires exactly one --input path")
        return translate_github_checks(
            payload=json.loads(input_paths[0].read_text()),
            subject=subject,
            name=name or "GitHub checks",
            required=required,
        )
    raise RuntimeError(f"unsupported evidence ingestion format: {source_format}")


def validate_evidence_files(paths: tuple[Path, ...]) -> dict[str, object]:
    """Validate native evidence files and return a compact producer-facing summary."""

    evidence = []
    for path in paths:
        evidence.extend(parse_evidence_text(path.read_text()))
    return _evidence_summary(tuple(evidence), files=len(paths))


def _evidence_summary(evidence: tuple, *, files: int) -> dict[str, object]:
    """Return a compact summary for already-normalized evidence."""

    blocking = [item for item in evidence if item.is_blocking]
    review = [item for item in evidence if item.requires_review]
    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for item in evidence:
        by_status[item.status] = by_status.get(item.status, 0) + 1
        by_type[item.evidence_type] = by_type.get(item.evidence_type, 0) + 1

    return {
        "valid": True,
        "files": files,
        "evidence_items": len(evidence),
        "blocking_required": len(blocking),
        "review_required": len(review),
        "by_status": dict(sorted(by_status.items())),
        "by_type": dict(sorted(by_type.items())),
    }


def translate_junit_xml(
    *,
    paths: tuple[Path, ...],
    subject: dict[str, object],
    name: str,
    required: bool,
) -> dict[str, object]:
    totals = {
        "tests": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }
    suites = 0
    source_paths: list[str] = []

    for path in paths:
        root = ElementTree.parse(path).getroot()
        source_paths.append(str(path))
        for suite in _iter_junit_suites(root):
            suites += 1
            totals["tests"] += _xml_int(suite.get("tests"))
            totals["failures"] += _xml_int(suite.get("failures"))
            totals["errors"] += _xml_int(suite.get("errors"))
            totals["skipped"] += _xml_int(suite.get("skipped"))

    failed = totals["failures"] + totals["errors"]
    if failed:
        status = "failed"
        severity = "high"
        summary = f"{failed} failing JUnit test(s) across {totals['tests']} total test(s)"
    elif totals["tests"] == 0:
        status = "unknown"
        severity = "medium"
        summary = "JUnit results contained no test cases"
    elif totals["skipped"] == totals["tests"]:
        status = "skipped"
        severity = "medium"
        summary = f"All {totals['tests']} JUnit test(s) were skipped"
    else:
        status = "passed"
        severity = "info"
        summary = f"{totals['tests']} JUnit test(s) passed"

    return _bundle(
        subject=subject,
        evidence=[
            {
                "evidence_type": "test_result",
                "category": "test",
                "name": name,
                "status": status,
                "severity": severity,
                "required": required,
                "summary": summary,
                "source": {
                    "provider": "junit",
                    "format": "junit_xml",
                    "paths": source_paths,
                },
                "attributes": {
                    "suite_count": suites,
                    **totals,
                },
            }
        ],
    )


def translate_github_checks(
    *,
    payload: object,
    subject: dict[str, object],
    name: str,
    required: bool,
) -> dict[str, object]:
    check_runs = _github_check_runs(payload)
    conclusions: dict[str, int] = {}
    statuses: dict[str, int] = {}
    details_urls: list[str] = []
    for run in check_runs:
        conclusion = str(run.get("conclusion") or "").strip().lower()
        status = str(run.get("status") or "").strip().lower()
        if conclusion:
            conclusions[conclusion] = conclusions.get(conclusion, 0) + 1
        if status:
            statuses[status] = statuses.get(status, 0) + 1
        details_url = str(run.get("details_url") or run.get("html_url") or "").strip()
        if details_url:
            details_urls.append(details_url)

    failing = sum(conclusions.get(item, 0) for item in ("failure", "cancelled", "timed_out", "action_required"))
    warning = sum(conclusions.get(item, 0) for item in ("neutral", "skipped"))
    pending = sum(statuses.get(item, 0) for item in ("queued", "in_progress", "waiting", "pending"))

    if failing:
        status = "failed"
        severity = "high"
        summary = f"{failing} GitHub check run(s) failed or require action"
    elif pending:
        status = "unknown"
        severity = "medium"
        summary = f"{pending} GitHub check run(s) are still pending"
    elif warning:
        status = "warning"
        severity = "medium"
        summary = f"{warning} GitHub check run(s) completed with neutral or skipped conclusions"
    else:
        status = "passed"
        severity = "info"
        summary = f"{len(check_runs)} GitHub check run(s) passed"

    return _bundle(
        subject=subject,
        evidence=[
            {
                "evidence_type": "ci_check",
                "category": "ci",
                "name": name,
                "status": status,
                "severity": severity,
                "required": required,
                "summary": summary,
                "details_url": details_urls[0] if details_urls else "",
                "source": {
                    "provider": "github",
                    "resource": "check_runs",
                },
                "attributes": {
                    "check_run_count": len(check_runs),
                    "conclusions": conclusions,
                    "statuses": statuses,
                },
            }
        ],
    )


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--required", action="store_true", help="Mark translated evidence as required for release")
    parser.add_argument("--repo", default="", help="Repository identifier, for example owner/repo")
    parser.add_argument("--pull-request", type=int, help="Pull request number")
    parser.add_argument("--commit", default="", help="Commit SHA the evidence applies to")
    parser.add_argument("--service", default="", help="Service identifier")
    parser.add_argument("--environment", default="", help="Target environment")


def _subject_from_args(args: argparse.Namespace) -> dict[str, object]:
    values = {
        "repo": args.repo,
        "pull_request": args.pull_request,
        "commit": args.commit,
        "service": args.service,
        "environment": args.environment,
    }
    return {key: value for key, value in values.items() if value not in ("", None)}


def _bundle(*, subject: dict[str, object], evidence: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "subject": subject,
        "evidence": evidence,
    }


def _iter_junit_suites(root: ElementTree.Element) -> tuple[ElementTree.Element, ...]:
    if _strip_namespace(root.tag) == "testsuite":
        return (root,)
    return tuple(item for item in root.iter() if _strip_namespace(item.tag) == "testsuite")


def _strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", maxsplit=1)[1]
    return tag


def _xml_int(value: str | None) -> int:
    if not value:
        return 0
    try:
        return int(float(value))
    except ValueError:
        return 0


def _github_check_runs(payload: object) -> tuple[dict[str, object], ...]:
    if isinstance(payload, dict) and isinstance(payload.get("check_runs"), list):
        runs = payload["check_runs"]
    elif isinstance(payload, list):
        runs = payload
    else:
        raise RuntimeError("GitHub checks input must be an array or an object with check_runs")

    if not all(isinstance(item, dict) for item in runs):
        raise RuntimeError("GitHub check run entries must be objects")
    return tuple(dict(item) for item in runs)


if __name__ == "__main__":
    raise SystemExit(main())
