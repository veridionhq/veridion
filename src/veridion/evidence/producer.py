"""Evidence producer manifest validation."""

from __future__ import annotations

import json
from pathlib import Path

from veridion.evidence.catalog import EVIDENCE_TYPE_CATALOG, STATUS_CATALOG
from veridion.evidence.model import NormalizedEvidence


def validate_producer_manifest(payload: object) -> dict[str, object]:
    """Validate an evidence producer manifest and return a compact summary."""

    if not isinstance(payload, dict):
        raise RuntimeError("producer manifest must contain an object")
    schema_version = payload.get("schema_version")
    if schema_version != 1:
        raise RuntimeError(f"unsupported producer manifest schema_version: {schema_version!r}")

    producer = payload.get("producer")
    if not isinstance(producer, dict):
        raise RuntimeError("producer manifest requires producer object")
    producer_id = _required_string(producer, "id", "producer.id")
    display_name = _required_string(producer, "display_name", "producer.display_name")

    emits = payload.get("emits")
    if not isinstance(emits, list) or not emits:
        raise RuntimeError("producer manifest requires non-empty emits list")

    evidence_types: list[str] = []
    statuses: list[str] = []
    for index, item in enumerate(emits):
        if not isinstance(item, dict):
            raise RuntimeError(f"emits[{index}] must be an object")
        evidence_type = _required_string(item, "evidence_type", f"emits[{index}].evidence_type")
        if evidence_type not in EVIDENCE_TYPE_CATALOG:
            raise RuntimeError(f"emits[{index}] uses unsupported evidence_type: {evidence_type}")
        evidence_types.append(evidence_type)

        item_statuses = item.get("statuses", [])
        if not isinstance(item_statuses, list) or not item_statuses:
            raise RuntimeError(f"emits[{index}].statuses must be a non-empty list")
        for status in item_statuses:
            normalized = str(status).strip().lower()
            if normalized not in STATUS_CATALOG:
                raise RuntimeError(f"emits[{index}] uses unsupported status: {status}")
            statuses.append(normalized)

        subject_keys = item.get("subject_keys", [])
        if subject_keys is not None and not isinstance(subject_keys, list):
            raise RuntimeError(f"emits[{index}].subject_keys must be a list")

    return {
        "valid": True,
        "producer_id": producer_id,
        "display_name": display_name,
        "emits": len(emits),
        "evidence_types": sorted(set(evidence_types)),
        "statuses": sorted(set(statuses)),
    }


def validate_producer_manifest_file(path: Path) -> dict[str, object]:
    return validate_producer_manifest(json.loads(path.read_text()))


def validate_evidence_against_producer(
    evidence: tuple[NormalizedEvidence, ...],
    producer_payload: object,
) -> dict[str, object]:
    """Validate emitted evidence against a producer manifest."""

    manifest_summary = validate_producer_manifest(producer_payload)
    allowed = _allowed_signal_pairs(producer_payload)
    required_subject_keys = _required_subject_keys(producer_payload)
    invalid: list[dict[str, str]] = []
    for item in evidence:
        allowed_statuses = allowed.get(item.evidence_type, set())
        if item.status not in allowed_statuses:
            invalid.append(
                {
                    "evidence_type": item.evidence_type,
                    "status": item.status,
                    "name": item.name,
                }
            )
            continue
        missing_subject_keys = tuple(
            key
            for key in required_subject_keys.get(item.evidence_type, ())
            if not str(item.subject.get(key) or "").strip()
        )
        if missing_subject_keys:
            raise RuntimeError(
                "producer emitted evidence missing required subject key(s): "
                f"{', '.join(missing_subject_keys)} for {item.evidence_type} from {item.name}"
            )

    if invalid:
        first = invalid[0]
        raise RuntimeError(
            "producer emitted undeclared evidence signal: "
            f"{first['evidence_type']} status {first['status']} from {first['name']}"
        )

    return {
        "valid": True,
        "producer_id": manifest_summary["producer_id"],
        "evidence_items": len(evidence),
        "declared_evidence_types": manifest_summary["evidence_types"],
        "declared_statuses": manifest_summary["statuses"],
    }


def validate_evidence_against_producer_file(
    evidence: tuple[NormalizedEvidence, ...],
    producer_path: Path,
) -> dict[str, object]:
    return validate_evidence_against_producer(evidence, json.loads(producer_path.read_text()))


def _allowed_signal_pairs(payload: object) -> dict[str, set[str]]:
    if not isinstance(payload, dict):
        raise RuntimeError("producer manifest must contain an object")
    emits = payload.get("emits")
    if not isinstance(emits, list):
        raise RuntimeError("producer manifest requires emits list")

    allowed: dict[str, set[str]] = {}
    for item in emits:
        if not isinstance(item, dict):
            continue
        evidence_type = str(item.get("evidence_type") or "").strip()
        statuses = item.get("statuses", [])
        if not isinstance(statuses, list):
            continue
        allowed.setdefault(evidence_type, set())
        allowed[evidence_type].update(str(status).strip().lower() for status in statuses)
    return allowed


def _required_subject_keys(payload: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(payload, dict):
        raise RuntimeError("producer manifest must contain an object")
    emits = payload.get("emits")
    if not isinstance(emits, list):
        raise RuntimeError("producer manifest requires emits list")

    required: dict[str, list[str]] = {}
    for item in emits:
        if not isinstance(item, dict):
            continue
        evidence_type = str(item.get("evidence_type") or "").strip()
        subject_keys = item.get("subject_keys", [])
        if not isinstance(subject_keys, list):
            continue
        required.setdefault(evidence_type, [])
        for key in subject_keys:
            normalized_key = str(key).strip()
            if normalized_key and normalized_key not in required[evidence_type]:
                required[evidence_type].append(normalized_key)
    return {key: tuple(values) for key, values in required.items()}


def _required_string(item: dict[str, object], key: str, label: str) -> str:
    value = str(item.get(key) or "").strip()
    if not value:
        raise RuntimeError(f"producer manifest requires non-empty {label}")
    return value
