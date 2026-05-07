"""Shared normalization helpers."""

from __future__ import annotations

import hashlib

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")

_SEVERITY_ALIASES = {
    "error": "high",
    "warning": "medium",
    "warn": "medium",
    "note": "low",
    "informational": "info",
}

_CONFIDENCE_ALIASES = {
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def normalize_severity(value: str | None) -> str:
    """Normalize source-specific severities to a stable internal vocabulary."""

    if not value:
        return "unknown"

    normalized = value.strip().lower()
    return _SEVERITY_ALIASES.get(normalized, normalized if normalized in SEVERITY_ORDER else "unknown")


def normalize_confidence(value: str | None) -> str | None:
    """Normalize confidence values when the source provides them."""

    if not value:
        return None

    normalized = value.strip().lower()
    return _CONFIDENCE_ALIASES.get(normalized)


def as_string(value: object, *, default: str | None = None) -> str | None:
    """Convert a value to string when possible."""

    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def as_int(value: object) -> int | None:
    """Convert an integer-like value when already typed as int."""

    if isinstance(value, int):
        return value
    return None


def as_float(value: object) -> float | None:
    """Convert float-like values from scanner payloads."""

    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def flatten_first(value: object) -> str | None:
    """Return the first string-like item from a scalar or list value."""

    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                return item
    return None


def location_path_from_locations(value: object) -> str | None:
    """Extract the first location path from scanner artifact locations."""

    if not isinstance(value, list):
        return None

    for item in value:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if isinstance(path, str):
            return path

    return None


def stable_text_hash(value: str | None) -> str | None:
    """Build a stable SHA-256 hash for matched source text."""

    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
