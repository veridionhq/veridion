"""Serialization helpers for plain Python structures."""

from __future__ import annotations

from typing import Any


def plain(value: Any) -> Any:
    """Convert nested tuples and dataclass-derived structures to plain objects."""

    if isinstance(value, tuple):
        return [plain(item) for item in value]
    if isinstance(value, list):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return {key: plain(item) for key, item in value.items()}
    return value


def strict_string(value: object) -> str:
    """Return a stripped string, rejecting non-string non-None values."""

    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    raise ValueError(f"expected string value, got: {value!r}")


def optional_string(value: object) -> str | None:
    """Return a stripped string or None when blank."""

    text = strict_string(value)
    return text or None
