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
