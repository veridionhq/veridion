"""Environment-agnostic operational context resolution."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.attribution import PullRequestMetadata, parse_pull_request_metadata
from veridion.change_context import ParsedChangeContext
from veridion.context.history import HistoricalSignals, parse_historical_signals
from veridion.context.operational_context_artifact import (
    extract_operational_context_sections,
    validate_operational_context_payload,
)
from veridion.context.ownership import OwnershipSignals, parse_ownership_signals
from veridion.context.runtime import RuntimeSignals, derive_runtime_signals, parse_runtime_signals
from veridion.context.trust_memory import TrustMemorySignals, parse_trust_memory_signals
from veridion.context.trust_profile_artifact import merge_metadata_with_trust_profile
from veridion.context.trust import (
    TrustBaseline,
    TrustProfileMetadata,
    parse_trust_baseline,
    parse_trust_profile_metadata,
)


@dataclass(frozen=True)
class ResolvedOperationalContext:
    """Normalized operational context consumed by the decision engine."""

    metadata: PullRequestMetadata | None
    historical_signals: HistoricalSignals
    runtime_signals: RuntimeSignals
    ownership_signals: OwnershipSignals
    trust_profile_metadata: TrustProfileMetadata
    trust_baseline: TrustBaseline
    trust_memory_signals: TrustMemorySignals


def resolve_operational_context(
    *,
    change_context: ParsedChangeContext,
    metadata_payload: dict[str, object] | None = None,
    trust_profile_payload: dict[str, object] | None = None,
) -> ResolvedOperationalContext:
    """Resolve operational context from generic metadata and trust-profile inputs."""

    metadata_payload = metadata_payload or {}
    trust_profile_payload = trust_profile_payload or {}
    merged_payload = merge_metadata_with_trust_profile(metadata_payload, trust_profile_payload)

    return ResolvedOperationalContext(
        metadata=parse_pull_request_metadata(metadata_payload) if metadata_payload else None,
        historical_signals=parse_historical_signals(merged_payload),
        runtime_signals=derive_runtime_signals(change_context, parse_runtime_signals(merged_payload)),
        ownership_signals=parse_ownership_signals(merged_payload),
        trust_profile_metadata=parse_trust_profile_metadata(merged_payload),
        trust_baseline=parse_trust_baseline(merged_payload),
        trust_memory_signals=parse_trust_memory_signals(merged_payload),
    )


def resolve_operational_context_artifact(
    *,
    change_context: ParsedChangeContext,
    operational_context_payload: dict[str, object],
) -> ResolvedOperationalContext:
    """Resolve operational context from the versioned operational-context artifact."""

    validate_operational_context_payload(operational_context_payload)
    sections = extract_operational_context_sections(operational_context_payload)
    merged_payload = {
        "historical": sections["historical"],
        "runtime": sections["runtime"],
        "ownership": sections["ownership"],
        "trust_baseline": sections["trust_baseline"],
        "trust_profile_metadata": sections["trust_profile_metadata"],
    }
    metadata_payload = sections["metadata"]

    return ResolvedOperationalContext(
        metadata=parse_pull_request_metadata(metadata_payload) if metadata_payload else None,
        historical_signals=parse_historical_signals(merged_payload),
        runtime_signals=derive_runtime_signals(change_context, parse_runtime_signals(merged_payload)),
        ownership_signals=parse_ownership_signals(merged_payload),
        trust_profile_metadata=parse_trust_profile_metadata(merged_payload),
        trust_baseline=parse_trust_baseline(merged_payload),
        trust_memory_signals=parse_trust_memory_signals(merged_payload),
    )
