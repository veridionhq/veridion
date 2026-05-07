from veridion.normalize.common import normalize_confidence, normalize_severity


def test_normalize_severity_maps_source_variants() -> None:
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("ERROR") == "high"
    assert normalize_severity("warning") == "medium"
    assert normalize_severity(None) == "unknown"


def test_normalize_confidence_rejects_unknown_values() -> None:
    assert normalize_confidence("HIGH") == "high"
    assert normalize_confidence("medium") == "medium"
    assert normalize_confidence("tentative") is None
