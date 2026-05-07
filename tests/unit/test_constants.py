from veridion.constants import RDI_DECISIONS


def test_rdi_decisions_are_defined_in_priority_order() -> None:
    assert RDI_DECISIONS == ("GO", "CONDITIONAL GO", "NO GO")
