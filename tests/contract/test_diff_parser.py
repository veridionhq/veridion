from pathlib import Path

from veridion.change_context import ParsedFileChange, parse_unified_diff


FIXTURE_PATH = Path("tests/fixtures/diffs/sample_pr.diff")


def test_unified_diff_parses_into_change_context_signals() -> None:
    context = parse_unified_diff(FIXTURE_PATH.read_text())

    assert context.changed_paths == (
        "requirements.txt",
        "poetry.lock",
        "terraform/prod/main.tf",
        "app/routes.py",
    )
    assert context.has_dependency_changes is True
    assert context.has_lockfile_changes is True
    assert context.has_iac_changes is True
    assert context.files == (
        ParsedFileChange(
            path="requirements.txt",
            change_type="added",
            added_lines=1,
            removed_lines=0,
            signals=("dependency_manifest",),
            previous_path="requirements.txt",
        ),
        ParsedFileChange(
            path="poetry.lock",
            change_type="modified",
            added_lines=1,
            removed_lines=1,
            signals=("lockfile",),
            previous_path="poetry.lock",
        ),
        ParsedFileChange(
            path="terraform/prod/main.tf",
            change_type="added",
            added_lines=2,
            removed_lines=0,
            signals=("infrastructure", "production_surface"),
            previous_path="terraform/prod/main.tf",
        ),
        ParsedFileChange(
            path="app/routes.py",
            change_type="modified",
            added_lines=2,
            removed_lines=1,
            signals=("application_code",),
            previous_path="app/routes.py",
        ),
    )
