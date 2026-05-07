from pathlib import Path

from veridion.change_context import ParsedFileChange, parse_unified_diff


FIXTURE_PATH = Path("tests/fixtures/diffs/rename_delete_pr.diff")


def test_unified_diff_handles_rename_delete_and_new_file_cases() -> None:
    context = parse_unified_diff(FIXTURE_PATH.read_text())

    assert context.changed_paths == (
        "app/new_name.py",
        "package-lock.json",
        ".github/workflows/release.yml",
    )
    assert context.has_lockfile_changes is True
    assert context.has_iac_changes is True
    assert context.files == (
        ParsedFileChange(
            path="app/new_name.py",
            change_type="renamed",
            added_lines=1,
            removed_lines=1,
            signals=("application_code",),
            previous_path="app/old_name.py",
        ),
        ParsedFileChange(
            path="package-lock.json",
            change_type="deleted",
            added_lines=0,
            removed_lines=1,
            signals=("lockfile",),
            previous_path="package-lock.json",
        ),
        ParsedFileChange(
            path=".github/workflows/release.yml",
            change_type="added",
            added_lines=2,
            removed_lines=0,
            signals=("infrastructure",),
            previous_path=None,
        ),
    )
