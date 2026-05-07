"""Parse pull request diffs into normalized change context."""

from __future__ import annotations

from dataclasses import dataclass


DEPENDENCY_MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
}

LOCKFILE_NAMES = {
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
}

IAC_SUFFIXES = (".tf", ".tfvars")
IAC_PATH_HINTS = (
    "terraform/",
    "helm/",
    "k8s/",
    "kubernetes/",
    "manifests/",
    "deploy/",
    "infrastructure/",
    ".github/workflows/",
)


@dataclass(frozen=True)
class ParsedFileChange:
    """Normalized view of a single changed file."""

    path: str
    change_type: str
    added_lines: int
    removed_lines: int
    signals: tuple[str, ...]
    previous_path: str | None = None


@dataclass(frozen=True)
class ParsedChangeContext:
    """Normalized representation of a pull request diff."""

    files: tuple[ParsedFileChange, ...]

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return tuple(file.path for file in self.files)

    @property
    def has_dependency_changes(self) -> bool:
        return any("dependency_manifest" in file.signals for file in self.files)

    @property
    def has_lockfile_changes(self) -> bool:
        return any("lockfile" in file.signals for file in self.files)

    @property
    def has_iac_changes(self) -> bool:
        return any("infrastructure" in file.signals for file in self.files)


def parse_unified_diff(diff_text: str) -> ParsedChangeContext:
    """Parse a unified diff into file-level change context."""

    files: list[ParsedFileChange] = []
    current_path: str | None = None
    previous_path: str | None = None
    added_lines = 0
    removed_lines = 0
    declared_change_type: str | None = None

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current_path is not None:
                files.append(
                    _build_file_change(
                        current_path,
                        added_lines,
                        removed_lines,
                        previous_path=previous_path,
                        declared_change_type=declared_change_type,
                    )
                )
            current_path = _parse_path_from_diff_header(line)
            previous_path = _parse_previous_path_from_diff_header(line)
            added_lines = 0
            removed_lines = 0
            declared_change_type = None
            continue

        if current_path is None:
            continue

        if line.startswith("new file mode "):
            declared_change_type = "added"
            continue

        if line.startswith("deleted file mode "):
            declared_change_type = "deleted"
            continue

        if line.startswith("rename from "):
            previous_path = line.removeprefix("rename from ").strip()
            declared_change_type = "renamed"
            continue

        if line.startswith("rename to "):
            current_path = line.removeprefix("rename to ").strip()
            declared_change_type = "renamed"
            continue

        if line.startswith("+++ ") or line.startswith("--- "):
            continue

        if line.startswith("@@ "):
            continue

        if line.startswith("+"):
            added_lines += 1
            continue

        if line.startswith("-"):
            removed_lines += 1

    if current_path is not None:
        files.append(
            _build_file_change(
                current_path,
                added_lines,
                removed_lines,
                previous_path=previous_path,
                declared_change_type=declared_change_type,
            )
        )

    return ParsedChangeContext(files=tuple(files))


def _parse_path_from_diff_header(header: str) -> str:
    parts = header.split()
    if len(parts) < 4:
        return "unknown"

    b_path = parts[3]
    if b_path.startswith("b/"):
        return b_path[2:]
    return b_path


def _parse_previous_path_from_diff_header(header: str) -> str | None:
    parts = header.split()
    if len(parts) < 3:
        return None

    a_path = parts[2]
    if a_path == "a/dev/null":
        return None
    if a_path.startswith("a/"):
        return a_path[2:]
    return a_path


def _build_file_change(
    path: str,
    added_lines: int,
    removed_lines: int,
    *,
    previous_path: str | None,
    declared_change_type: str | None,
) -> ParsedFileChange:
    signals = _classify_path(path)
    resolved_previous_path = previous_path

    if declared_change_type == "added":
        resolved_previous_path = None

    if declared_change_type is not None:
        change_type = declared_change_type
    elif added_lines and removed_lines:
        change_type = "modified"
    elif added_lines:
        change_type = "added"
    elif removed_lines:
        change_type = "deleted"
    else:
        change_type = "modified"

    return ParsedFileChange(
        path=path,
        change_type=change_type,
        added_lines=added_lines,
        removed_lines=removed_lines,
        signals=signals,
        previous_path=resolved_previous_path,
    )


def _classify_path(path: str) -> tuple[str, ...]:
    signals: list[str] = []
    file_name = path.rsplit("/", maxsplit=1)[-1]
    is_dependency_surface = False

    if file_name in DEPENDENCY_MANIFEST_NAMES:
        signals.append("dependency_manifest")
        is_dependency_surface = True

    if file_name in LOCKFILE_NAMES:
        signals.append("lockfile")
        is_dependency_surface = True

    if _is_infrastructure_path(path, allow_suffix_match=not is_dependency_surface):
        signals.append("infrastructure")

    if not signals:
        signals.append("application_code")

    return tuple(signals)


def _is_infrastructure_path(path: str, *, allow_suffix_match: bool) -> bool:
    if allow_suffix_match and path.endswith(IAC_SUFFIXES):
        return True
    if any(hint in path for hint in IAC_PATH_HINTS):
        return path.endswith((".yaml", ".yml", ".json", ".tf", ".tfvars")) or ".github/workflows/" in path
    return False
