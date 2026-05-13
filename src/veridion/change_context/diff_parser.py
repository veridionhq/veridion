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
PRODUCTION_PATH_HINTS = (
    "prod/",
    "production/",
    "environments/prod/",
    "environments/production/",
)
PUBLIC_EXPOSURE_HINTS = (
    "ingress",
    "gateway",
    "public",
    "edge",
    "loadbalancer",
    "load-balancer",
    "api-gateway",
)
SHARED_PLATFORM_HINTS = (
    ".github/workflows/",
    "terraform/modules/",
    "helm/charts/",
    "k8s/base/",
    "kubernetes/base/",
    "platform/",
    "shared/",
)
DATABASE_MIGRATION_HINTS = (
    "migrations/",
    "migration/",
    "alembic/versions/",
    "db/migrate/",
    "schema/migrations/",
)
PAYMENTS_HINTS = ("payment", "payments", "billing", "checkout")
AUTH_HINTS = ("auth", "identity", "oauth", "sso", "token")
DATA_HINTS = ("tenant", "privacy", "pii", "database", "db/", "data/")


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

    @property
    def has_production_surface_changes(self) -> bool:
        return any("production_surface" in file.signals for file in self.files)

    @property
    def has_public_exposure_changes(self) -> bool:
        return any("public_exposure_surface" in file.signals for file in self.files)

    @property
    def has_shared_platform_changes(self) -> bool:
        return any("shared_platform_surface" in file.signals for file in self.files)

    @property
    def has_database_migration_changes(self) -> bool:
        return any("database_migration_surface" in file.signals for file in self.files)

    @property
    def touches_payments_surface(self) -> bool:
        return any("payments_surface" in file.signals for file in self.files)

    @property
    def touches_auth_surface(self) -> bool:
        return any("auth_surface" in file.signals for file in self.files)

    @property
    def touches_data_surface(self) -> bool:
        return any("data_surface" in file.signals for file in self.files)

    @property
    def has_healthcheck_risk_changes(self) -> bool:
        return any("healthcheck_risk_surface" in file.signals for file in self.files)

    @property
    def has_direct_rollout_changes(self) -> bool:
        return any("direct_rollout_surface" in file.signals for file in self.files)

    @property
    def has_autoscaling_changes(self) -> bool:
        return any("autoscaling_surface" in file.signals for file in self.files)

    @property
    def has_privileged_container_changes(self) -> bool:
        return any("privileged_container_surface" in file.signals for file in self.files)

    @property
    def has_broad_iam_changes(self) -> bool:
        return any("broad_iam_surface" in file.signals for file in self.files)

    @property
    def has_resource_limit_risk_changes(self) -> bool:
        return any("resource_limit_risk_surface" in file.signals for file in self.files)


def parse_unified_diff(diff_text: str) -> ParsedChangeContext:
    """Parse a unified diff into file-level change context."""

    files: list[ParsedFileChange] = []
    current_path: str | None = None
    previous_path: str | None = None
    added_lines = 0
    removed_lines = 0
    declared_change_type: str | None = None
    added_content: list[str] = []
    removed_content: list[str] = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current_path is not None:
                files.append(
                    _build_file_change(
                        current_path,
                        added_lines,
                        removed_lines,
                        added_content=tuple(added_content),
                        removed_content=tuple(removed_content),
                        previous_path=previous_path,
                        declared_change_type=declared_change_type,
                    )
                )
            current_path = _parse_path_from_diff_header(line)
            previous_path = _parse_previous_path_from_diff_header(line)
            added_lines = 0
            removed_lines = 0
            declared_change_type = None
            added_content = []
            removed_content = []
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
            added_content.append(line[1:])
            continue

        if line.startswith("-"):
            removed_lines += 1
            removed_content.append(line[1:])

    if current_path is not None:
        files.append(
            _build_file_change(
                current_path,
                added_lines,
                removed_lines,
                added_content=tuple(added_content),
                removed_content=tuple(removed_content),
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
    added_content: tuple[str, ...],
    removed_content: tuple[str, ...],
    previous_path: str | None,
    declared_change_type: str | None,
) -> ParsedFileChange:
    signals = _classify_path(
        path,
        added_content=added_content,
        removed_content=removed_content,
    )
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


def _classify_path(
    path: str,
    *,
    added_content: tuple[str, ...],
    removed_content: tuple[str, ...],
) -> tuple[str, ...]:
    signals: list[str] = []
    file_name = path.rsplit("/", maxsplit=1)[-1]
    is_dependency_surface = False
    normalized_path = path.lower()
    added_lower = tuple(line.lower() for line in added_content)
    removed_lower = tuple(line.lower() for line in removed_content)

    if file_name in DEPENDENCY_MANIFEST_NAMES:
        signals.append("dependency_manifest")
        is_dependency_surface = True

    if file_name in LOCKFILE_NAMES:
        signals.append("lockfile")
        is_dependency_surface = True

    if _is_infrastructure_path(path, allow_suffix_match=not is_dependency_surface):
        signals.append("infrastructure")

    if any(hint in normalized_path for hint in PRODUCTION_PATH_HINTS):
        signals.append("production_surface")
    if any(hint in normalized_path for hint in PUBLIC_EXPOSURE_HINTS):
        signals.append("public_exposure_surface")
    if any(hint in normalized_path for hint in SHARED_PLATFORM_HINTS):
        signals.append("shared_platform_surface")
    if any(hint in normalized_path for hint in DATABASE_MIGRATION_HINTS):
        signals.append("database_migration_surface")
    if any(hint in normalized_path for hint in PAYMENTS_HINTS):
        signals.append("payments_surface")
    if any(hint in normalized_path for hint in AUTH_HINTS):
        signals.append("auth_surface")
    if any(hint in normalized_path for hint in DATA_HINTS):
        signals.append("data_surface")
    if _has_healthcheck_risk(added_lower, removed_lower):
        signals.append("healthcheck_risk_surface")
    if _has_direct_rollout_signal(added_lower):
        signals.append("direct_rollout_surface")
    if _has_autoscaling_signal(normalized_path, added_lower, removed_lower):
        signals.append("autoscaling_surface")
    if _has_privileged_container_signal(added_lower):
        signals.append("privileged_container_surface")
    if _has_broad_iam_signal(normalized_path, added_lower):
        signals.append("broad_iam_surface")
    if _has_resource_limit_risk(added_lower, removed_lower):
        signals.append("resource_limit_risk_surface")

    if not signals:
        signals.append("application_code")

    if "application_code" not in signals and not {"dependency_manifest", "lockfile", "infrastructure"} & set(signals):
        signals.append("application_code")

    return tuple(dict.fromkeys(signals))


def _is_infrastructure_path(path: str, *, allow_suffix_match: bool) -> bool:
    if allow_suffix_match and path.endswith(IAC_SUFFIXES):
        return True
    if any(hint in path for hint in IAC_PATH_HINTS):
        return path.endswith((".yaml", ".yml", ".json", ".tf", ".tfvars")) or ".github/workflows/" in path
    return False


def _has_healthcheck_risk(added_lines: tuple[str, ...], removed_lines: tuple[str, ...]) -> bool:
    probe_markers = ("livenessprobe", "readinessprobe", "startupprobe", "healthcheck")
    removed_probe = any(any(marker in line for marker in probe_markers) for line in removed_lines)
    added_probe = any(any(marker in line for marker in probe_markers) for line in added_lines)
    return removed_probe and not added_probe


def _has_direct_rollout_signal(added_lines: tuple[str, ...]) -> bool:
    direct_markers = (
        "type: recreate",
        "maxunavailable: 100%",
        "maxsurge: 100%",
    )
    return any(any(marker in line for marker in direct_markers) for line in added_lines)


def _has_autoscaling_signal(
    normalized_path: str,
    added_lines: tuple[str, ...],
    removed_lines: tuple[str, ...],
) -> bool:
    if any(token in normalized_path for token in ("hpa", "autoscaler", "autoscaling")):
        return True
    markers = ("minreplicas", "maxreplicas", "targetcpuutilizationpercentage", "targetmemoryutilizationpercentage")
    combined = added_lines + removed_lines
    return any(any(marker in line for marker in markers) for line in combined)


def _has_privileged_container_signal(added_lines: tuple[str, ...]) -> bool:
    markers = (
        "privileged: true",
        "allowprivilegeescalation: true",
        "hostnetwork: true",
        "hostpid: true",
        "runasuser: 0",
        "capabilities:",
        "add:",
    )
    return any(any(marker in line for marker in markers) for line in added_lines)


def _has_broad_iam_signal(normalized_path: str, added_lines: tuple[str, ...]) -> bool:
    if not any(token in normalized_path for token in ("iam", "policy", "role", "terraform/", ".github/workflows/")):
        return False
    markers = (
        "administratoraccess",
        '"action": "*"',
        "action = \"*\"",
        "iam:*",
        '"resource": "*"',
        "resource = \"*\"",
    )
    return any(any(marker in line for marker in markers) for line in added_lines)


def _has_resource_limit_risk(added_lines: tuple[str, ...], removed_lines: tuple[str, ...]) -> bool:
    removed_limits = any("limits:" in line or "requests:" in line for line in removed_lines)
    added_limits = any("limits:" in line or "requests:" in line for line in added_lines)
    return removed_limits and not added_limits
