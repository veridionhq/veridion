import pytest

from veridion.action.bootstrap import build_bootstrap_files, write_bootstrap_files


def test_build_bootstrap_files_scaffolds_expected_paths() -> None:
    files = build_bootstrap_files(
        preset="application-team",
        action_ref="veridionhq/veridion@main",
        repo_id="acme/payments-platform",
        service_id="payments/api",
        team_id="platform-trust",
    )

    assert set(files) == {
        ".veridion/policy.yaml",
        ".veridion/suppressions.json",
        ".veridion/README.md",
        ".github/workflows/veridion-rdi.yml",
    }
    assert "require_approval_for:" in files[".veridion/policy.yaml"]
    assert '"schema_version": 1' in files[".veridion/suppressions.json"]
    assert "uses: veridionhq/veridion@main" in files[".github/workflows/veridion-rdi.yml"]
    assert "policy-path: .veridion/policy.yaml" in files[".github/workflows/veridion-rdi.yml"]
    assert "suppression-path: .veridion/suppressions.json" in files[".github/workflows/veridion-rdi.yml"]
    assert "scan-metadata-path: veridion-scan-metadata.json" in files[".github/workflows/veridion-rdi.yml"]
    assert "scanner_versions" in files[".github/workflows/veridion-rdi.yml"]
    assert "PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in files[".github/workflows/veridion-rdi.yml"]
    assert "PR_BRANCH: ${{ github.head_ref || github.ref_name }}" in files[".github/workflows/veridion-rdi.yml"]
    assert '"branch": "${{ github.head_ref || github.ref_name }}"' not in files[".github/workflows/veridion-rdi.yml"]
    assert "cat > veridion-scan-metadata.json <<EOF" not in files[".github/workflows/veridion-rdi.yml"]
    assert "Clean up baseline worktree" in files[".github/workflows/veridion-rdi.yml"]
    assert "Show Veridion decision" in files[".github/workflows/veridion-rdi.yml"]
    assert "trust-profile-source-path" not in files[".github/workflows/veridion-rdi.yml"]
    assert "approval-map-path" not in files[".github/workflows/veridion-rdi.yml"]
    assert 'request-approvals: "true"' not in files[".github/workflows/veridion-rdi.yml"]
    assert 'verify-approvals: "true"' not in files[".github/workflows/veridion-rdi.yml"]
    assert "decision-contract-path: veridion-decision.json" in files[".github/workflows/veridion-rdi.yml"]
    assert "semgrep" not in files[".github/workflows/veridion-rdi.yml"].lower()
    assert "Repo: acme/payments-platform" in files[".veridion/README.md"]
    assert "Service: payments/api" in files[".veridion/README.md"]
    assert "Team: platform-trust" in files[".veridion/README.md"]
    assert "reason_type" in files[".veridion/README.md"]
    assert "Do not add operational context" in files[".veridion/README.md"]


def test_dependency_risk_v1_preset_stays_narrow() -> None:
    files = build_bootstrap_files(preset="dependency-risk-v1")

    policy = files[".veridion/policy.yaml"]
    assert "require_approval_for: []" in policy
    assert "require_platform_owner_for: []" in policy
    assert "require_service_owner_for: []" in policy
    assert "require_sre_owner_for: []" in policy
    assert "require_security_owner_for: []" in policy
    assert "condition_on_release_controls: false" in policy
    assert "  - production_iac" not in policy
    assert "dependency_reputation_risk" not in policy
    assert "ai_signal_score_penalty" not in policy


def test_build_bootstrap_files_rejects_unknown_preset() -> None:
    with pytest.raises(ValueError, match=r"unsupported preset: unknown"):
        build_bootstrap_files(preset="unknown")


def test_write_bootstrap_files_writes_and_protects_existing_files(tmp_path) -> None:
    files = {
        ".veridion/policy.yaml": "hello\n",
        ".github/workflows/veridion-rdi.yml": "world\n",
    }

    write_bootstrap_files(output_root=str(tmp_path), files=files, force=False)

    assert (tmp_path / ".veridion/policy.yaml").read_text() == "hello\n"
    assert (tmp_path / ".github/workflows/veridion-rdi.yml").read_text() == "world\n"

    with pytest.raises(RuntimeError, match=r"--force"):
        write_bootstrap_files(output_root=str(tmp_path), files=files, force=False)

    write_bootstrap_files(output_root=str(tmp_path), files=files, force=True)


def test_write_bootstrap_files_can_update_only_workflow(tmp_path) -> None:
    files = {
        ".veridion/policy.yaml": "policy-v1\n",
        ".veridion/suppressions.json": '{"schema_version": 1, "suppressions": [{"rule_id": "keep"}]}\n',
        ".veridion/README.md": "readme-v1\n",
        ".github/workflows/veridion-rdi.yml": "workflow-v1\n",
    }
    write_bootstrap_files(output_root=str(tmp_path), files=files)

    updated = {
        ".veridion/policy.yaml": "policy-v2\n",
        ".veridion/suppressions.json": '{"schema_version": 1, "suppressions": []}\n',
        ".veridion/README.md": "readme-v2\n",
        ".github/workflows/veridion-rdi.yml": "workflow-v2\n",
    }
    write_bootstrap_files(output_root=str(tmp_path), files=updated, force=True, only={"workflow"})

    assert (tmp_path / ".veridion/policy.yaml").read_text() == "policy-v1\n"
    assert "keep" in (tmp_path / ".veridion/suppressions.json").read_text()
    assert (tmp_path / ".veridion/README.md").read_text() == "readme-v1\n"
    assert (tmp_path / ".github/workflows/veridion-rdi.yml").read_text() == "workflow-v2\n"
