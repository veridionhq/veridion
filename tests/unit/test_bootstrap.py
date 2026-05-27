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
        ".veridion/trust-profile.source.json",
        ".veridion/trust-catalog.source.json",
        ".veridion/suppressions.json",
        ".veridion/approval-map.json",
        ".github/workflows/veridion-rdi.yml",
    }
    assert "require_approval_for:" in files[".veridion/policy.yaml"]
    assert '"repo_id": "acme/payments-platform"' in files[".veridion/trust-profile.source.json"]
    assert '"schema_version": 1' in files[".veridion/suppressions.json"]
    assert '"platform_owner"' in files[".veridion/approval-map.json"]
    assert "uses: veridionhq/veridion@main" in files[".github/workflows/veridion-rdi.yml"]
    assert "policy-path: .veridion/policy.yaml" in files[".github/workflows/veridion-rdi.yml"]
    assert "suppression-path: .veridion/suppressions.json" in files[".github/workflows/veridion-rdi.yml"]
    assert "approval-map-path: .veridion/approval-map.json" in files[".github/workflows/veridion-rdi.yml"]
    assert 'request-approvals: "true"' in files[".github/workflows/veridion-rdi.yml"]
    assert 'verify-approvals: "true"' in files[".github/workflows/veridion-rdi.yml"]
    assert "decision-contract-path: veridion-decision.json" in files[".github/workflows/veridion-rdi.yml"]
    assert "semgrep" not in files[".github/workflows/veridion-rdi.yml"].lower()


def test_dependency_risk_v1_preset_stays_narrow() -> None:
    files = build_bootstrap_files(preset="dependency-risk-v1")

    policy = files[".veridion/policy.yaml"]
    assert "  - dependency_changes" in policy
    assert "require_platform_owner_for: []" in policy
    assert "require_service_owner_for: []" in policy
    assert "require_sre_owner_for: []" in policy
    assert "  - production_iac" not in policy
    assert "ai_signal_score_penalty: 0" in policy


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

    with pytest.raises(RuntimeError, match=r"refusing to overwrite existing file"):
        write_bootstrap_files(output_root=str(tmp_path), files=files, force=False)

    write_bootstrap_files(output_root=str(tmp_path), files=files, force=True)
