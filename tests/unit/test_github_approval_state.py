import json

from veridion.action import github_approval_state
from veridion.action.github_approvals import ApprovalMap, ReviewerTarget


def test_evaluate_required_approval_state_returns_not_required_when_no_roles() -> None:
    result = github_approval_state.evaluate_required_approval_state(
        repository="acme/veridion",
        pull_request_number=7,
        github_token="token",
        required_approvals=(),
        approval_map=ApprovalMap(roles={}),
    )

    assert result.status == "not_required"
    assert result.approvals_satisfied is True
    assert result.role_states == ()


def test_evaluate_required_approval_state_marks_user_role_satisfied(monkeypatch) -> None:
    monkeypatch.setattr(
        github_approval_state,
        "_fetch_pull_request_reviews",
        lambda **kwargs: (
            github_approval_state.ReviewRecord(reviewer="alice", state="APPROVED"),
        ),
    )

    result = github_approval_state.evaluate_required_approval_state(
        repository="acme/veridion",
        pull_request_number=7,
        github_token="token",
        required_approvals=("security_owner",),
        approval_map=ApprovalMap(
            roles={"security_owner": ReviewerTarget(users=("alice",))}
        ),
    )

    assert result.status == "satisfied"
    assert result.approvals_satisfied is True
    assert result.satisfied_roles == ("security_owner",)
    assert result.unsatisfied_roles == ()


def test_evaluate_required_approval_state_marks_team_role_satisfied_from_member_review(monkeypatch) -> None:
    monkeypatch.setattr(
        github_approval_state,
        "_fetch_pull_request_reviews",
        lambda **kwargs: (
            github_approval_state.ReviewRecord(reviewer="bob", state="APPROVED"),
        ),
    )
    monkeypatch.setattr(
        github_approval_state,
        "_fetch_team_members",
        lambda **kwargs: ("bob", "carol"),
    )

    result = github_approval_state.evaluate_required_approval_state(
        repository="acme/veridion",
        pull_request_number=7,
        github_token="token",
        required_approvals=("platform_owner",),
        approval_map=ApprovalMap(
            roles={"platform_owner": ReviewerTarget(teams=("platform-team",))}
        ),
    )

    assert result.status == "satisfied"
    assert result.role_states[0].approved_by == ("bob",)


def test_evaluate_required_approval_state_tracks_pending_and_unmapped_roles(monkeypatch) -> None:
    monkeypatch.setattr(github_approval_state, "_fetch_pull_request_reviews", lambda **kwargs: ())
    monkeypatch.setattr(github_approval_state, "_fetch_team_members", lambda **kwargs: ("bob",))

    result = github_approval_state.evaluate_required_approval_state(
        repository="acme/veridion",
        pull_request_number=7,
        github_token="token",
        required_approvals=("platform_owner", "security_owner"),
        approval_map=ApprovalMap(
            roles={"platform_owner": ReviewerTarget(teams=("platform-team",))}
        ),
    )

    assert result.status == "unmapped"
    assert result.approvals_satisfied is False
    assert result.unsatisfied_roles == ("platform_owner", "security_owner")
    assert result.role_states[0].status == "pending"
    assert result.role_states[1].status == "unmapped"


def test_enrich_decision_contract_adds_approval_state() -> None:
    contract = {"automation": {"comment_identifier": "veridion:rdi"}}
    result = github_approval_state.ApprovalSatisfactionResult(
        status="pending",
        approvals_satisfied=False,
        satisfied_roles=("platform_owner",),
        unsatisfied_roles=("security_owner",),
        role_states=(
            github_approval_state.ApprovalRoleState(role="platform_owner", status="satisfied", approved_by=("alice",)),
            github_approval_state.ApprovalRoleState(role="security_owner", status="pending", pending_users=("bob",)),
        ),
    )

    enriched = github_approval_state.enrich_decision_contract(contract, result)

    assert enriched["automation"]["approval_satisfaction_status"] == "pending"
    assert enriched["automation"]["approvals_satisfied"] is False
    assert enriched["automation"]["satisfied_approvals"] == ["platform_owner"]
    assert enriched["automation"]["unsatisfied_approvals"] == ["security_owner"]


def test_evaluate_approval_gate_blocks_unsatisfied_required_approvals() -> None:
    result = github_approval_state.ApprovalSatisfactionResult(
        status="pending",
        approvals_satisfied=False,
        satisfied_roles=(),
        unsatisfied_roles=("security_owner",),
        role_states=(),
    )

    gate = github_approval_state.evaluate_approval_gate(result, enforce=True)

    assert gate.status == "blocked"
    assert gate.allowed is False


def test_enrich_decision_contract_with_approval_gate_adds_gate_fields() -> None:
    contract = {"automation": {}}
    enriched = github_approval_state.enrich_decision_contract_with_approval_gate(
        contract,
        github_approval_state.ApprovalGateEvaluation(status="blocked", allowed=False),
    )

    assert enriched["automation"]["approval_gate_status"] == "blocked"
    assert enriched["automation"]["approval_gate_allowed"] is False


def test_write_github_outputs_emits_approval_state(tmp_path, monkeypatch) -> None:
    output_path = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    github_approval_state._write_github_outputs(
        github_approval_state.ApprovalSatisfactionResult(
            status="pending",
            approvals_satisfied=False,
            satisfied_roles=("platform_owner",),
            unsatisfied_roles=("security_owner",),
            role_states=(
                github_approval_state.ApprovalRoleState(role="platform_owner", status="satisfied", approved_by=("alice",)),
            ),
        ),
        github_approval_state.ApprovalGateEvaluation(status="blocked", allowed=False),
    )

    content = output_path.read_text()
    assert "approval_satisfaction_status=pending" in content
    assert "approvals_satisfied=false" in content
    assert "approval_gate_status=blocked" in content
    assert "approval_gate_allowed=false" in content
    satisfied_line = next(line for line in content.splitlines() if line.startswith("satisfied_approvals_json="))
    assert json.loads(satisfied_line.split("=", maxsplit=1)[1]) == ["platform_owner"]
