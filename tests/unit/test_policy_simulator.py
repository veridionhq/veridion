import json
from pathlib import Path

from veridion.policy.simulator import main


def test_policy_simulator_compares_named_policy_sets(tmp_path) -> None:
    diff_path = tmp_path / "pr.diff"
    diff_path.write_text(
        "diff --git a/requirements.txt b/requirements.txt\n"
        "index 1111111..2222222 100644\n"
        "--- a/requirements.txt\n"
        "+++ b/requirements.txt\n"
        "@@ -1 +1 @@\n"
        "-urllib3==2.2.2\n"
        "+urllib3==1.25.8\n"
    )
    app_policy = tmp_path / "app.yaml"
    app_policy.write_text(
        "policy_pack_id: app-team\n"
        "policy_pack_name: Application Team\n"
        "policy_pack_version: 1\n"
        "policy_pack_owner: appsec\n"
        "policy_rollout_stage: general\n"
        "max_severity: critical\n"
        "allow_conditional: true\n"
        "no_go_below_score: 60\n"
        "conditional_go_below_score: 85\n"
    )
    strict_policy = tmp_path / "strict.yaml"
    strict_policy.write_text(
        "policy_pack_id: strict\n"
        "policy_pack_name: Strict\n"
        "policy_pack_version: 1\n"
        "policy_pack_owner: platform-trust\n"
        "policy_rollout_stage: pilot\n"
        "max_severity: high\n"
        "allow_conditional: false\n"
        "no_go_below_score: 90\n"
        "conditional_go_below_score: 95\n"
    )
    trivy_path = tmp_path / "trivy.json"
    trivy_path.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Class": "lang-pkgs",
                        "Type": "pip",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2025-99999",
                                "PkgName": "urllib3",
                                "InstalledVersion": "1.25.8",
                                "Title": "Temporary dependency issue",
                                "Severity": "HIGH",
                            }
                        ],
                    }
                ]
            }
        )
    )
    output_path = tmp_path / "simulation.json"

    exit_code = main(
        [
            "--diff-path",
            str(diff_path),
            "--report",
            f"trivy={trivy_path}",
            "--policy-set",
            f"app={app_policy}",
            "--policy-set",
            f"strict={strict_policy}",
            "--output-path",
            str(output_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    assert payload["schema_version"] == 1
    assert {item["name"] for item in payload["results"]} == {"app", "strict"}
    assert payload["results"][0]["policy_pack"]["pack_id"]
