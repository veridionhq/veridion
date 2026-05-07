from veridion.change_context import parse_unified_diff


def test_plain_yaml_and_json_configs_are_not_classified_as_infrastructure() -> None:
    diff = """\
diff --git a/config/api_config.yaml b/config/api_config.yaml
--- a/config/api_config.yaml
+++ b/config/api_config.yaml
@@ -1 +1 @@
-debug: false
+debug: true
diff --git a/config/schema.json b/config/schema.json
--- a/config/schema.json
+++ b/config/schema.json
@@ -1 +1 @@
-{"version": 1}
+{"version": 2}
"""

    context = parse_unified_diff(diff)

    assert context.has_iac_changes is False
    assert tuple(file.signals for file in context.files) == (
        ("application_code",),
        ("application_code",),
    )
