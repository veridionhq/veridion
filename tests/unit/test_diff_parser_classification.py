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


def test_change_surface_hints_are_inferred_from_sensitive_paths() -> None:
    diff = """\
diff --git a/terraform/prod/payments/ingress.tf b/terraform/prod/payments/ingress.tf
--- a/terraform/prod/payments/ingress.tf
+++ b/terraform/prod/payments/ingress.tf
@@ -1 +1 @@
-enabled = false
+enabled = true
diff --git a/alembic/versions/20260508_add_index.py b/alembic/versions/20260508_add_index.py
--- a/alembic/versions/20260508_add_index.py
+++ b/alembic/versions/20260508_add_index.py
@@ -1 +1 @@
-pass
+print("migrate")
diff --git a/platform/shared/auth/gateway.py b/platform/shared/auth/gateway.py
--- a/platform/shared/auth/gateway.py
+++ b/platform/shared/auth/gateway.py
@@ -1 +1 @@
-allow = false
+allow = true
"""

    context = parse_unified_diff(diff)

    assert context.has_iac_changes is True
    assert context.has_production_surface_changes is True
    assert context.has_public_exposure_changes is True
    assert context.has_shared_platform_changes is True
    assert context.has_database_migration_changes is True
    assert context.touches_payments_surface is True
    assert context.touches_auth_surface is True
    assert tuple(context.files[0].signals) == (
        "infrastructure",
        "production_surface",
        "public_exposure_surface",
        "payments_surface",
    )
