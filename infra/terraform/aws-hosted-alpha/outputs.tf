output "alb_dns_name" {
  value = aws_lb.service.dns_name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "service_name" {
  value = aws_ecs_service.service.name
}

output "worker_service_name" {
  value = aws_ecs_service.worker.name
}

output "migrate_task_definition_arn" {
  value = aws_ecs_task_definition.migrate.arn
}

output "db_endpoint" {
  value = aws_db_instance.postgres.address
}

output "materialization_bucket" {
  value = local.materialization_bucket
}

output "efs_id" {
  value = aws_efs_file_system.materializations.id
}
