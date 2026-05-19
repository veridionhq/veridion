output "alb_dns_name" {
  value = aws_lb.service.dns_name
}

output "vpc_id" {
  value = local.chosen_vpc_id
}

output "public_subnet_ids" {
  value = local.public_subnet_ids
}

output "private_subnet_ids" {
  value = local.private_subnet_ids
}

output "ecs_task_subnet_ids" {
  value = local.ecs_task_subnet_ids
}

output "ecs_assign_public_ip" {
  value = local.ecs_assign_public_ip ? "ENABLED" : "DISABLED"
}

output "ecs_security_group_id" {
  value = aws_security_group.ecs.id
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

output "container_image" {
  value = local.container_image
}

output "ecr_repository_url" {
  value = var.create_ecr_repository ? aws_ecr_repository.app[0].repository_url : ""
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
