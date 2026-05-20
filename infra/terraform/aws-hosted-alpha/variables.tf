variable "aws_region" {
  type = string
}

variable "name" {
  type    = string
  default = "veridion-alpha"
}

variable "vpc_id" {
  type    = string
  default = ""
}

variable "public_subnet_ids" {
  type    = list(string)
  default = []
}

variable "private_subnet_ids" {
  type    = list(string)
  default = []
}

variable "container_image" {
  type    = string
  default = ""
}

variable "container_image_tag" {
  type    = string
  default = "alpha"
}

variable "create_ecr_repository" {
  type    = bool
  default = true
}

variable "create_github_actions_oidc_role" {
  type    = bool
  default = true
}

variable "create_github_actions_deploy_role" {
  type    = bool
  default = true
}

variable "create_github_oidc_provider" {
  type    = bool
  default = true
}

variable "github_oidc_provider_arn" {
  type    = string
  default = ""
}

variable "github_repository" {
  type    = string
  default = "veridionhq/veridion"
}

variable "github_allowed_branches" {
  type    = list(string)
  default = ["develop", "main"]
}

variable "ecr_repository_name" {
  type    = string
  default = ""
}

variable "ecr_expire_untagged_after_days" {
  type    = number
  default = 1
}

variable "alb_target_deregistration_delay_seconds" {
  type    = number
  default = 15
}

variable "alb_health_check_interval_seconds" {
  type    = number
  default = 10
}

variable "alb_health_check_healthy_threshold" {
  type    = number
  default = 1
}

variable "alb_health_check_unhealthy_threshold" {
  type    = number
  default = 2
}

variable "create_network" {
  type    = bool
  default = true
}

variable "create_nat_gateway" {
  type    = bool
  default = false
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.42.0.0/24", "10.42.1.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.42.10.0/24", "10.42.11.0/24"]
}

variable "availability_zones" {
  type    = list(string)
  default = []
}

variable "db_name" {
  type    = string
  default = "veridion_history"
}

variable "db_username" {
  type    = string
  default = "veridion"
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "jwt_issuer" {
  type    = string
  default = ""
}

variable "jwt_audience" {
  type    = string
  default = ""
}

variable "jwks_url" {
  type    = string
  default = ""
}

variable "oidc_discovery_url" {
  type    = string
  default = ""
}

variable "tenants" {
  type = list(object({
    tenant_id     = string
    display_name  = string
    history_paths = list(string)
  }))
}

variable "service_tokens" {
  type = list(object({
    token          = string
    token_id       = optional(string)
    principal_name = optional(string)
    auth_type      = optional(string)
    status         = optional(string)
    tenants        = optional(list(string))
    roles          = optional(list(string))
  }))
  default   = []
  sensitive = true
}

variable "schedules" {
  type = list(object({
    schedule_id                 = string
    cron                        = string
    tenants                     = list(string)
    athena_database             = string
    athena_table                = string
    athena_s3_location_template = string
  }))
  default = []
}

variable "service_desired_count" {
  type    = number
  default = 0
}

variable "worker_desired_count" {
  type    = number
  default = 0
}

variable "service_cpu" {
  type    = number
  default = 256
}

variable "service_memory" {
  type    = number
  default = 512
}

variable "worker_cpu" {
  type    = number
  default = 256
}

variable "worker_memory" {
  type    = number
  default = 512
}

variable "ecs_tasks_in_public_subnets" {
  type    = bool
  default = true
}

variable "log_retention_in_days" {
  type    = number
  default = 7
}

variable "create_s3_bucket" {
  type    = bool
  default = true
}

variable "s3_bucket_name" {
  type    = string
  default = ""
}
