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

variable "ecr_repository_name" {
  type    = string
  default = ""
}

variable "create_network" {
  type    = bool
  default = true
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

variable "tenants_json" {
  type = string
}

variable "schedules_json" {
  type    = string
  default = "[]"
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
  default = 512
}

variable "service_memory" {
  type    = number
  default = 1024
}

variable "worker_cpu" {
  type    = number
  default = 512
}

variable "worker_memory" {
  type    = number
  default = 1024
}

variable "create_s3_bucket" {
  type    = bool
  default = true
}

variable "s3_bucket_name" {
  type    = string
  default = ""
}
