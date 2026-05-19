variable "aws_region" {
  type = string
}

variable "name" {
  type    = string
  default = "veridion-alpha"
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "container_image" {
  type = string
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
  default = 1
}

variable "worker_desired_count" {
  type    = number
  default = 1
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
