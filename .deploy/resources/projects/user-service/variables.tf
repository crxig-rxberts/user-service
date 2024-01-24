variable "active_spring_profiles" { type = string }
variable "env_name" { type = string }
variable "health_endpoint" { type = string }
variable "image_name" { type = string }
variable "image_version" { type = string }
variable "resource_cpu" { type = string }
variable "resource_memory" { type = string }
variable "resource_network" { type = string }
variable "service_count" { type = number }
variable "service_name" { type = string }
variable "service_name_fq" { type = string }
variable "region" { type = string }
variable "tfstate_env" { type = string }
variable "tfstate_bucket" { type = string }

locals {
  service_name_fq = "${var.service_name}${var.env_name}"
}
