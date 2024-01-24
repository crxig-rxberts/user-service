resource "nomad_job" "service" {
  jobspec = templatefile("files/job/service.hcl", {
    active_spring_profiles = var.active_spring_profiles
    #    dd_agent_host              = var.dd_agent_host
    #    dd_profiling_enabled       = var.dd_profiling_enabled
    #    dd_runtime_metrics_enabled = var.dd_runtime_metrics_enabled
    env_name         = var.env_name
    health_endpoint  = var.health_endpoint
    image            = "${var.image_name}:${var.image_version}"
    image_version    = var.image_version
    resource_cpu     = var.resource_cpu
    resource_memory  = var.resource_memory
    resource_network = var.resource_network
    service_count    = var.service_count
    service_name     = var.service_name
    service_name_fq  = var.service_name_fq
  })

  detach = false
}
