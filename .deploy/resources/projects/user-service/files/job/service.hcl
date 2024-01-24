job "${service_name_fq}" {
  datacenters = ["dc1"]
  type        = "service"

  update {
    max_parallel      = 1
    min_healthy_time  = "10s"
    healthy_deadline  = "3m"
    progress_deadline = "0"
    auto_revert       = true
    canary            = 0
  }

  migrate {
    max_parallel     = 1
    health_check     = "checks"
    min_healthy_time = "10s"
    healthy_deadline = "5m"
  }

  group "${service_name_fq}" {
    count = "${service_count}"

    restart {
      attempts = 2
      interval = "30m"
      delay    = "15s"
      mode     = "fail"
    }

    task "${service_name_fq}" {
      driver = "docker"

      config {
        image = "${image}"

        port_map {
          http = "${port}"
        }

        logging {
          type = "journald"

          config {
            tag = "${service_name}"
          }
        }

        labels {
        }
      }

      resources {
        cpu    = "${resource_cpu}"
        memory = "${resource_memory}"

        network {
          port  "http"{}
        }
      }

      service {
        name = "${service_name_fq}"
        tags = ["traefik.tags=public"]
        port = "http"

        check {
          name     = "${service_name_fq}"
          type     = "http"
          path     = "${health_endpoint}"
          interval = "10s"
          timeout  = "2s"
        }
      }

      env {
#        DD_AGENT_HOST                          = "${dd_agent_host}"
#        DD_ENV                                 = "${env_name}"
#        DD_LOGS_INJECTION                      = "true"
#        DD_PROFILING_ENABLED                   = "${dd_profiling_enabled}"
#        DD_RUNTIME_METRICS_ENABLED             = "${dd_runtime_metrics_enabled}"
#        DD_SERVICE                             = "${service_name}"
#        DD_SERVICE_MAPPING                     = "java-aws-sdk:${service_name}-dynamodb"
#        DD_VERSION                             = "${image_version}"
        SPRING_PROFILES_ACTIVE                 = "${active_spring_profiles}"
      }
    }
  }
}
