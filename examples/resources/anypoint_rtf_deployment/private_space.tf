# CloudHub 2.0 private space on usage-based pricing: size replicas with
# instance_type and omit the resources block.
resource "anypoint_rtf_deployment" "private_space" {
  org_id = var.root_org
  env_id = var.env_id
  name   = "your-awesome-app"
  application {
    desired_state = "STARTED"
    ref {
      group_id    = var.root_org
      artifact_id = "your-artifact-id"
      version     = "1.0.2"
      packaging   = "jar"
    }
    configuration {
      mule_agent_app_props_service {
        properties = {
          props1 = "value01"
        }
      }
      mule_agent_logging_service {
        scope_logging_configurations {
          scope     = "mule.package"
          log_level = "INFO"
        }
      }
    }
  }

  target {
    provider  = "MC"
    target_id = var.private_space_id
    replicas  = 1
    deployment_settings {
      instance_type = "mule.nano"
      runtime {
        version = "4.8.5:4e-java8"
      }
    }
  }
}
