# Stub of root/gcp for testing the PR pipeline. No providers, no real systems:
# it reads the persona the same way the real root does, so the speculative plan
# changes whenever a persona changes.
#
# Org, workspace and host come from TF_CLOUD_ORGANIZATION, TF_WORKSPACE and
# TF_CLOUD_HOSTNAME (set by the workflow), so nothing is hardcoded here.
terraform {
  required_version = ">= 1.6.0"

  cloud {}
}

variable "persona_dir" {
  description = "Path to the persona folder, relative to root/gcp/."
  type        = string
  default     = "../../personas/test/demo"
}

locals {
  persona = yamldecode(file("${path.module}/${var.persona_dir}/config.yaml"))
  grant   = local.persona.entitlement.gcp.grants[0]
  group   = upper("${local.persona.org}-${local.persona.team}-gcp-${local.grant.permission_set.name}")
}

resource "terraform_data" "group" {
  input = {
    group    = local.group
    projects = local.grant.assign_by.projects
    roles    = try(local.grant.permission_set.builtin_roles, [])
  }
}

output "okta_group_name" {
  value = local.group
}
