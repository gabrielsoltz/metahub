dashboard "exposure" {
  text {
    value = "## MetaHub: [Resources](${var.host}/metahub.dashboard.resources) | [Findings](${var.host}/metahub.dashboard.findings) | [Accounts](${var.host}/metahub.dashboard.accounts) | [Access](${var.host}/metahub.dashboard.access) | Exposure"
  }

  container {
    card {
      query = query.count_exposure
      width = 4
      args = {
        exposure = "effectively-public"
      }
      href  = "/metahub.dashboard.exposure?input.exposure=effectively-public"
    }
    card {
      query = query.count_exposure
      width = 4
      args = {
        exposure = "restricted-public"
      }
      href  = "/metahub.dashboard.exposure?input.exposure=restricted-public"
    }
    card {
      query = query.count_exposure
      width = 4
      args = {
        exposure = "unrestricted-private"
      }
      href  = "/metahub.dashboard.exposure?input.exposure=unrestricted-private"
    }
    card {
      query = query.count_exposure
      width = 4
      args = {
        exposure = "launch-public"
      }
      href  = "/metahub.dashboard.exposure?input.exposure=launch-public"
    }
    card {
      query = query.count_exposure
      width = 4
      args = {
        exposure = "restricted"
      }
      href  = "/metahub.dashboard.exposure?input.exposure=restricted"
    }
    card {
      query = query.count_exposure
      width = 4
      type = "ok"
      args = {
        exposure = "unknown"
      }
      href  = "/metahub.dashboard.exposure?input.exposure=unknown"
    }
  }

  container {
    input "exposure" {
      base = metahub.input.exposure
    }

    input "access" {
      base = metahub.input.exposure
    }

    input "encryption" {
      base = metahub.input.encryption
    }

    input "status" {
      base = metahub.input.status
    }

    input "severity" {
      base = metahub.input.severity
    }

    input "environment" {
      base = metahub.input.environment
    }
  }

  container {
    input "owner" {
      base = metahub.input.owner
    }

    input "application" {
      base = metahub.input.application
    }

    input "account" {
      base = metahub.input.account
    }

    input "type" {
      base = metahub.input.type
    }

    input "region" {
      base = metahub.input.region
    }

    input "tags" {
      base = metahub.input.tags
    }
  }

  container {
    table {
      query = query.resources
      args = {
        exposure    = self.input.exposure.value
        access      = self.input.access.value
        encryption  = self.input.encryption.value
        status      = self.input.status.value
        severity    = self.input.severity.value
        environment = self.input.environment.value
        owner       = self.input.owner.value
        application = self.input.application.value
        account     = self.input.account.value
        type        = self.input.type.value
        region      = self.input.region.value
        tags        = self.input.tags.value
      }
      column "name" {
        href = "${dashboard.findings.url_path}?input.resource_arn={{.'resource_arn' | @uri}}"
      }
      column "resource_arn" {
        href = "${dashboard.findings.url_path}?input.resource_arn={{.'resource_arn' | @uri}}"
      }
    }
  }
}