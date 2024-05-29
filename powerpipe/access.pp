dashboard "access" {
  text {
    value = "## MetaHub: [Resources](${var.host}/metahub.dashboard.resources) | [Findings](${var.host}/metahub.dashboard.findings) | [Accounts](${var.host}/metahub.dashboard.accounts) | Access | [Exposure](${var.host}/metahub.dashboard.exposure)"
  }

  container {
    card {
      query = query.count_access
      width = 3
      args = {
        access = "unrestricted"
      }
      href  = "/metahub.dashboard.access?input.access=unrestricted"
    }
    card {
      query = query.count_access
      width = 3
      args = {
        access = "untrusted-principal"
      }
      href  = "/metahub.dashboard.access?input.access=untrusted-principal"
    }
    card {
      query = query.count_access
      width = 3
      args = {
        access = "unrestricted-principal"
      }
      href  = "/metahub.dashboard.access?input.access=unrestricted-principal"
    }
    card {
      query = query.count_access
      width = 3
      args = {
        access = "cross-account-principal"
      }
      href  = "/metahub.dashboard.access?input.access=cross-account-principal"
    }
    card {
      query = query.count_access
      width = 3
      args = {
        access = "unrestricted-actions"
      }
      href  = "/metahub.dashboard.access?input.access=unrestricted-actions"
    }
    card {
      query = query.count_access
      width = 3
      args = {
        access = "dangerous-actions"
      }
      href  = "/metahub.dashboard.access?input.access=dangerous-actions"
    }
    card {
      query = query.count_access
      width = 2
      args = {
        access = "unrestricted-service"
      }
      href  = "/metahub.dashboard.access?input.access=unrestricted-service"
    }
    card {
      query = query.count_access
      width = 2
      args = {
        access = "restricted"
      }
      href  = "/metahub.dashboard.access?input.access=restricted"
    }
    card {
      query = query.count_access
      width = 2
      type = "ok"
      args = {
        access = "unknown"
      }
      href  = "/metahub.dashboard.access?input.access=unknown"
    }
  }

  container {
    input "exposure" {
      base = metahub.input.exposure
    }

    input "access" {
      base = metahub.input.access
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