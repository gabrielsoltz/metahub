dashboard "resources" {
  text {
<<<<<<< Updated upstream
    value = "## MetaHub: Resources | [Findings](${var.host}/metahub.dashboard.findings) | [Accounts](${var.host}/metahub.dashboard.accounts)"
=======
    value = "## MetaHub: Resources | [Findings](${var.host}/metahub.dashboard.findings) | [Accounts](${var.host}/metahub.dashboard.accounts) | [Access](${var.host}/metahub.dashboard.access) | [Exposure](${var.host}/metahub.dashboard.exposure)"
>>>>>>> Stashed changes
  }

  container {
    card {
      title = "Exposure"
      query = query.count_exposure
      width = 2
      args = {
        exposure = "effectively-public"
      }
      href  = "/metahub.dashboard.resources?input.exposure=effectively-public"
    }

    card {
      title = "Access"
      query = query.count_access
      width = 2
      args = {
        access = "unrestricted"
      }
      href  = "/metahub.dashboard.resources?input.access=unrestricted"
    }

    card {
      title = "Encryption"
      query = query.count_encryption
      width = 2
      type  = "info"
      args = {
        encryption = "unencrypted"
      }
      href  = "/metahub.dashboard.resources?input.encryption=unencrypted"
    }

    card {
      title = "Status"
      query = query.count_status
      width = 2
      type  = "info"
      args = {
        status = "not-attached"
      }
      href  = "/metahub.dashboard.resources?input.status=not-attached"
    }

    card {
      title = "Severity"
      query = query.count_severity
      width = 2
      type  = "info"
      args = {
        severity = "CRITICAL"
      }
      href  = "/metahub.dashboard.resources?input.severity=CRITICAL"
    }

    card {
      title = "Environment"
      query = query.count_environment
      width = 2
      type  = "info"
      args = {
        environment = "production"
      }
      href  = "/metahub.dashboard.resources?input.environment=production"
    }
  }

  # Container for charts is commented out. If needed, uncomment and review for use.
  # container {
  #   chart {
  #     query = query.group_exposure
  #     width = 2
  #     type  = "pie"
  #   }

  #   chart {
  #     query = query.group_access
  #     width = 2
  #     type  = "donut"
  #   }

  #   chart {
  #     query = query.group_encryption
  #     width = 2
  #     type  = "donut"
  #   }

  #   chart {
  #     query = query.group_status
  #     width = 2
  #     type  = "donut"
  #   }

  #   chart {
  #     query = query.group_severity
  #     width = 2
  #     type  = "donut"
  #   }

  #   chart {
  #     query = query.group_environment
  #     width = 2
  #     type  = "donut"
  #   }
  # }

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

query "resources" {
  sql = <<-EOQ
    select
      resource_arn as arn,
      resource_tags ->> 'Name' as name,
      resource_type as type,
      resource_region as region,
      resource_account_id as account_id,
      resource_account_alias as account_alias,
      resource_exposure as exposure,
      resource_access as access,
      resource_encryption as encryption,
      resource_status as status,
      resource_application as application,
      resource_environment as environment,
      resource_owner as owner,
      resource_findings_critical as findings_critical,
      resource_findings_high as findings_high,
      resource_findings_medium as findings_medium,
      resource_findings_low as findings_low,
      resource_findings_informational as findings_informational,
      resource_score as score,
      resource_tags as tags
    from
      resources
    where
      ($1 = 'ALL' OR ',' || $1 || ',' LIKE '%,' || resource_exposure || ',%') AND
      ($2 = 'ALL' OR ',' || $2 || ',' LIKE '%,' || resource_access || ',%') AND
      ($3 = 'ALL' OR ',' || $3 || ',' LIKE '%,' || resource_encryption || ',%') AND
      ($4 = 'ALL' OR ',' || $4 || ',' LIKE '%,' || resource_status || ',%') AND
      CASE
          WHEN $5 = 'CRITICAL' THEN resource_findings_critical > 0
          WHEN $5 = 'HIGH' THEN resource_findings_high > 0
          WHEN $5 = 'MEDIUM' THEN resource_findings_medium > 0
          WHEN $5 = 'LOW' THEN resource_findings_low > 0
          WHEN $5 = 'INFORMATIONAL' THEN resource_findings_informational > 0
          ELSE 1 --
      END AND
      ($6 = 'ALL' OR ',' || $6 || ',' LIKE '%,' || resource_environment || ',%') AND
      ($7 = 'ALL' OR ',' || $7 || ',' LIKE '%,' || resource_owner || ',%') AND
      ($8 = 'ALL' OR ',' || $8 || ',' LIKE '%,' || resource_application || ',%') AND
      ($9 = 'ALL' OR ',' || $9 || ',' LIKE '%,' || resource_account_id || ',%') AND
      ($10 = 'ALL' OR ',' || $10 || ',' LIKE '%,' || resource_type || ',%') AND
      ($11 = 'ALL' OR ',' || $11 || ',' LIKE '%,' || resource_region || ',%') AND
      ($12 = 'ALL' OR json_extract(resource_tags, '$."' || SUBSTR($12, 1, INSTR($12, ':') - 1) || '"') = SUBSTR($12, INSTR($12, ':') + 1))
  EOQ

  param "exposure" {}
  param "access" {}
  param "encryption" {}
  param "status" {}
  param "severity" {}
  param "environment" {}
  param "owner" {}
  param "application" {}
  param "account" {}
  param "type" {}
  param "region" {}
  param "tags" {}
}

query "count_exposure" {
  sql = <<-EOQ
    select
      $1 as label,
      count(*) as value,
      case
        when $1 = 'unknown' then 'info'
        when $1 = 'restricted' then 'ok'
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    where
      resource_exposure = $1
  EOQ

  param "exposure" {}
}

query "count_access" {
  sql = <<-EOQ
    select
      $1 as label,
      count(*) as value,
      case
        when $1 = 'unknown' then 'info'
        when $1 = 'restricted' then 'ok'
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    where
      resource_access = $1
  EOQ
  param "access" {}
}

query "count_encryption" {
  sql = <<-EOQ
    select
      $1 as label,
      count(*) as value,
      case
        when $1 = 'unknown' then 'info'
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    where
      resource_encryption = $1
  EOQ
  param "encryption" {}
}

query "count_status" {
  sql = <<-EOQ
    select
      $1 as label,
      count(*) as value,
      case
        when $1 = 'unknown' then 'info'
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    where
      resource_status = $1
  EOQ
  param "status" {}
}

query "count_environment" {
  sql = <<-EOQ
    select
      $1 as label,
      count(*) as value,
      case
        when $1 = 'unknown' then 'info'
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    where
      resource_environment = $1
  EOQ
  param "environment" {}
}

query "group_exposure" {
  sql = <<-EOQ
    select
      resource_exposure as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    group by
      resource_exposure
  EOQ
}

query "group_access" {
  sql = <<-EOQ
    select
      resource_access as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    group by
      resource_access
  EOQ
}

query "group_encryption" {
  sql = <<-EOQ
    select
      resource_encryption as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    group by
      resource_encryption
  EOQ
}

query "group_status" {
  sql = <<-EOQ
    select
      resource_status as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    group by
      resource_status
  EOQ
}

query "group_environment" {
  sql = <<-EOQ
    select
      resource_environment as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      resources
    group by
      resource_environment
  EOQ
}
