dashboard "findings" {
  text {
    value = "## MetaHub: [Resources](${var.host}/metahub.dashboard.resources) | Findings | [Accounts](${var.host}/metahub.dashboard.accounts) | [Access](${var.host}/metahub.dashboard.access) | [Exposure](${var.host}/metahub.dashboard.exposure)"
  }


  container {
    card {
      query = query.count_severity
      width = 2
      args = {
        severity = "ALL"
      }
    }

    card {
      query = query.count_severity
      width = 2
      args = {
        severity = "CRITICAL"
      }
    }

    card {
      query = query.count_severity
      width = 2
      args = {
        severity = "HIGH"
      }
    }

    card {
      query = query.count_severity
      width = 2
      type  = "info"
      args = {
        severity = "MEDIUM"
      }
    }

    card {
      query = query.count_severity
      width = 2
      type  = "info"
      args = {
        severity = "LOW"
      }
    }

    card {
      query = query.count_severity
      width = 2
      type  = "info"
      args = {
        severity = "INFORMATIONAL"
      }
    }
  }

  container {
    chart {
      title = "Title"
      query = query.group_title
      width = 4
      type  = "donut"
      legend {
        display  = "none"
      }
    }

    chart {
      title = "Resource ARN"
      query = query.group_resource_arn
      width = 4
      type  = "donut"
    }

    chart {
      title = "Workflow Status"
      query = query.group_workflowstatus
      width = 4
      type  = "donut"
    }

  }

  container {
    input "resource_arn" {
      type  = "multicombo"
      width = 2
      option "ALL" {
        label = "Resource ARN (ALL)"
      }
    }

    input "title" {
      type  = "multicombo"
      width = 2
      option "ALL" {
        label = "Title (ALL)"
      }
    }

    input "recordstate" {
      type  = "multiselect"
      width = 2
      option "ALL" {
        label = "Record State (ALL)"
      }
      option "ACTIVE" {}
      option "ARCHIVED" {}
    }

    input "workflowstatus" {
      type  = "multiselect"
      width = 2
      option "ALL" {
        label = "Workflow Status (ALL)"
      }
      option "NEW" {}
      option "NOTIFIED" {}
      option "RESOLVED" {}
      option "SUPPRESSED" {}
    }

    input "compliancestatus" {
      type  = "multiselect"
      width = 2
      option "ALL" {
        label = "Compliance Stat. (ALL)"
      }
      option "FAILED" {}
      option "PASSED" {}
      option "NOT_AVAILABLE" {}
    }

    input "productarn" {
      type  = "multicombo"
      width = 2
      option "ALL" {
        label = "Product ARN (ALL)"
      }
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
    table {
      query = query.findings
      args = {
        title = self.input.title
        severity = self.input.severity
        workflowstatus = self.input.workflowstatus
        recordstate = self.input.recordstate
        compliancestatus = self.input.compliancestatus
        productarn = self.input.productarn
        resource_arn = self.input.resource_arn
        exposure    = self.input.exposure
        access      = self.input.access
        encryption  = self.input.encryption
        status      = self.input.status
        environment = self.input.environment
      }
    }
  }
}

query "findings" {
  sql = <<-EOQ
    SELECT
        findings.finding_title,
        findings.finding_severity,
        findings.finding_workflowstatus,
        findings.finding_recordstate,
        findings.finding_compliancestatus,
        findings.finding_productarn,
        findings.finding_resource_arn,
        findings.finding_id,
        resources.resource_exposure,
        resources.resource_access,
        resources.resource_encryption,
        resources.resource_status,
        resources.resource_environment,
        resources.resource_owner,
        resources.resource_application,
        resources.resource_account_id,
        resources.resource_type,
        resources.resource_region,
        resources.resource_tags
    FROM
        findings
    JOIN resources ON findings.finding_resource_arn = resources.resource_arn
    WHERE
        ($1 = 'ALL' OR ',' || $1 || ',' LIKE '%,' || findings.finding_title || ',%') AND
        ($2 = 'ALL' OR ',' || $2 || ',' LIKE '%,' || findings.finding_severity || ',%') AND
        ($3 = 'ALL' OR ',' || $3 || ',' LIKE '%,' || findings.finding_workflowstatus || ',%') AND
        ($4 = 'ALL' OR ',' || $4 || ',' LIKE '%,' || findings.finding_recordstate || ',%') AND
        ($5 = 'ALL' OR ',' || $5 || ',' LIKE '%,' || findings.finding_compliancestatus || ',%') AND
        ($6 = 'ALL' OR ',' || $6 || ',' LIKE '%,' || findings.finding_productarn || ',%') AND
        ($7 = 'ALL' OR ',' || $7 || ',' LIKE '%,' || findings.finding_resource_arn || ',%') AND
        ($8 = 'ALL' OR ',' || $8 || ',' LIKE '%,' || resources.resource_exposure || ',%') AND
        ($9 = 'ALL' OR ',' || $9 || ',' LIKE '%,' || resources.resource_access || ',%') AND
        ($10 = 'ALL' OR ',' || $10 || ',' LIKE '%,' || resources.resource_encryption || ',%') AND
        ($11 = 'ALL' OR ',' || $11 || ',' LIKE '%,' || resources.resource_status || ',%') AND
        ($12 = 'ALL' OR ',' || $12 || ',' LIKE '%,' || resources.resource_environment || ',%')
  EOQ

  param "title" {}
  param "severity" {}
  param "workflowstatus" {}
  param "recordstate" {}
  param "compliancestatus" {}
  param "productarn" {}
  param "resource_arn" {}
  param "exposure" {}
  param "access" {}
  param "encryption" {}
  param "status" {}
  param "environment" {}
}

query "count_severity" {
  sql = <<-EOQ
    select
      $1 as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      findings
    where
      ($1 = 'ALL' OR ',' || $1 || ',' LIKE '%,' || finding_severity || ',%')
  EOQ
  param "severity" {}
}

query "group_workflowstatus" {
  sql = <<-EOQ
    select
      finding_workflowstatus as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      findings
    group by
      finding_workflowstatus
  EOQ
}

query "group_recordstate" {
  sql = <<-EOQ
    select
      finding_recordstate as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      findings
    group by
      finding_recordstate
  EOQ
}

query "group_title" {
  sql = <<-EOQ
    SELECT
      finding_title AS label,
      COUNT(*) AS value,
      CASE
        WHEN COUNT(*) > 0 THEN 'alert'
        ELSE 'ok'
      END AS type
    FROM
      findings
    GROUP BY
      finding_title
    ORDER BY
      value DESC
    LIMIT 10;
  EOQ
}

query "group_resource_arn" {
  sql = <<-EOQ
    SELECT
      finding_resource_arn AS label,
      COUNT(*) AS value,
      CASE
        WHEN COUNT(*) > 0 THEN 'alert'
        ELSE 'ok'
      END AS type
    FROM
      findings
    GROUP BY
      finding_resource_arn
    ORDER BY
      value DESC
    LIMIT 10;
  EOQ
}

query "group_compliancestatus" {
  sql = <<-EOQ
    select
      finding_compliancestatus as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      findings
    group by
      finding_compliancestatus
  EOQ
}

query "group_severity" {
  sql = <<-EOQ
    select
      finding_severity as label,
      count(*) as value,
      case
        when count(*) > 0 then 'alert'
        else 'ok'
      end as type
    from
      findings
    group by
      finding_severity
  EOQ
}

query "group_productarn" {
  sql = <<-EOQ
    SELECT
      finding_productarn AS label,
      COUNT(*) AS value,
      CASE
        WHEN COUNT(*) > 0 THEN 'alert'
        ELSE 'ok'
      END AS type
    FROM
      findings
    GROUP BY
      finding_productarn
    ORDER BY
      value DESC
    LIMIT 10;
  EOQ
}
