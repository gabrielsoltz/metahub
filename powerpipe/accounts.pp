dashboard "accounts" {
  text {
    value = "## MetaHub: [Resources](${var.host}/metahub.dashboard.resources) | [Findings](${var.host}/metahub.dashboard.findings) | Accounts | [Access](${var.host}/metahub.dashboard.access) | [Exposure](${var.host}/metahub.dashboard.exposure)"
  }

  container {
    table {
      query = query.accounts
    }
  }
}

query "accounts" {
  sql = <<-EOQ
    select
      *
    from
      accounts
  EOQ
}
