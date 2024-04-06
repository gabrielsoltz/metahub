dashboard "accounts" {
  text {
    value = "## MetaHub: [Resources](${var.host}/metahub.dashboard.resources) | [Findings](${var.host}/metahub.dashboard.findings) | Accounts"
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
