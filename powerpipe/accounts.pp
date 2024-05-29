dashboard "accounts" {
  text {
<<<<<<< Updated upstream
    value = "## MetaHub: [Resources](${var.host}/metahub.dashboard.resources) | [Findings](${var.host}/metahub.dashboard.findings) | Accounts"
=======
    value = "## MetaHub: [Resources](${var.host}/metahub.dashboard.resources) | [Findings](${var.host}/metahub.dashboard.findings) | Accounts | [Access](${var.host}/metahub.dashboard.access) | [Exposure](${var.host}/metahub.dashboard.exposure)"
>>>>>>> Stashed changes
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
