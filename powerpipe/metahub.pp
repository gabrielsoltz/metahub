locals {
  header = <<-EOM
        ## Dashboards: [Resources](${var.host}/metahub.dashboard.resources) | [Findings](${var.host}/metahub.dashboard.findings) | [accounts](${var.host}/metahub.dashboard.accounts)"
      EOM
}

variable "host" {
  type    = string
  default = "http://localhost:9033"
}
