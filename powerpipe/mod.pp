mod "metahub" {
  title = "MetaHub Security Dashboards"
}

input "exposure" {
  type  = "multiselect"
  width = 2
  option "ALL" {
    label = "Exposure (ALL)"
  }
  option "effectively-public" {}
  option "restricted-public" {}
  option "unrestricted-private" {}
  option "launch-public" {}
  option "restricted" {}
  option "unknown" {}
}

input "access" {
  type  = "multiselect"
  width = 2
  option "ALL" {
    label = "Access (ALL)"
  }
  option "unrestricted" {}
  option "untrusted-principal" {}
  option "unrestricted-principal" {}
  option "cross-account-principal" {}
  option "unrestricted-actions" {}
  option "dangerous-actions" {}
  option "unrestricted-service" {}
  option "restricted" {}
  option "unknown" {}
}

input "encryption" {
  type  = "multiselect"
  width = 2
  option "ALL" {
    label = "Encryption (ALL)"
  }
  option "unencrypted" {}
  option "encrypted" {}
  option "unknown" {}
}

input "status" {
  type  = "multiselect"
  width = 2
  option "ALL" {
    label = "Status (ALL)"
  }
  option "attached" {}
  option "running" {}
  option "enabled" {}
  option "not-attached" {}
  option "not-running" {}
  option "not-enabled" {}
  option "unknown" {}
}

input "severity" {
  type  = "multiselect"
  width = 2
  option "ALL" {
    label = "Severity (ALL)"
  }
  option "CRITICAL" {}
  option "HIGH" {}
  option "MEDIUM" {}
  option "LOW" {}
  option "INFORMATIONAL" {}
}

input "environment" {
  type  = "multicombo"
  width = 2
  option "ALL" {
    label = "Environment (ALL)"
  }
  option "production" {}
  option "staging" {}
  option "development" {}
}

input "owner" {
  type  = "multicombo"
  width = 2
  option "ALL" {
    label = "Owner (ALL)"
  }
}

input "application" {
  type  = "multicombo"
  width = 2
  option "ALL" {
    label = "Application (ALL)"
  }
}

input "account" {
  type  = "multicombo"
  width = 2
  option "ALL" {
    label = "Account (ALL)"
  }
}

input "type" {
  type  = "multicombo"
  width = 2
  option "ALL" {
    label = "Type (ALL)"
  }
}

input "region" {
  type  = "multicombo"
  width = 2
  option "ALL" {
    label = "Region (ALL)"
  }
}

input "tags" {
  type  = "combo"
  width = 2
  option "ALL" {
    label = "TAG:VALUE (ALL)"
  }
}
