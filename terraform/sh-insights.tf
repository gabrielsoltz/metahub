# Insights

# Exposure Insights

resource "aws_securityhub_insight" "exposure_effectively_public" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "exposure"
      value      = "effectively-public"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Exposure: Effectively Public"

}

resource "aws_securityhub_insight" "exposure_restricted_public" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "exposure"
      value      = "restricted-public"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Exposure: Restricted Public"

}

resource "aws_securityhub_insight" "exposure_unrestricted_private" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "exposure"
      value      = "unrestricted-private"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Exposure: Unrestricted Private"

}

resource "aws_securityhub_insight" "exposure_launch_public" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "exposure"
      value      = "launch-public"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Exposure: Launch Public"

}

resource "aws_securityhub_insight" "exposure_restricted" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "exposure"
      value      = "restricted"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Exposure: Restricted"

}



# Access Insights

resource "aws_securityhub_insight" "access_unrestricted" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "access"
      value      = "unrestricted"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Access: Unrestricted"

}

resource "aws_securityhub_insight" "access_untrusted-principal" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "access"
      value      = "untrusted-principal"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Access: Untrusted Principal"

}

resource "aws_securityhub_insight" "access_unrestricted-principal" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "access"
      value      = "unrestricted-principal"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Access: Unrestricted Principal"

}

resource "aws_securityhub_insight" "access_cross-account-principal" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "access"
      value      = "cross-account-principal"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Access: Cross-Account principal"

}

resource "aws_securityhub_insight" "access_unrestricted-actions" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "access"
      value      = "unrestricted-actions"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Access: Unrestricted Actions"

}

resource "aws_securityhub_insight" "access_dangerous-actions" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "access"
      value      = "dangerous-actions"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Access: Dangerous Actions"

}

resource "aws_securityhub_insight" "access_unrestricted-service" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "access"
      value      = "unrestricted-service"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Access: Unrestricted Service"

}

resource "aws_securityhub_insight" "access_restricted" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "access"
      value      = "restricted"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Access: Restricted"

}

# Encryption Insights

resource "aws_securityhub_insight" "encryption_unencrypted" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "encryption"
      value      = "unencrypted"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Encryption: Unencrypted"

}

resource "aws_securityhub_insight" "encryption_encrypted" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "encryption"
      value      = "encrypted"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Encryption: Encrypted"

}

# Status Insights

resource "aws_securityhub_insight" "status_attached" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "status"
      value      = "attached"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Status: Attached"

}

resource "aws_securityhub_insight" "status_running" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "status"
      value      = "running"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Status: Running"

}

resource "aws_securityhub_insight" "status_enabled" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "status"
      value      = "enabled"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Status: Enabled"

}

resource "aws_securityhub_insight" "status_not_attached" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "status"
      value      = "not-attached"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Status: Not Attached"

}

resource "aws_securityhub_insight" "status_not_running" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "status"
      value      = "not-running"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Status: Not Running"

}

resource "aws_securityhub_insight" "status_not_enabled" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    user_defined_values {
      comparison = "EQUALS"
      key        = "status"
      value      = "not-enabled"
    }
  }

  group_by_attribute = "ResourceId"

  name = "MetaHub Status: Not Enabled"

}
