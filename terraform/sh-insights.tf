# Insights

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
