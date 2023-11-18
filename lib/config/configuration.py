# MetaHub Configurations

# ---------------------------------- #
# Security Hub Configurations        #
# ---------------------------------- #

# Default filters for Security Hub
sh_default_filters = {"RecordState": ["ACTIVE"], "WorkflowStatus": ["NEW"]}


# ---------------------------------- #
# Impact Configurations              #
# ---------------------------------- #

# Impact Scoring Defintion File
path_yaml_impact = "lib/config/impact.yaml"

# Severity Values for impact scoring calculation
findings_severity_value = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 1,
    "LOW": 0.5,
    "INFORMATIONAL": 0,
}

# List of AWS accounts ids that are trusted and not considered as external.
# This is used in check untrusted_principal for policies.
trusted_accounts = []

# Dangerous IAM actions that should be considered as a finding if used in a policy
dangerous_iam_actions = [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
]

# Days to consider a resource (key) unrotated
days_to_consider_unrotated = 90

# Environment Tags Definition
# tag_ENVIRONMENT = {"TAG-KEY": ["TAG-VALUE1", "TAG-VALUE1", "TAG-VALUE3"]}
tags_production = {
    "Environment": ["Production", "production", "prd"],
    "Env": ["production"],
    "environment": ["prd"],
}
tags_staging = {
    "Environment": ["Staging", "staging", "stg"],
    "Env": ["stg"],
    "environment": ["stg"],
}
tags_development = {
    "Environment": ["Development", "development", "dev"],
    "Env": ["dev"],
    "environment": ["dev"],
}


# ---------------------------------- #
# Output Configurations              #
# ---------------------------------- #

# Columns
# You can define the columns that will be displayed in the output HTML, CSV AND XLSX.
# You can also use `--output-config-columns` and `--output-tags-columns` to override these values.
# If you want all fields as columns, comment the following lines.
config_columns = ["public"]
tag_columns = ["Name", "Owner"]
account_columns = ["AccountAlias"]
impact_columns = ["score", "exposure", "access", "encryption", "status", "environment"]

# Decide if you want to output as part of the findings the whole json resource policy
output_resource_policy = True

# Output directory
outputs_dir = "outputs/"

# Output file name date format
outputs_time_str = "%Y%m%d-%H%M%S"

# ---------------------------------- #
# Other Configurations               #
# ---------------------------------- #

# Assume role duration in seconds
assume_role_duration = 3600
