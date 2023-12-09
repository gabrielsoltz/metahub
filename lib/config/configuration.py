# MetaHub Configurations

# ---------------------------------- #
# Security Hub Configurations        #
# ---------------------------------- #

# Default filters for Security Hub
sh_default_filters = {"RecordState": ["ACTIVE"], "WorkflowStatus": ["NEW"]}

# Enrichment fields for Security Hub when using the option --enrich-findings
# Choose from: tags, config, account, cloudtrail, associations, impact
sh_enrich_with = [
    "tags",
    "config",
    "account",
    "cloudtrail",
    "associations",
    "impact",
]


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

# Days to consider a resource (key) unrotated
days_to_consider_unrotated = 90

# ---------------------------------- #
# Impact: Access Configurations      #
# ---------------------------------- #

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

# ---------------------------------- #
# Impact: Environment Configurations #
# ---------------------------------- #
# You can define the environment by tags, account id or account alias.
# You can define how many environments you want, then assign each environment a value in the file: lib/config/impact.yaml

environments = {
    "production": {
        "tags": {
            "Environment": ["Production", "production", "prd"],
            "environment": ["Production", "production", "prd"],
            "Env": ["Production", "production", "prd"],
            "env": ["Production", "production", "prd"],
        },
        "account": {
            "account_ids": ["123456789012"],
            "account_aliases": ["production", "prod"],
        },
    },
    "staging": {
        "tags": {
            "Environment": ["Staging", "staging", "stg"],
            "environment": ["Staging", "staging", "stg"],
            "Env": ["Staging", "staging", "stg"],
            "env": ["Staging", "staging", "stg"],
        },
        "account": {
            "account_ids": ["123456789012"],
            "account_aliases": ["staging", "stg"],
        },
    },
    "development": {
        "tags": {
            "Environment": ["Development", "development", "dev"],
            "environment": ["Development", "development", "dev"],
            "Env": ["Development", "development", "dev"],
            "env": ["Development", "development", "dev"],
        },
        "account": {
            "account_ids": ["123456789012"],
            "account_aliases": ["development", "dev"],
        },
    },
}

# ---------------------------------- #
# Impact: Application Configurations #
# ---------------------------------- #
# https://aws.amazon.com/blogs/aws/new-myapplications-in-the-aws-management-console-simplifies-managing-your-application-resources/
# You can define the application by tags, account id or account alias.
# You can define how many appliactions you want, then assign each application a value in the file: lib/config/impact.yaml

applications = {
    "app1": {
        "tags": {
            "awsApplication": [
                "arn:aws:resource-groups:eu-west-1:123456789012:group/app1/0c8vpbjkzeeffsz2cqgxpae7b2"
            ],
        },
        "account": {
            "account_ids": ["123456789012"],
            "account_aliases": ["app1"],
        },
    },
    "app2": {
        "tags": {
            "awsApplication": [
                "arn:aws:resource-groups:eu-west-1:123456789012:group/app2/0c8vpbjkzeeffsz2cqgxpae7b2"
            ],
        },
        "account": {
            "account_ids": ["123456789012"],
            "account_aliases": ["app2"],
        },
    },
}

# ---------------------------------- #
# Impact: Owner Configurations       #
# ---------------------------------- #
# You can define the owner by tags, account id or account alias.
# You can define how owner you want, then assign each owner a value in the file: lib/config/impact.yaml

owners = {
    "owner1": {
        "tags": {
            "Owner": ["owner1"],
            "owner": ["owner1"],
        },
        "account": {
            "account_ids": ["123456789012"],
            "account_aliases": ["owner1"],
        },
    },
    "owner2": {
        "tags": {
            "Owner": ["owner2"],
            "owner": ["owner2"],
        },
        "account": {
            "account_ids": ["123456789012"],
            "account_aliases": ["owner2"],
        },
    },
}

# ---------------------------------- #
# Output Configurations              #
# ---------------------------------- #

# Columns
# You can define the columns that will be displayed in the output HTML, CSV AND XLSX.
# You can also use `--output-config-columns` and `--output-tags-columns` to override these values.
# If you want all fields as columns, comment the following lines.
config_columns = []
tag_columns = ["Name", "Owner"]
account_columns = ["Alias"]
impact_columns = [
    "score",
    "exposure",
    "access",
    "encryption",
    "status",
    "environment",
    "application",
]

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
