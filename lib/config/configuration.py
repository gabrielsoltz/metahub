# Security Hub Configurations

# Default filters for Security Hub findings, not implemented yet
# sh_default_filters = {"RecordState": ["ACTIVE"], "WorkflowStatus": ["NEW"]}

# MetaChecks configurations

# List of AWS accounts ids that are trusted and not considered as external. This is used in the is_principal_external MetaCheck for policies.
trusted_accounts = []

# Days to consider a resource (key) unrotated
days_to_consider_unrotated = 90

# Output Columns
# You can define the columns that will be displayed in the output HTML, CSV AND XLSX.
# You can also use `--output-config-columns` and `--output-tags-columns` to override these values.
# If you want all fields as columns, comment the following lines.
config_columns = ["public"]
tag_columns = ["Owner"]
account_columns = ["AccountAlias"]
impact_columns = ["score", "exposure"]
