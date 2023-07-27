# Security Hub Configurations

# Default filters for Security Hub findings
sh_default_filters = {"RecordState": ["ACTIVE"], "WorkflowStatus": ["NEW"]}

# MetaCheck configurations

# List of AWS accounts ids that are trusted and not considered as external. This is used in the is_principal_external MetaCheck for policies.
trusted_accounts = []
