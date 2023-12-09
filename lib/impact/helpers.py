def get_config_key(resource_values, key):
    # True, False, or None
    try:
        # Config exists for resource
        if "config" in resource_values:
            if (
                resource_values["config"] is not None
                and resource_values["config"] is not False
            ):
                # Key exists in config and is not null
                if key in resource_values["config"]:
                    if resource_values["config"][key] is not None:
                        return resource_values["config"][key]
        return None
    except Exception as e:
        print("Error getting config key: ", key, e, resource_values)
        return None


def get_associated_resources(resource_values, associated_resources):
    # True or None
    try:
        # Config exists for resource
        if "associations" in resource_values:
            if (
                resource_values["associations"] is not None
                and resource_values["associations"] is not False
            ):
                # Key exists in config and is not null
                if associated_resources in resource_values["associations"]:
                    if (
                        resource_values["associations"][associated_resources]
                        is not None
                        and resource_values["associations"][associated_resources]
                        is not False
                    ):
                        return resource_values["associations"][associated_resources]
        return None
    except Exception as e:
        print("Error getting asssociations: ", associated_resources, e, resource_values)
        return None


def check_key(resource_values, key):
    # Config exists for resource
    if key in resource_values and resource_values[key]:
        return True
    return None


def check_tags(resource_values, environment_definition):
    resource_tags = resource_values.get("tags", {})
    if resource_tags:
        for tag_key, tag_values in environment_definition.items():
            for tag_value in tag_values:
                if tag_key in resource_tags and resource_tags[tag_key] == tag_value:
                    return True, {tag_key: tag_value}
    return False, False


def check_account(resource_values, environment_definition):
    resource_AwsAccountId = resource_values.get("AwsAccountId", "")
    resouce_account = resource_values.get("account", {})
    # Check by ID
    if resource_AwsAccountId and "account_ids" in environment_definition:
        if resource_AwsAccountId in environment_definition["account_ids"]:
            return True, {"account_id": resource_AwsAccountId}
    # Check by Alias
    if resouce_account:
        if "account_aliases" in environment_definition:
            if (
                resouce_account.get("Alias")
                in environment_definition["account_aliases"]
            ):
                return True, {"account_alias": resouce_account.get("Alias")}
    return False, False
