def get_config_key(resource_values, key):
    # Config exists for resource
    if "config" in resource_values:
        # Key exists in config and is not null
        if key in resource_values["config"]:
            if resource_values["config"][key] is not None:
                return resource_values["config"][key]
    return None


def get_associated_resources(resource_values, associated_resources):
    # Config exists for resource
    if "associations" in resource_values:
        # Key exists in config and is not null
        if associated_resources in resource_values["associations"]:
            if resource_values["associations"][associated_resources] is not None:
                return resource_values["associations"][associated_resources]
    return None


def check_key(resource_values, key):
    # Config exists for resource
    if key in resource_values and resource_values[key]:
        return True
    return None
