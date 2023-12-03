from lib.config.configuration import environments


class Environment:
    def __init__(self, logger):
        self.logger = logger

    def get_environment(self, resource_arn, resource_values):
        self.logger.info("Calculating environment for resource: %s", resource_arn)

        def check_tags(environment_definition):
            resource_tags = resource_values.get("tags", {})
            if resource_tags:
                for tag_key, tag_values in environment_definition.items():
                    for tag_value in tag_values:
                        if (
                            tag_key in resource_tags
                            and resource_tags[tag_key] == tag_value
                        ):
                            return True, {tag_key: tag_value}
            return False, False

        def check_account(environment_definition):
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

        for env in environments:
            # tags_matched, tags_details = check_tags(environments[env].get("tags", {}))
            # if tags_matched:
            #     return {env: {"tags": tags_details}}
            account_matched, account_details = check_account(
                environments[env].get("account", {})
            )
            if account_matched:
                return {env: {"account": account_details}}

        return {"unknown": {}}
