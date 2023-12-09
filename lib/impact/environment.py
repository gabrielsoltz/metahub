from lib.config.configuration import environments
from lib.impact.helpers import check_account, check_tags


class Environment:
    def __init__(self, logger):
        self.logger = logger

    def get_environment(self, resource_arn, resource_values):
        self.logger.info("Calculating environment for resource: %s", resource_arn)

        for env in environments:
            tags_matched, tags_details = check_tags(
                resource_values, environments[env].get("tags", {})
            )
            if tags_matched:
                return {env: {"tags": tags_details}}
            account_matched, account_details = check_account(
                resource_values, environments[env].get("account", {})
            )
            if account_matched:
                return {env: {"account": account_details}}

        return {"unknown": {}}
