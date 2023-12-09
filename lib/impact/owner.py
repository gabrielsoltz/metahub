from lib.config.configuration import owners
from lib.impact.helpers import check_account, check_tags


class Owner:
    def __init__(self, logger):
        self.logger = logger

    def get_owner(self, resource_arn, resource_values):
        self.logger.info("Calculating owner for resource: %s", resource_arn)

        for owner in owners:
            tags_matched, tags_details = check_tags(
                resource_values, owners[owner].get("tags", {})
            )
            if tags_matched:
                return {owner: {"tags": tags_details}}
            account_matched, account_details = check_account(
                resource_values, owners[owner].get("account", {})
            )
            if account_matched:
                return {owner: {"account": account_details}}

        return {"unknown": {}}
