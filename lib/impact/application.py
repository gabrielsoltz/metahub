from lib.config.configuration import applications
from lib.impact.helpers import check_account, check_tags


class Application:
    def __init__(self, logger):
        self.logger = logger

    def get_application(self, resource_arn, resource_values):
        self.logger.info("Calculating application for resource: %s", resource_arn)

        for app in applications:
            tags_matched, tags_details = check_tags(
                resource_values, applications[app].get("tags", {})
            )
            if tags_matched:
                return {app: {"tags": tags_details}}
            account_matched, account_details = check_account(
                resource_values, applications[app].get("account", {})
            )
            if account_matched:
                return {app: {"account": account_details}}

        return {"unknown": {}}
