from lib.impact.helpers import check_key, get_config_key


class Status:
    def __init__(self, logger):
        self.logger = logger

    def get_status(self, resource_arn, resource_values):
        self.logger.info("Calculating status for resource: %s", resource_arn)

        status = get_config_key(resource_values, "status")
        attached = get_config_key(resource_values, "attached")

        status_checks = {
            "status": status,
            "attached": attached,
        }

        # If no config and no associations, return unknown
        if not check_key(resource_values, "config") and not check_key(
            resource_values, "associations"
        ):
            return {"unknown": status_checks}

        if attached is not None:
            if attached is True:
                return {"attached": status_checks}
            if attached is False:
                return {"not-attached": status_checks}

        if status is not None:
            if status == "running":
                return {"running": status_checks}
            if status != "running":
                return {"not-running": status_checks}

        return {"unknown": status_checks}
