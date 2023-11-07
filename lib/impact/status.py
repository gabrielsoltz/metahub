class Status:
    def __init__(self, logger):
        self.logger = logger

    def get_status(self, resource_arn, resource_values):
        self.logger.info("Calculating status for resource: %s", resource_arn)

        config = resource_values.get("config", {})
        if config:
            if config.get("status"):
                if config.get("status") == "running":
                    return {"running": config.get("status")}
                else:
                    return {"not-running": config.get("status")}
            if config.get("attached") is True:
                return {"attached": config.get("attached")}
            if config.get("attached") is False:
                return {"not-attached": config.get("attached")}

        return {"unknown": {}}
