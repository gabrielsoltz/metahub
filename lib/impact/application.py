from lib.config.configuration import applications


class Application:
    def __init__(self, logger):
        self.logger = logger

    def get_application(self, resource_arn, resource_values):
        self.logger.info("Calculating application for resource: %s", resource_arn)

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

        for app in applications:
            tags_matched, tags_details = check_tags(applications[app].get("tags", {}))
            if tags_matched:
                return {app: {"tags": tags_details}}

        return {"unknown": {}}
