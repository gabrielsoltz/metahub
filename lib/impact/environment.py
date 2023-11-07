from lib.config.configuration import tags_development, tags_production, tags_staging


class Environment:
    def __init__(self, logger):
        self.logger = logger

    def get_environment(self, resource_arn, resource_values):
        self.logger.info("Calculating environment for resource: %s", resource_arn)

        def check_tags(tags_environment):
            tags = resource_values.get("tags", {})
            if tags:
                for tag_key, tag_values in tags_environment.items():
                    for tag_value in tag_values:
                        if tag_key in tags and tags[tag_key] == tag_value:
                            return True, {tag_key: tag_value}
            return False, False

        envs = {
            "production": tags_production,
            "staging": tags_staging,
            "development": tags_development,
        }
        for env in envs:
            check, tags_matched = check_tags(envs[env])
            if check:
                return {env: tags_matched}

        return {"unknown": {}}
