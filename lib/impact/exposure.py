class Exposure:
    def __init__(self, logger):
        self.logger = logger

    def get_exposure(self, resource_arn, resource_values):
        self.logger.info("Calculating exposure for resource: %s", resource_arn)

        public_rules = []
        config_public = None
        entrypoint = None

        config = resource_values.get("config", {})
        if config:
            # Helper function to determine entrypoint
            def get_entrypoint():
                entrypoints = [
                    "public_endpoint",
                    "public_ip",
                    "public_ips",
                    "aliases",
                    "public_dns",
                    "endpoint",
                    "private_ip",
                    "private_dns",
                ]
                for ep in entrypoints:
                    if config.get(ep):
                        return config[ep]

            entrypoint = get_entrypoint()
            if config.get("public"):
                config_public = config["public"]

            # Same Security Group
            if config.get("is_ingress_rules_unrestricted"):
                public_rules.extend(config.get("is_ingress_rules_unrestricted"))

        # Associated with an Security Group
        associations = resource_values.get("associations", {})
        if associations:
            security_groups = associations.get("security_groups", {})
            if security_groups:
                for sg_arn, sg_details in security_groups.items():
                    if sg_details:
                        sg_config = sg_details.get("config", {})
                        if sg_config.get("is_ingress_rules_unrestricted"):
                            public_rules.extend(
                                sg_config["is_ingress_rules_unrestricted"]
                            )

        if not config and not associations:
            exposure = "unknown"
        elif config_public:
            if public_rules:
                exposure = "effectively-public"
            else:
                exposure = "restricted-public"
        elif config_public is None:
            if public_rules:
                exposure = "unknown-public"
            else:
                exposure = "restricted"
        else:
            if public_rules:
                exposure = "unrestricted-private"
            else:
                exposure = "restricted"

        exposure_dict = {
            exposure: {
                "entrypoint": entrypoint,
                "public_rules": public_rules,
            }
        }

        return exposure_dict
