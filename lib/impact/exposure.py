from lib.impact.access import Access
from lib.impact.helpers import check_key, get_associated_resources, get_config_key


class Exposure:
    def __init__(self, logger):
        self.logger = logger

    def check_security_group_rules(self, rules):
        failed_rules = {
            "unrestricted_ingress_rules": [],
            "unrestricted_egress_rules": [],
        }
        if rules:
            for rule in rules:
                if (
                    self.check_unrestricted_ingress_rules(rule)
                    and rule not in failed_rules["unrestricted_ingress_rules"]
                ):
                    failed_rules["unrestricted_ingress_rules"].append(rule)
                if (
                    self.check_unrestricted_egress_rules(rule)
                    and rule not in failed_rules["unrestricted_egress_rules"]
                ):
                    failed_rules["unrestricted_egress_rules"].append(rule)
        return failed_rules

    def check_unrestricted_ingress_rules(self, rule):
        """ """
        if "CidrIpv4" in rule:
            if "0.0.0.0/0" in rule["CidrIpv4"] and not rule["IsEgress"]:
                return True
        if "CidrIpv6" in rule:
            if "::/0" in rule["CidrIpv6"] and not rule["IsEgress"]:
                return True
        return False

    def check_unrestricted_egress_rules(self, rule):
        """ """
        if "CidrIpv4" in rule:
            if "0.0.0.0/0" in rule["CidrIpv4"] and rule["IsEgress"]:
                return True
        if "CidrIpv6" in rule:
            if "::/0" in rule["CidrIpv6"] and rule["IsEgress"]:
                return True
        return False

    def get_exposure(self, resource_arn, resource_values):
        self.logger.info("Calculating exposure for resource: %s", resource_arn)

        resource_type = resource_values.get("ResourceType")

        unrestricted_ingress_rules = []
        unrestricted_egress_rules = []
        entrypoint = None

        # Public Config
        # This is a standard key we add at the resource level to check if the resoruce it's public at their config.
        resource_public_config = get_config_key(resource_values, "public")

        # Resource Policy, for some resources, exposure is defined using a resource policy.
        # We will neeed to evaluate this policy to check if the resource is public.
        resource_policy = get_config_key(resource_values, "resource_policy")
        unrestricted_policy_access = False
        if resource_policy:
            access = Access(self.logger).get_access(resource_arn, resource_values)
            if "unrestricted" in access:
                unrestricted_policy_access = True

        # Entrypoint
        # We check all possible entrypoint. This is a bit messy, probably some standarizationg would be good at the resource.
        entrypoints = [
            "public_endpoint",
            "public_ip",
            "public_ips",
            "aliases",
            "public_dns",
            "endpoint",
            "private_ip",
            "private_dns",
            "website_enabled",
        ]
        for ep in entrypoints:
            entrypoint = get_config_key(resource_values, ep)
            if entrypoint:
                break

        # Security Group Rules. This should be checked here, instead of in the security group.
        # We need to add the rules as as a list in the config.
        rules = get_config_key(resource_values, "security_group_rules")
        if rules:
            checked_rules = self.check_security_group_rules(rules)
            unrestricted_ingress_rules.extend(
                checked_rules["unrestricted_ingress_rules"]
            )
            unrestricted_egress_rules.extend(checked_rules["unrestricted_egress_rules"])

        # Associated with an Security Group, we check their rules.
        security_groups = get_associated_resources(resource_values, "security_groups")
        if security_groups:
            for sg_arn, sg_details in security_groups.items():
                if sg_details:
                    security_groups_rules = get_config_key(
                        sg_details, "security_group_rules"
                    )
                    if security_groups_rules:
                        checked_rules = self.check_security_group_rules(
                            security_groups_rules
                        )
                        unrestricted_ingress_rules.extend(
                            checked_rules["unrestricted_ingress_rules"]
                        )
                        unrestricted_egress_rules.extend(
                            checked_rules["unrestricted_egress_rules"]
                        )

        exposure_checks = {
            "entrypoint": entrypoint,
            "unrestricted_ingress_rules": unrestricted_ingress_rules,
            "unrestricted_egress_rules": unrestricted_egress_rules,
            "resource_public_config": resource_public_config,
        }

        # If no config and no associations, return unknown
        if not check_key(resource_values, "config") and not check_key(
            resource_values, "associations"
        ):
            return {"unknown": exposure_checks}

        # Effectively Public If:
        # 1. Public config and unrestricted SG ingress rules
        # 2. Public config and no SG and no resource policy
        # 3. Public config and unrestricted policy access
        if (
            (resource_public_config and unrestricted_ingress_rules)
            or (resource_public_config and not security_groups and not resource_policy)
            or (resource_public_config and unrestricted_policy_access)
        ):
            # These are not effectively public, but they could create a public resource.
            if resource_type in (
                "AwsEc2Subnet",
                "AwsEc2LaunchTemplate",
                "AwsAutoScalingLaunchConfiguration",
            ):
                return {"launch-public": exposure_checks}
            return {"effectively-public": exposure_checks}

        # Restricted Public If:
        # 1. Public config and no unrestricted SG ingress rules and no unrestricted policy access
        if resource_public_config and (
            not unrestricted_ingress_rules and not unrestricted_policy_access
        ):
            return {"restricted-public": exposure_checks}

        # Restricted Private If:
        # 1. No public config and unrestricted SG ingress rules or unrestricted policy access
        if not resource_public_config and (
            unrestricted_ingress_rules or unrestricted_policy_access
        ):
            return {"unrestricted-private": exposure_checks}

        return {"restricted": exposure_checks}
