from pathlib import Path

import yaml

from lib.context.resources.ContextHelpers import PolicyHelper


class Impact:
    def __init__(self, logger):
        self.logger = logger
        self.impact_config = self.load_impact_config()
        self.findings_severity_value = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 1,
            "LOW": 0.5,
            "INFORMATIONAL": 0,
        }

    def load_impact_config(self):
        path_yaml_impact = "lib/config/impact.yaml"
        try:
            yaml_to_dict = yaml.safe_load(Path(path_yaml_impact).read_text())
            if not self.validate_config(yaml_to_dict):
                yaml_to_dict = False
        except (yaml.scanner.ScannerError, FileNotFoundError) as err:
            self.logger.error("Error loading impact.yaml: %s", err)
            yaml_to_dict = False
        return yaml_to_dict

    def validate_config(self, config):
        for property in config:
            property_values = config[property]["values"]
            property_weight = config[property]["weight"]
            if not isinstance(property_weight, (int, float)):
                self.logger.error(
                    "Error validating impact.yaml: weight is not int %s",
                    property_weight,
                )
                return False
            for value in property_values:
                for value_key, value_data in value.items():
                    score = value_data["score"]
                    if not isinstance(score, (int, float)):
                        self.logger.error(
                            "Error validating impact.yaml: score is not int %s",
                            property_weight,
                        )
                        return False
                    if score > 1:
                        self.logger.error(
                            "Error validating impact.yaml: score is greater than 1 %s",
                            property_weight,
                        )
                        return False
        return True

    def check_match(self, match_type, match, resource):
        # Check if the value match the resource
        """match_type: metachecks/metatags/metaaccount"""
        """ match: {key: value} """
        for resource_key, value in resource.items():
            if resource_key == match_type and value:
                for match_key, match_value in match.items():
                    meta_output = value.get(match_key)
                    if meta_output is not None:
                        if match_type == "metachecks":
                            if bool(meta_output) == bool(match_value):
                                return True
                        else:
                            if meta_output == match_value:
                                return True
        return False

    def check_property(self, property_values, resource):
        # Check if the property is applicable to the resource
        for value in property_values:
            for value_key, value_data in value.items():
                score = value_data["score"]
                matchs = value_data["matchs"]
                for match in matchs:
                    for match_type, matchs_data in match.items():
                        for match_item in matchs_data:
                            if self.check_match(match_type, match_item, resource):
                                return value_key, score
        return False

    def get_findings_score(self, resource):
        self.logger.info("Calculating impact findings score for resource")

        # Initialize the findings score to zero
        findings_score = 0

        # Iterate through each finding in the resource
        for f in resource["findings"]:
            for k, v in f.items():
                # Check if the finding is active
                if v.get("RecordState") == "ACTIVE":
                    # Get the severity value for the finding
                    single_finding_severity = self.findings_severity_value.get(
                        v.get("SeverityLabel")
                    )
                    # Get the single finding score
                    single_finding_score = single_finding_severity / max(
                        self.findings_severity_value.values()
                    )
                    # Sum the single finding score to the findings score
                    findings_score += single_finding_score

        # Ensure the findings score does not exceed 1
        if findings_score > 1:
            findings_score = 1

        return findings_score

    def get_meta_score(self, resource):
        self.logger.info("Calculating impact meta score for resource")

        # Initialize variables to track the meta score details and context
        meta_score_details = {}
        weight_total = 0
        score_total = 0
        context = False

        # Iterate through each property in the impact configuration for the resource
        for property in self.impact_config:
            # Get the weight and values for each the property from the configuration
            property_values = self.impact_config[property]["values"]
            property_weight = self.impact_config[property]["weight"]
            # Check the property against the finding
            checked_property = self.check_property(property_values, resource)
            # If the property check is not False (i.e., it has a value),
            # record the weight, value, and calculated score for this property
            if checked_property is not False:
                meta_score_details[property] = {
                    "weight": property_weight,
                    "value": checked_property[0],
                    "score": checked_property[1],
                }
                # Update the total weight and value based on this property
                weight_total += property_weight
                score_total += property_weight * checked_property[1]
                # Flag there is some context for the resource
                context = True
            else:
                # If the property check is False, indicate that it's not applicable
                meta_score_details[property] = {
                    "weight": property_weight,
                    "value": "n/a",
                    "score": "-",
                }

        # Calculate the meta score based on the weighted values if there is context
        if not context:
            meta_score = "n/a"
        else:
            meta_score = score_total / weight_total

        self.logger.info(
            "Impact Meta Score %s, details:: %s", meta_score, meta_score_details
        )

        return meta_score

    def get_impact(self, resource):
        self.logger.info("Calculating impact score for resource")
        if not self.impact_config:
            return False

        # Create a dictionary to store the impact scores
        impact = {}

        # Calculate the findings score using the get_findings_score method
        impact["findings_score"] = self.get_findings_score(resource)
        # Calculate the meta score using the get_meta_score method
        impact["meta_score"] = self.get_meta_score(resource)

        # Check if the meta score is not "n/a" (i.e., there's context)
        if impact["meta_score"] != "n/a":
            # Calculate the overall impact score as the product of findings_score and meta_score
            impact_score = impact["findings_score"] * impact["meta_score"] * 100
        else:
            # If there's no context, calculate the impact score as findings_score * 100
            impact_score = impact["findings_score"] * 100

        # Round the impact score to 2 decimal places
        impact_score = round(impact_score, 2)

        # Check if the number has a decimal part
        if impact_score % 1 == 0:
            impact_score = int(impact_score)  # Return the integer part

        impact["score"] = impact_score

        # Return the dictionary containing impact scores
        return impact

    def resource_exposure(self, resource_arn, resource_values):
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

            if config.get("public"):
                config_public = config["public"]
                entrypoint = get_entrypoint()

            # Same Security Group
            if config.get("is_ingress_rules_unrestricted"):
                public_rules.extend(config.get("is_ingress_rules_unrestricted"))

        # Associated with an Security Group
        associations = resource_values.get("associations", {})
        if associations:
            security_groups = associations.get("security_groups", {})
            if security_groups:
                for sg_arn, sg_details in security_groups.items():
                    sg_config = sg_details.get("config", {})
                    if sg_config.get("is_ingress_rules_unrestricted"):
                        public_rules.extend(sg_config["is_ingress_rules_unrestricted"])

        if config_public:
            if public_rules:
                exposure = "effectively-public"
            elif resource_values.get("ResourceType") != "AwsEc2SecurityGroup":
                if resource_values.get("associations", {}):
                    if not associations.get("security_groups"):
                        exposure = "unrestricted-public"
                exposure = "restricted-public"
            else:
                exposure = "restricted-public"
        elif config_public is None:
            if public_rules:
                exposure = "unknown-public"
            else:
                exposure = "restricted"
        else:
            exposure = "unrestricted-private"

        exposure_dict = {
            exposure: {
                "entrypoint": entrypoint,
                "public_rules": public_rules,
            }
        }

        return exposure_dict

    def resource_access(self, resource_arn, resource_values):
        self.logger.info("Calculating access for resource: %s", resource_arn)

        resource_account_id = resource_values.get("AwsAccountId")
        access_checks = {
            "unrestricted": {},
            "wildcard_principal": {},
            "untrusted_principal": {},
            "cross_account_principal": {},
            "wildcard_actions": {},
            "dangerous_actions": {},
        }

        # Helper function to check policies and update access_checks
        def check_policy_and_update(policy_json, policy_name):
            policy_checks = PolicyHelper(
                self.logger, resource_arn, resource_account_id, policy_json
            ).check_policy()
            for check_type, check_data in policy_checks.items():
                if check_data:
                    access_checks[check_type].update({policy_name: check_data})

        config = resource_values.get("config", {})
        if config:
            # Check config resource policy
            config_resource_policy = resource_values.get("config", {}).get(
                "resource_policy"
            )
            if config_resource_policy:
                check_policy_and_update(config_resource_policy, "resource_policy")

            # Check inline policies from config
            config_inline_policies = resource_values.get("config", {}).get(
                "iam_inline_policies", {}
            )
            for policy_arn, policy_config in config_inline_policies.items():
                if policy_config.get("config") and policy_config["config"].get(
                    "resource_policy"
                ):
                    check_policy_and_update(
                        policy_config["config"]["resource_policy"], policy_arn
                    )

            # Check associated IAM policies
            associated_policies = resource_values.get("associations", {}).get(
                "iam_policies", {}
            )
            for policy_arn, policy_config in associated_policies.items():
                if policy_config.get("config") and policy_config["config"].get(
                    "resource_policy"
                ):
                    check_policy_and_update(
                        policy_config["config"]["resource_policy"], policy_arn
                    )

        associations = resource_values.get("associations", {})
        if associations:
            # Check associated IAM roles with IAM policies
            associated_roles = resource_values.get("associations", {}).get(
                "iam_roles", {}
            )
            for role_arn, role_config in associated_roles.items():
                role_associated_policies = role_config.get("associations", {}).get(
                    "iam_policies", {}
                )
                for policy_arn, policy_config in role_associated_policies.items():
                    if policy_config.get("config") and policy_config["config"].get(
                        "resource_policy"
                    ):
                        check_policy_and_update(
                            policy_config["config"]["resource_policy"], policy_arn
                        )

        for check_type, check_data in list(access_checks.items()):
            if not check_data:
                del access_checks[check_type]

        # Determine the final result
        if not any(access_checks.values()):
            return {"restricted": {}}
        elif "unrestricted" in access_checks:
            return {"unrestricted": access_checks["unrestricted"]}
        elif "untrusted_principal" in access_checks:
            return {"untrusted-principal": access_checks["untrusted_principal"]}
        elif "wildcard_principal" in access_checks and config_resource_policy:
            return {
                "unrestricted-resource-principal": access_checks["wildcard_principal"]
            }
        elif "cross_account_principal" in access_checks:
            return {"cross-account-principal": access_checks["cross_account_principal"]}
        elif "wildcard_actions" in access_checks:
            return {"unrestricted-actions": access_checks["wildcard_actions"]}
        elif "dangerous_actions" in access_checks:
            return {"dangerous-actions": access_checks["dangerous_actions"]}
        else:
            return {"unknown": access_checks}

    def resource_encryption(self, resource_arn, resource_values):
        self.logger.info("Calculating encryption for resource: %s", resource_arn)

        unencrypted_resources = []

        associations = resource_values.get("associations", {})
        if associations:
            # Associated with EBS Volumes or Snapshots
            associated_volumes = resource_values.get("associations").get("volumes")
            if associated_volumes:
                for id, config in associated_volumes.items():
                    volume_encryption = config.get("config").get("encrypted")
                    if not volume_encryption:
                        unencrypted_resources.append(id)
            associated_snapshots = resource_values.get("associations").get("snapshots")
            if associated_snapshots:
                for id, config in associated_snapshots.items():
                    snapshot_encryption = config.get("config").get("encrypted")
                    if not snapshot_encryption:
                        unencrypted_resources.append(id)

        resource_type = resource_values.get("ResourceType")
        config = resource_values.get("config", {})
        resource_encryption_config = "unknown"
        # Configuration by resource type
        if config:
            if resource_type in (
                "AwsRdsDbCluster",
                "AwsRdsDbInstance",
                "AwsEc2Volume",
                "AwsEc2Volume",
            ):
                if config.get("encrypted"):
                    resource_encryption_config = True
                else:
                    resource_encryption_config = False

            if resource_type in (
                "AwsElasticsearchDomain",
                "AwsElastiCacheCacheCluster",
            ):
                if config.get("at_rest_encryption") and config.get(
                    "transit_encryption"
                ):
                    resource_encryption_config = True
                else:
                    resource_encryption_config = False

            if resource_type in ("AwsS3Bucket"):
                if config.get("bucket_encryption"):
                    resource_encryption_config = True
                else:
                    resource_encryption_config = False

            if resource_type in ("AwsCloudFrontDistribution"):
                if (
                    config.get("viewer_protocol_policy") == "redirect-to-https"
                    or config.get("viewer_protocol_policy") == "https-only"
                ) and config.get("certificate"):
                    resource_encryption_config = True
                else:
                    resource_encryption_config = False

        if resource_encryption_config and not unencrypted_resources:
            return {
                "encrypted": {
                    "config": resource_encryption_config,
                }
            }
        elif not resource_encryption_config or unencrypted_resources:
            return {
                "unencrypted": {
                    "config": resource_encryption_config,
                    "unencrypted_resources": unencrypted_resources,
                }
            }
        else:
            return {
                "unknown-encryption": {
                    "config": resource_encryption_config,
                    "unencrypted_resources": unencrypted_resources,
                }
            }

    def resource_status(self, resource_arn, resource_values):
        self.logger.info("Calculating encryption for resource: %s", resource_arn)

        config = resource_values.get("config", {})
        if config:
            if config.get("status"):
                if config.get("status") == "running":
                    return {"running": config.get("status")}
                else:
                    return {"not-running": config.get("status")}
            if config.get("attached"):
                if config.get("attached") is True:
                    return {"attached": config.get("attached")}
                else:
                    return {"non-attached": config.get("attached")}
            return {"unknown": {}}

    def resource_environment(self, resource_arn, resource_values):
        self.logger.info("Calculating encryption for resource: %s", resource_arn)
