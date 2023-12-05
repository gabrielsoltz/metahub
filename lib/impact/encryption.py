from lib.impact.helpers import check_key, get_associated_resources, get_config_key


class Encryption:
    def __init__(self, logger):
        self.logger = logger

    def get_encryption(self, resource_arn, resource_values):
        self.logger.info("Calculating encryption for resource: %s", resource_arn)

        resource_type = resource_values.get("ResourceType")
        unencrypted_resources = []

        # Associated Volumes
        associated_volumes = get_associated_resources(resource_values, "volumes")
        if associated_volumes:
            for id, config in associated_volumes.items():
                encrypted = get_config_key(config, "encrypted")
                if encrypted is False:
                    unencrypted_resources.append(id)

        # Associated Snapshots
        associated_snapshots = get_associated_resources(resource_values, "snapshots")
        if associated_snapshots:
            for id, config in associated_snapshots.items():
                encrypted = get_config_key(config, "encrypted")
                if encrypted is False:
                    unencrypted_resources.append(id)

        # Check Encryption at Resouce Configuration Level
        resource_encryption_config = None

        if resource_type in (
            "AwsRdsDbCluster",
            "AwsRdsDbInstance",
            "AwsEc2Volume",
            "AwsEc2Volume",
            "AwsAthenaWorkGroup",
        ):
            resource_encryption_config = get_config_key(resource_values, "encrypted")

        if resource_type in (
            "AwsElasticsearchDomain",
            "AwsElastiCacheCacheCluster",
            "AwsElastiCacheReplicationGroup",
        ):
            resource_encryption_config = False
            at_rest_encryption = get_config_key(resource_values, "at_rest_encryption")
            transit_encryption = get_config_key(resource_values, "transit_encryption")
            if at_rest_encryption and transit_encryption:
                resource_encryption_config = True

        if resource_type in ("AwsS3Bucket"):
            resource_encryption_config = get_config_key(
                resource_values, "bucket_encryption"
            )

        if resource_type in ("AwsCloudFrontDistribution"):
            resource_encryption_config = False
            viewer_protocol_policy = get_config_key(
                resource_values, "at_rest_encryption"
            )
            if (
                viewer_protocol_policy == "redirect-to-https"
                or viewer_protocol_policy == "https-only"
            ):
                resource_encryption_config = True

        if resource_type in ("AwsSqsQueue"):
            resource_encryption_config = get_config_key(resource_values, "sse_enabled")

        encryption_checks = {
            "unencrypted_resources": unencrypted_resources,
            "resource_encryption_config": resource_encryption_config,
        }

        # If no config and no associations, return unknown
        if not check_key(resource_values, "config") and not check_key(
            resource_values, "associations"
        ):
            return {"unknown": encryption_checks}

        # Resources without unencrypted resources and no encryption config are unknown.
        if not unencrypted_resources and resource_encryption_config is None:
            return {"unknown": encryption_checks}

        if unencrypted_resources or resource_encryption_config is False:
            return {"unencrypted": encryption_checks}

        return {"encrypted": encryption_checks}
