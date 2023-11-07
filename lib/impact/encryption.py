class Encryption:
    def __init__(self, logger):
        self.logger = logger

    def get_encryption(self, resource_arn, resource_values):
        self.logger.info("Calculating encryption for resource: %s", resource_arn)

        unencrypted_resources = []

        associations = resource_values.get("associations", {})
        if associations:
            # Associated with EBS Volumes or Snapshots
            associated_volumes = resource_values.get("associations").get("volumes")
            if associated_volumes:
                for id, config in associated_volumes.items():
                    if config:
                        volume_encryption = config.get("config").get("encrypted")
                        if not volume_encryption:
                            unencrypted_resources.append(id)
            associated_snapshots = resource_values.get("associations").get("snapshots")
            if associated_snapshots:
                for id, config in associated_snapshots.items():
                    if config:
                        snapshot_encryption = config.get("config").get("encrypted")
                        if not snapshot_encryption:
                            unencrypted_resources.append(id)

        resource_type = resource_values.get("ResourceType")
        config = resource_values.get("config", {})
        resource_encryption_config = None
        # Configuration by resource type
        if config:
            if resource_type in (
                "AwsRdsDbCluster",
                "AwsRdsDbInstance",
                "AwsEc2Volume",
                "AwsEc2Volume",
            ):
                resource_encryption_config = False
                if config.get("encrypted"):
                    resource_encryption_config = True

            if resource_type in (
                "AwsElasticsearchDomain",
                "AwsElastiCacheCacheCluster",
            ):
                resource_encryption_config = False
                if config.get("at_rest_encryption") and config.get(
                    "transit_encryption"
                ):
                    resource_encryption_config = True

            if resource_type in ("AwsS3Bucket"):
                resource_encryption_config = False
                if config.get("bucket_encryption"):
                    resource_encryption_config = True

            if resource_type in ("AwsCloudFrontDistribution"):
                resource_encryption_config = False
                if (
                    config.get("viewer_protocol_policy") == "redirect-to-https"
                    or config.get("viewer_protocol_policy") == "https-only"
                ) and config.get("certificate"):
                    resource_encryption_config = True

            if resource_type in ("AwsSqsQueue"):
                resource_encryption_config = False
                if config.get("sse_enabled"):
                    resource_encryption_config = True

        if (not config and not associations) or (
            resource_encryption_config is None and not unencrypted_resources
        ):
            return {
                "unknown": {
                    "config": resource_encryption_config,
                    "unencrypted_resources": unencrypted_resources,
                }
            }
        elif resource_encryption_config and not unencrypted_resources:
            return {
                "encrypted": {
                    "config": resource_encryption_config,
                }
            }
        else:
            return {
                "unencrypted": {
                    "config": resource_encryption_config,
                    "unencrypted_resources": unencrypted_resources,
                }
            }
