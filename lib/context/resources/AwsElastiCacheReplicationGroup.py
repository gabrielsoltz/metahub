"""ResourceType: AwsElastiCacheReplicationGroup"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import ContextBase


class Metacheck(ContextBase):
    def __init__(
        self,
        logger,
        finding,
        mh_filters_config,
        sess,
        drilled=False,
    ):
        self.logger = logger
        self.sess = sess
        self.mh_filters_config = mh_filters_config
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(
            self.logger, "elasticache", self.region, self.sess
        )
        # Describe
        self.replication_group = self.describe_replication_groups()
        if not self.replication_group:
            return False
        # Associated MetaChecks
        self.cache_clusters = self._describe_replication_group_cache_cluster()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_type = finding["Resources"][0]["Type"]
        if finding["Resources"][0]["Id"].split(":")[5] == "replicationgroup":
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
        else:
            self.logger.error(
                "Error parsing elasticache cluster resource id: %s",
                self.resource_arn,
            )
            self.resource_id = finding["Resources"][0]["Id"]

    # Describe functions

    def describe_replication_groups(self):
        try:
            response = self.client.describe_replication_groups(
                ReplicationGroupId=self.resource_id,
            )
            if response["ReplicationGroups"]:
                return response["ReplicationGroups"][0]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                self.logger.error(
                    "Failed to describe_replication_groups: {}, {}".format(
                        self.resource_id, err
                    )
                )
        return False

    def _describe_replication_group_cache_cluster(self):
        cache_clusters = {}
        if self.replication_group:
            if self.replication_group["NodeGroups"]:
                for cache_cluster in self.replication_group["NodeGroups"][0][
                    "NodeGroupMembers"
                ]:
                    arn = generate_arn(
                        cache_cluster["CacheClusterId"],
                        "elasticache",
                        "cache_cluster",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    cache_clusters[arn] = {}
        return cache_clusters

    # Context Config

    def endpoint(self):
        endpoints = []
        if self.replication_group:
            if self.replication_group.get("ConfigurationEndpoint"):
                return self.replication_group["ConfigurationEndpoint"]["Address"]
        if endpoints:
            return endpoints
        return False

    def at_rest_encryption(self):
        if self.replication_group:
            if self.replication_group["AtRestEncryptionEnabled"]:
                return True
        return False

    def transit_encryption(self):
        if self.replication_group:
            if self.replication_group["TransitEncryptionEnabled"]:
                return True
        return False

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        if self.cache_clusters:
            for cache_cluster, value in self.cache_clusters.items():
                return value["config"]["public"]
        if self.endpoint():
            return True
        return False

    def get_upstream_security_groups(self):
        if self.cache_clusters:
            for cache_cluster, value in self.cache_clusters.items():
                return value["associations"]["security_groups"]

    def get_upstream_vpcs(self):
        if self.cache_clusters:
            for cache_cluster, value in self.cache_clusters.items():
                return value["associations"]["vpcs"]

    def associations(self):
        associations = {
            "cache_clusters": self.cache_clusters,
            "security_groups": self.get_upstream_security_groups(),
            "vpcs": self.get_upstream_vpcs(),
        }
        return associations

    def checks(self):
        checks = {
            "endpoint": self.endpoint(),
            "rest_encrypted": self.at_rest_encryption(),
            "transit_encrypted": self.transit_encryption(),
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
