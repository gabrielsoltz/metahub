"""ResourceType: AwsElastiCacheReplicationGroup"""

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
        if self.endpoint():
            return True
        return False

    def associations(self):
        associations = {}
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
