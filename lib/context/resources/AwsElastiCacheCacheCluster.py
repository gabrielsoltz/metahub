"""MetaCheck: AwsElastiCacheCacheCluster"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        mh_filters_checks,
        sess,
        drilled=False,
    ):
        self.logger = logger
        self.sess = sess
        self.mh_filters_checks = mh_filters_checks
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(
            self.logger, "elasticache", self.region, self.sess
        )
        # Describe
        self.elasticcache_cluster = self.describe_cache_clusters()
        if not self.elasticcache_cluster:
            return False
        # Drilled MetaChecks
        self.security_groups = self._describe_cache_clusters_security_groups()
        self.replication_group = self._describe_cache_clusters_replication_groups()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_type = finding["Resources"][0]["Type"]
        if finding["Resources"][0]["Id"].split(":")[5] == "cachecluster":
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
        elif finding["Resources"][0]["Id"].split(":")[5] == "cluster":
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
        else:
            self.logger.error(
                "Error parsing elasticache cluster resource id: %s",
                self.resource_arn,
            )
            self.resource_id = finding["Resources"][0]["Id"]

    # Describe functions

    def describe_cache_clusters(self):
        try:
            response = self.client.describe_cache_clusters(
                CacheClusterId=self.resource_id,
                ShowCacheNodeInfo=True,
                # ShowCacheClustersNotInReplicationGroups=True|False
            )
            if response["CacheClusters"]:
                return response["CacheClusters"][0]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "CacheClusterNotFoundFault":
                self.logger.error(
                    "Failed to describe_cache_clusters: {}, {}".format(
                        self.resource_id, err
                    )
                )
        return False

    def _describe_cache_clusters_security_groups(self):
        security_groups = {}
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["SecurityGroups"]:
                for sg in self.elasticcache_cluster["SecurityGroups"]:
                    arn = generate_arn(
                        sg["SecurityGroupId"],
                        "ec2",
                        "security_group",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    security_groups[arn] = {}
        if security_groups:
            return security_groups
        return False

    def _describe_cache_clusters_replication_groups(self):
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["ReplicationGroupId"]:
                arn = generate_arn(
                    self.elasticcache_cluster["ReplicationGroupId"],
                    "elasticache",
                    "replication_group",
                    self.region,
                    self.account,
                    self.partition,
                )
                return {arn: {}}
        return False

    # MetaChecks

    def endpoint(self):
        endpoints = []
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["CacheNodes"]:
                for node in self.elasticcache_cluster["CacheNodes"]:
                    if node["Endpoint"]:
                        endpoints.append(node["Endpoint"]["Address"])
        if endpoints:
            return endpoints
        return False

    def is_rest_encrypted(self):
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["AtRestEncryptionEnabled"]:
                return True
        return False

    def is_transit_encrypted(self):
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["TransitEncryptionEnabled"]:
                return True
        return False

    def is_encrypted(self):
        if self.elasticcache_cluster:
            if self.is_rest_encrypted() and self.is_transit_encrypted():
                return True
        return False

    def is_public(self):
        public_dict = {}
        if self.endpoint():
            for endpoint in self.endpoint():
                for sg in self.security_groups:
                    if self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                        public_dict[endpoint] = []
                        for rule in self.security_groups[sg].get(
                            "is_ingress_rules_unrestricted"
                        ):
                            from_port = rule.get("FromPort")
                            to_port = rule.get("ToPort")
                            ip_protocol = rule.get("IpProtocol")
                            public_dict[endpoint].append(
                                {
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "ip_protocol": ip_protocol,
                                }
                            )
        if public_dict:
            return public_dict
        return False

    def associations(self):
        associations = {
            "security_groups": self.security_groups,
            "replication_group": self.replication_group,
        }
        return associations

    def checks(self):
        checks = {
            "endpoint": self.endpoint(),
            "is_rest_encrypted": self.is_rest_encrypted(),
            "is_transit_encrypted": self.is_transit_encrypted(),
            "is_encrypted": self.is_encrypted(),
            "is_public": self.is_public(),
        }
        return checks
