"""MetaCheck: AwsElastiCacheCacheCluster"""

import boto3
from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        metachecks,
        mh_filters_checks,
        sess,
        drilled_down,
        drilled=False,
    ):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            self.mh_filters_checks = mh_filters_checks
            if not sess:
                self.client = boto3.client("elasticache", region_name=self.region)
            else:
                self.client = sess.client(
                    service_name="elasticache", region_name=self.region
                )
            self.resource_arn = finding["Resources"][0]["Id"]
            if finding["Resources"][0]["Id"].split(":")[5] == "cachecluster":
                self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            elif finding["Resources"][0]["Id"].split(":")[5] == "cluster":
                self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            else:
                self.logger.error(
                    "Error parsing elasticache cluster resource id: %s",
                    self.resource_arn,
                )
            self.elasticcache_cluster = self._describe_cache_clusters()
            # Drilled MetaChecks
            self.security_groups = self.describe_security_groups()
            if drilled_down:
                self.execute_drilled_metachecks()

    # Describe functions

    def _describe_cache_clusters(self):
        try:
            response = self.client.describe_cache_clusters(
                CacheClusterId=self.resource_id,
                ShowCacheNodeInfo=True,
                # ShowCacheClustersNotInReplicationGroups=True|False
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "CacheClusterNotFoundFault":
                self.logger.info(
                    "Failed to describe_cache_clusters: {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
            else:
                self.logger.error(
                    "Failed to describe_cache_clusters: {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
        if response["CacheClusters"]:
            return response["CacheClusters"][0]

        return False

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def describe_security_groups(self):
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

    # MetaChecks

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

    def its_associated_with_security_groups(self):
        if self.security_groups:
            return self.security_groups
        return False

    def its_associated_with_replication_group(self):
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["ReplicationGroupId"]:
                return self.elasticcache_cluster["ReplicationGroupId"]
        return False

    def it_has_endpoint(self):
        endpoints = []
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["CacheNodes"]:
                for node in self.elasticcache_cluster["CacheNodes"]:
                    if node["Endpoint"]:
                        endpoints.append(node["Endpoint"]["Address"])
        if endpoints:
            return endpoints
        return False

    def is_public(self):
        ingress = False
        if self.security_groups:
            for sg in self.security_groups:
                if self.security_groups[sg]["is_ingress_rules_unrestricted"]:
                    ingress = True
        if ingress:
            return True
        return False

    def checks(self):
        checks = [
            "is_rest_encrypted",
            "is_transit_encrypted",
            "is_encrypted",
            "its_associated_with_security_groups",
            "its_associated_with_replication_group",
            "it_has_endpoint",
            "is_public",
        ]
        return checks
