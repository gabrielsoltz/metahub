"""MetaCheck: AwsElastiCacheCacheCluster"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from aws_arn import generate_arn

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import SecurityGroupChecker

class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = "aws"
            if not sess:
                self.client = boto3.client("elasticache", region_name=self.region)
            else:
                self.client = sess.client(service_name="elasticache", region_name=self.region)
            self.resource_arn = finding["Resources"][0]["Id"]
            if finding["Resources"][0]["Id"].split(":")[5] == "cachecluster":
                self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            elif finding["Resources"][0]["Id"].split(":")[5] == "cluster":
                self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            else:
                self.logger.error("Error parsing elasticache cluster resource id: %s", self.resource_arn)
            self.mh_filters_checks = mh_filters_checks
            self.elasticcache_cluster = self._describe_cache_clusters()
            # Security Groups
            self.security_groups = self.describe_security_groups(finding, sess)
    
    # Describe functions

    def _describe_cache_clusters(self):
        try:
            response = self.client.describe_cache_clusters(
                CacheClusterId=self.resource_id,
                ShowCacheNodeInfo=True,
                # ShowCacheClustersNotInReplicationGroups=True|False
            )
        except ClientError as e:
            return False
        if response["CacheClusters"]:
            return response["CacheClusters"][0]
            
        return False

    # Security Groups

    def describe_security_groups(self, finding, sess):
        sgs = {}
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["SecurityGroups"]:
                for sg in self.elasticcache_cluster["SecurityGroups"]:
                    arn = generate_arn(sg["SecurityGroupId"], "ec2", "security_group", self.region, self.account, self.partition)
                    details = SecurityGroupChecker(self.logger, finding, sgs, sess).check_security_group()
                    sgs[arn] = details
        if sgs:
            return sgs
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
            if self.elasticcache_cluster['CacheNodes']:
                for node in self.elasticcache_cluster['CacheNodes']:
                    if node['Endpoint']:
                        endpoints.append(node['Endpoint']['Address'])
        if endpoints:
            return endpoints
        return False

    def is_public(self):
        ingress = False
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
            "is_public"
        ]
        return checks