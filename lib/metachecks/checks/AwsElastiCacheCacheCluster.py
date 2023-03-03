"""MetaCheck: AwsElastiCacheCacheCluster"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from lib.metachecks.checks.Base import MetaChecksBase

class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client("elasticache", region_name=region)
                self.ec2_client = boto3.client("ec2", region_name=region)
            else:
                self.client = sess.client(service_name="elasticache", region_name=region)
                self.ec2_client = sess.client(service_name="ec2", region_name=region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.elasticcache_cluster = self._describe_cache_clusters()
            self.elasticcache_cluster_security_groups_rules = self._describe_security_group_rules()
    
    # Describe functions

    def _describe_cache_clusters(self):
        try:
            response = self.client.describe_cache_clusters(
                CacheClusterId=self.resource_id,
                # ShowCacheNodeInfo=True|False,
                # ShowCacheClustersNotInReplicationGroups=True|False
            )
        except ClientError as e:
            return False
        if response["CacheClusters"]:
            return response["CacheClusters"][0]
        return False

    def _describe_security_group_rules(self):
        Rules = []
        if self.its_associated_with_security_groups():
            response = self.ec2_client.describe_security_group_rules(
                Filters=[
                    {
                        "Name": "group-id",
                        "Values": self.its_associated_with_security_groups(),
                    },
                ],
            )
            Rules.append(response["SecurityGroupRules"])
        if Rules:
            return Rules
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
        SG = []
        if self.elasticcache_cluster:
            for sg in self.elasticcache_cluster["SecurityGroups"]:
                SG.append(sg["SecurityGroupId"])
        if SG:
            return SG
        return False

    def its_associated_with_security_group_rules_unrestricted(self):
        UnrestrictedRule = []
        if self.elasticcache_cluster_security_groups_rules:
            for rule in self.elasticcache_cluster_security_groups_rules:
                if "CidrIpv4" in rule:
                    if "0.0.0.0/0" in rule["CidrIpv4"] and not rule["IsEgress"]:
                        if rule not in UnrestrictedRule:
                            UnrestrictedRule.append(rule)
                if "CidrIpv6" in rule:
                    if "::/0" in rule["CidrIpv6"] and not rule["IsEgress"]:
                        if rule not in UnrestrictedRule:
                            UnrestrictedRule.append(rule)
        if UnrestrictedRule:
            return UnrestrictedRule
        return False

    def checks(self):
        checks = [
            "is_rest_encrypted",
            "is_transit_encrypted",
            "is_encrypted",
            "its_associated_with_security_groups",
            "its_associated_with_security_group_rules_unrestricted"
        ]
        return checks