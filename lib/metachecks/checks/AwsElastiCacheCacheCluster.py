"""MetaCheck: AwsElastiCacheCacheCluster"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import SecurityGroupChecker

class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client("elasticache", region_name=region)
            else:
                self.client = sess.client(service_name="elasticache", region_name=region)
            self.resource_arn = finding["Resources"][0]["Id"]
            if finding["Resources"][0]["Id"].split(":")[5] == "cachecluster":
                self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            elif finding["Resources"][0]["Id"].split(":")[5] == "cluster":
                self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            else:
                self.logger.error("Error parsing elasticache cluster resource id: %s", self.resource_arn)
            self.mh_filters_checks = mh_filters_checks
            self.elasticcache_cluster = self._describe_cache_clusters()
            self.elasticcache_cluster_sg = self._describe_cache_clusters_security_groups()
            if self.elasticcache_cluster_sg:
                self.checked_elasticcache_cluster_sg = SecurityGroupChecker(self.logger, finding, self.elasticcache_cluster_sg, sess).check_security_group()
    
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

    def _describe_cache_clusters_security_groups(self):
        SG = []
        if self.elasticcache_cluster:
            for sg in self.elasticcache_cluster["SecurityGroups"]:
                SG.append(sg["SecurityGroupId"])
        if SG:
            return SG
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
        if self.elasticcache_cluster_sg:
            return self.elasticcache_cluster_sg
        return False

    def its_associated_with_security_group_rules_ingress_unrestricted(self):
        if self.elasticcache_cluster_sg:
            if self.checked_elasticcache_cluster_sg["is_ingress_rules_unrestricted"]:
                return self.checked_elasticcache_cluster_sg["is_ingress_rules_unrestricted"]
        return False

    def its_associated_with_security_group_rules_egress_unrestricted(self):
        if self.elasticcache_cluster_sg:
            if self.checked_elasticcache_cluster_sg["is_egress_rule_unrestricted"]:
                return self.checked_elasticcache_cluster_sg["is_egress_rule_unrestricted"]
        return False

    def its_associated_with_replication_group(self):
        if self.elasticcache_cluster:
            if self.elasticcache_cluster["ReplicationGroupId"]:
                return self.elasticcache_cluster["ReplicationGroupId"]
        return False

    def checks(self):
        checks = [
            "is_rest_encrypted",
            "is_transit_encrypted",
            "is_encrypted",
            "its_associated_with_security_groups",
            "its_associated_with_security_group_rules_ingress_unrestricted",
            "its_associated_with_security_group_rules_egress_unrestricted",
            "its_associated_with_replication_group"
        ]
        return checks