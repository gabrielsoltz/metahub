"""MetaCheck: AwsRdsDbCluster"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from aws_arn import generate_arn

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import SecurityGroupChecker, ResourceIamRoleChecker

class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = "aws"
            if not sess:
                self.client = boto3.client("rds", region_name=self.region)
            else:
                self.client = sess.client(service_name="rds", region_name=self.region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.rds_cluster = self._describe_db_clusters()
            # Roles
            self.iam_roles = self.describe_iam_roles(finding, sess)
            # Security Groups
            self.security_groups = self.describe_security_groups(finding, sess)

    # Describe Functions

    def _describe_db_clusters(self):
        try:
            response = self.client.describe_db_clusters(
                DBClusterIdentifier=self.resource_id
            )
        except ClientError as err:
                self.logger.error("Failed to describe_db_clusters: {}, {}".format(self.resource_id, err))
                return False
        if response["DBClusters"]:
            return response["DBClusters"][0]
        return False

    # Roles

    def describe_iam_roles(self, finding, sess):
        roles = {}
        if self.rds_cluster:
            if self.rds_cluster["AssociatedRoles"]:
                for role in self.rds_cluster["AssociatedRoles"]:
                    role_arn = role["RoleArn"]
                    details = ResourceIamRoleChecker(self.logger, finding, role_arn, sess).check_role_policies()
                    roles[role_arn] = details
        return roles

    # Security Groups

    def describe_security_groups(self, finding, sess):
        security_groups = {}
        if self.rds_cluster:
            if self.rds_cluster["VpcSecurityGroups"]:
                for sg in self.rds_cluster["VpcSecurityGroups"]:
                    sg_id = sg["VpcSecurityGroupId"]
                    arn = generate_arn(sg_id, "ec2", "security_group", self.region, self.account, self.partition)
                    security_groups[arn] = {}
                    details = SecurityGroupChecker(self.logger, finding, security_groups, sess).check_security_group()
                    security_groups[arn] = details
        return security_groups

    # MetaChecks

    def its_assoaciated_with_iam_roles(self):
        if self.rds_cluster:
            return self.iam_roles
        return False

    def its_associated_with_security_groups(self):
        if self.rds_cluster:
            return self.security_groups
        return False

    def is_public(self):
        ingress = False
        if self.security_groups:
            for sg in self.security_groups:
                if self.security_groups[sg]["is_ingress_rules_unrestricted"]:
                    ingress = True
        if self.rds_cluster:
            if self.rds_cluster.get("PubliclyAccessible") and ingress:
                return True
        return False

    
    def checks(self):
        checks = [
            "its_assoaciated_with_iam_roles",
            "its_associated_with_security_groups",
            "is_public"
        ]
        return checks