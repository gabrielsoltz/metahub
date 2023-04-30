"""MetaCheck: AwsEksCluster"""

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
                self.client = boto3.client("eks", region_name=self.region)
            else:
                self.client = sess.client(service_name="eks", region_name=self.region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.eks_cluster = self._describe_cluster()
            # Roles
            self.iam_roles = self.describe_iam_roles(finding, sess)
            # Security Groups
            self.security_groups = self.describe_security_groups(finding, sess)

    # Describe Functions

    def _describe_cluster(self):
        try:
            response = self.client.describe_cluster(
                name=self.resource_id
            )
        except ClientError as err:
                self.logger.error("Failed to describe_cluster: {}, {}".format(self.resource_id, err))
                return False
        if response["cluster"]:
            return response["cluster"]
        return False

    # Roles

    def describe_iam_roles(self, finding, sess):
        roles = {}
        if self.eks_cluster:
            if self.eks_cluster["roleArn"]:
                role_arn = self.eks_cluster["roleArn"]
                details = ResourceIamRoleChecker(self.logger, finding, role_arn, sess).check_role_policies()
                roles[role_arn] = details
        return roles

    # Security Groups

    def describe_security_groups(self, finding, sess):
        security_groups = {}
        if self.eks_cluster:
            if self.eks_cluster["resourcesVpcConfig"]["securityGroupIds"]:
                for security_group_id in self.eks_cluster["resourcesVpcConfig"]["securityGroupIds"]:
                    arn = generate_arn(security_group_id, "ec2", "security_group", self.region, self.account, self.partition)
                    security_groups[arn] = {}
                    details = SecurityGroupChecker(self.logger, finding, security_groups, sess).check_security_group()
                    security_groups[arn] = details
        return security_groups

    # MetaChecks Functions

    def its_associated_with_iam_roles(self):
        if self.eks_cluster:
            return self.iam_roles

    def its_associated_with_security_groups(self):
        if self.eks_cluster:
            return self.security_groups

    def it_has_endpoint(self):
        if self.eks_cluster:
            return self.eks_cluster.get("endpoint")

    def checks(self):
        checks = [
            "its_associated_with_iam_roles",
            "its_associated_with_security_groups",
            "it_has_endpoint"
        ]
        return checks