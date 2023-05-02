"""MetaCheck: AwsLambdaFunction"""

import json

import boto3
from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import (
    ResourceIamRoleChecker,
    ResourcePolicyChecker,
)


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            self.mh_filters_checks = mh_filters_checks
            if not sess:
                self.client = boto3.client("lambda", region_name=self.region)
            else:
                self.client = sess.client(
                    service_name="lambda", region_name=self.region
                )
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.function = self._get_function()
            self.function_vpc = self._get_function_vpc()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy(finding, sess)
            # Roles
            self.iam_roles = self.describe_iam_roles(finding, sess)
            # Drilled MetaChecks
            self.security_groups = self.describe_security_groups()
            self.execute_drilled_metachecks()

    # Describe Functions

    def _get_function(self):
        try:
            response = self.client.get_function(
                FunctionName=self.resource_arn
                #            Qualifier='string'
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            else:
                self.logger.error(
                    "Failed to get_function {}, {}".format(self.resource_id, err)
                )
                return False
        if response["Configuration"]:
            return response["Configuration"]
        return False

    def _get_function_vpc(self):
        if self.function:
            try:
                return self.function["VpcConfig"]
            except KeyError:
                return False
        return False

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def describe_security_groups(self):
        security_groups = {}
        if self.function_vpc.get("SecurityGroupIds"):
            for sg in self.function_vpc["SecurityGroupIds"]:
                arn = generate_arn(
                    sg,
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

    # Resource Policy

    def describe_resource_policy(self, finding, sess):
        if self.function:
            try:
                response = self.client.get_policy(
                    FunctionName=self.resource_arn
                    #            Qualifier='string'
                )
            except ClientError as err:
                if err.response["Error"]["Code"] == "ResourceNotFoundException":
                    return False
                else:
                    self.logger.error(
                        "Failed to get_policy {}, {}".format(self.resource_id, err)
                    )
                    return False
            if response["Policy"]:
                details = ResourcePolicyChecker(
                    self.logger, finding, json.loads(response["Policy"])
                ).check_policy()
                policy = {
                    "policy_checks": details,
                    "policy": json.loads(response["Policy"]),
                }
                return policy
        return False

    # IAM Roles

    def describe_iam_roles(self, finding, sess):
        roles = {}
        if self.function:
            try:
                role_arn = self.function["Role"]
                details = ResourceIamRoleChecker(
                    self.logger, finding, role_arn, sess
                ).check_role_policies()
                roles[role_arn] = details
            except KeyError:
                pass

        return roles

    # MetaChecks

    def it_has_resource_policy(self):
        return self.resource_policy

    def its_associated_with_vpc(self):
        if self.function_vpc:
            if self.function_vpc["VpcId"]:
                return self.function_vpc["VpcId"]
        return False

    def its_associated_with_security_groups(self):
        if self.security_groups:
            return self.security_groups
        return False

    def its_associated_with_subnets(self):
        if self.function_vpc:
            if self.function_vpc["SubnetIds"]:
                return self.function_vpc["SubnetIds"]
        return False

    def is_public(self):
        if self.resource_policy:
            if self.resource_policy["policy_checks"]["is_public"]:
                return True
        return False

    def its_associated_with_iam_roles(self):
        return self.iam_roles

    def checks(self):
        checks = [
            "it_has_resource_policy",
            "its_associated_with_iam_roles",
            "its_associated_with_vpc",
            "its_associated_with_security_groups",
            "its_associated_with_subnets",
            "is_public",
        ]
        return checks
