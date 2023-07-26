"""MetaCheck: AwsLambdaFunction"""

import json

from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import PolicyHelper


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        metachecks,
        mh_filters_checks,
        sess,
        drilled=False,
    ):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(
                self.logger, "lambda", self.region, self.sess
            )
            # Describe
            self.function = self.get_function()
            if not self.function:
                return False
            self.function_vpc = self.get_function_vpc()
            self.function_url_config = self.get_function_url_config()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy()
            # Drilled MetaChecks
            self.iam_roles = self.describe_iam_roles()
            self.security_groups = self.describe_security_groups()
            self.vpcs = self._describe_lambda_vpc()
            self.subnets = self._describe_lambda_subnet()

    # Describe Functions

    def get_function(self):
        try:
            response = self.client.get_function(
                FunctionName=self.resource_arn
                #            Qualifier='string'
            )
            return response.get("Configuration")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to get_function {}, {}".format(self.resource_id, err)
                )
        return False

    def get_function_vpc(self):
        if self.function:
            try:
                return self.function["VpcConfig"]
            except KeyError:
                return False
        return False

    def get_function_url_config(self):
        try:
            function_url_config = self.client.get_function_url_config(
                FunctionName=self.resource_arn
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            else:
                self.logger.error(
                    "Failed to get_function_url_config {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False

        return function_url_config

    # Resource Policy

    def describe_resource_policy(self):
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
                checked_policy = PolicyHelper(
                    self.logger, self.finding, json.loads(response["Policy"])
                ).check_policy()
                return checked_policy
        return False

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def describe_security_groups(self):
        security_groups = {}
        if self.function_vpc:
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

        return security_groups

    def describe_iam_roles(self):
        iam_roles = {}
        if self.function:
            if self.function.get("Role"):
                role_arn = self.function["Role"]
                iam_roles[role_arn] = {}
        return iam_roles

    def _describe_lambda_vpc(self):
        vpc = {}
        if self.function_vpc:
            if self.function_vpc["VpcId"]:
                arn = generate_arn(
                    self.function_vpc["VpcId"],
                    "ec2",
                    "vpc",
                    self.region,
                    self.account,
                    self.partition,
                )
                vpc[arn] = {}
        return vpc

    def _describe_lambda_subnet(self):
        subnet = {}
        if self.function_vpc:
            if self.function_vpc["SubnetIds"]:
                for subnet_id in self.function_vpc["SubnetIds"]:
                    arn = generate_arn(
                        subnet_id,
                        "ec2",
                        "subnet",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    subnet[arn] = {}
        return subnet

    # MetaChecks

    def it_has_resource_policy(self):
        return self.resource_policy

    def its_associated_with_vpc(self):
        if self.vpcs:
            return self.vpcs
        return False

    def its_associated_with_subnets(self):
        if self.subnets:
            return self.subnets
        return False

    def its_associated_with_security_groups(self):
        if self.security_groups:
            return self.security_groups
        return False

    def is_unrestricted(self):
        if self.resource_policy:
            if self.resource_policy["is_unrestricted"]:
                return True
        return False

    def its_associated_with_iam_roles(self):
        return self.iam_roles

    def it_has_endpoint(self):
        if self.function:
            if self.function_url_config:
                if self.function_url_config["FunctionUrl"]:
                    return self.function_url_config["FunctionUrl"]
        return False

    def is_public(self):
        public_dict = {}
        if self.function:
            if self.function_url_config:
                if (
                    self.it_has_endpoint()
                    and self.function_url_config["AuthType"] == "NONE"
                ):
                    public_dict[self.it_has_endpoint()] = []
                    from_port = "443"
                    to_port = "443"
                    ip_protocol = "tcp"
                    public_dict[self.it_has_endpoint()].append(
                        {
                            "from_port": from_port,
                            "to_port": to_port,
                            "ip_protocol": ip_protocol,
                        }
                    )
        if public_dict:
            return public_dict
        return False

    def checks(self):
        checks = [
            "it_has_resource_policy",
            "its_associated_with_iam_roles",
            "its_associated_with_vpc",
            "its_associated_with_subnets",
            "its_associated_with_security_groups",
            "is_unrestricted",
            "it_has_endpoint",
            "is_public",
        ]
        return checks
