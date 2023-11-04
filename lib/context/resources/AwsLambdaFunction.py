"""MetaCheck: AwsLambdaFunction"""

import json

from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import MetaChecksBase
from lib.context.resources.MetaChecksHelpers import PolicyHelper


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
        self.client = get_boto3_client(self.logger, "lambda", self.region, self.sess)
        # Describe
        self.function = self.describe_function()
        if not self.function:
            return False
        self.function_vpc_config = self._describe_function_vpc_config()
        self.function_url_config = self.get_function_url_config()
        # Resource Policy
        self.resource_policy = self.describe_resource_policy()
        # Drilled MetaChecks
        self.iam_roles = self._describe_function_iam_roles()
        self.security_groups = self._describe_function_security_groups()
        self.vpcs = self._describe_function_vpc_config_vpc()
        self.subnets = self._describe_function_vpc_config_subnet()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]

    # Describe Functions

    def describe_function(self):
        try:
            response = self.client.get_function(
                FunctionName=self.resource_arn
                #            Qualifier='string'
            )
            return response.get("Configuration")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to describe_function {}, {}".format(self.resource_id, err)
                )
        return False

    def _describe_function_vpc_config(self):
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

    def _describe_function_security_groups(self):
        security_groups = {}
        if self.function_vpc_config:
            if self.function_vpc_config.get("SecurityGroupIds"):
                for sg in self.function_vpc_config["SecurityGroupIds"]:
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

    def _describe_function_iam_roles(self):
        iam_roles = {}
        if self.function:
            if self.function.get("Role"):
                role_arn = self.function["Role"]
                iam_roles[role_arn] = {}
        return iam_roles

    def _describe_function_vpc_config_vpc(self):
        vpc = {}
        if self.function_vpc_config:
            if self.function_vpc_config["VpcId"]:
                arn = generate_arn(
                    self.function_vpc_config["VpcId"],
                    "ec2",
                    "vpc",
                    self.region,
                    self.account,
                    self.partition,
                )
                vpc[arn] = {}
        return vpc

    def _describe_function_vpc_config_subnet(self):
        subnet = {}
        if self.function_vpc_config:
            if self.function_vpc_config["SubnetIds"]:
                for subnet_id in self.function_vpc_config["SubnetIds"]:
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

    def is_unrestricted(self):
        if self.resource_policy:
            if self.resource_policy["is_unrestricted"]:
                return self.resource_policy["is_unrestricted"]
        return False

    def endpoint(self):
        if self.function:
            if self.function_url_config:
                if self.function_url_config["FunctionUrl"]:
                    return self.function_url_config["FunctionUrl"]
        return False

    def is_public(self):
        public_dict = {}
        if self.function:
            if self.function_url_config:
                if self.endpoint() and self.function_url_config["AuthType"] == "NONE":
                    public_dict[self.endpoint()] = []
                    from_port = "443"
                    to_port = "443"
                    ip_protocol = "tcp"
                    public_dict[self.endpoint()].append(
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
            "vpcs": self.vpcs,
            "subnets": self.subnets,
            "security_groups": self.security_groups,
            "iam_roles": self.iam_roles,
        }
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.resource_policy,
            "is_unrestricted": self.is_unrestricted(),
            "endpoint": self.endpoint(),
            "is_public": self.is_public(),
        }
        return checks
