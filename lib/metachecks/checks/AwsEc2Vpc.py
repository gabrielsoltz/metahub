"""MetaCheck: AwsEc2Vpc"""

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase


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
            self.resource_id = (
                finding["Resources"][0]["Id"].split("/")[1]
                if not drilled
                else drilled.split("/")[1]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
            # Describe
            self.vpc = self.describe_vpcs()
            if not self.vpc:
                return False
            # Drilled MetaChecks
            self.subnets = self.describe_subnets()

    # Describe

    def describe_vpcs(self):
        try:
            response = self.client.describe_vpcs(
                VpcIds=[self.resource_id],
            )
            return response["Vpcs"][0]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchEntity":
                self.logger.error(
                    "Failed to describe_vpcs {}, {}".format(self.resource_id, err)
                )
        return False

    # Drilled MetaChecks

    def describe_subnets(self):
        subnets = {}
        try:
            response = self.client.describe_subnets(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [
                            self.resource_id,
                        ],
                    },
                ],
            )
            for subnet in response["Subnets"]:
                subnets[subnet["SubnetArn"]] = {}

        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchEntity":
                self.logger.error(
                    "Failed to describe_subnets {}, {}".format(self.resource_id, err)
                )

        return subnets

    # MetaChecks

    def is_default(self):
        if self.vpc:
            if self.vpc["IsDefault"]:
                return True
        return False

    def its_associated_with_subnets(self):
        if self.vpc:
            if self.subnets:
                return self.subnets
        return False

    def it_has_cidr(self):
        if self.vpc:
            if self.vpc.get("CidrBlock"):
                return self.vpc.get("CidrBlock")
        return False

    def checks(self):
        checks = [
            "is_default",
            "its_associated_with_subnets",
            "it_has_cidr",
        ]
        return checks
