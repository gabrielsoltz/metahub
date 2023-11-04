"""MetaCheck: AwsEc2Vpc"""

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import MetaChecksBase


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
        self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
        # Describe
        self.vpc = self.describe_vpcs()
        if not self.vpc:
            return False
        # Drilled MetaChecks
        self.subnets = self.describe_subnets()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[1]
            if not drilled
            else drilled.split("/")[1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

    # Describe functions

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

    def cidr(self):
        if self.vpc:
            if self.vpc.get("CidrBlock"):
                return self.vpc.get("CidrBlock")
        return False

    def is_default(self):
        if self.vpc:
            if self.vpc["IsDefault"]:
                return True
        return False

    def associations(self):
        associations = {
            "subnets": self.subnets,
        }
        return associations

    def checks(self):
        checks = {
            "cidr": self.cidr(),
            "is_default": self.is_default(),
        }
        return checks
