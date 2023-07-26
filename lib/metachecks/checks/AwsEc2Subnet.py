"""MetaCheck: AwsEc2Subnet"""

from aws_arn import generate_arn
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
            self.subnet = self.describe_subnets()
            if not self.subnet:
                return False
            # Drilled MetaChecks
            self.route_tables = self.describe_route_tables()

    # Describe
    def describe_subnets(self):
        try:
            response = self.client.describe_subnets(
                SubnetIds=[self.resource_id],
            )
            return response["Subnets"][0]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchEntity":
                self.logger.error(
                    "Failed to describe_subnets {}, {}".format(self.resource_id, err)
                )
            return False

    # Drilled MetaChecks
    def describe_route_tables(self):
        route_tables = {}
        if self.subnet:
            try:
                response = self.client.describe_route_tables(
                    Filters=[
                        {
                            "Name": "association.subnet-id",
                            "Values": [
                                self.resource_id,
                            ],
                        }
                    ],
                )
                if not response["RouteTables"]:
                    response = self.client.describe_route_tables(
                        Filters=[
                            {"Name": "association.main", "Values": ["true"]},
                            {"Name": "vpc-id", "Values": [self.subnet["VpcId"]]},
                        ],
                    )
                for route_table in response["RouteTables"]:
                    arn = generate_arn(
                        route_table["RouteTableId"],
                        "ec2",
                        "route_table",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    route_tables[arn] = {}

            except ClientError as err:
                if not err.response["Error"]["Code"] == "NoSuchEntity":
                    self.logger.error(
                        "Failed to describe_route_tables {}, {}".format(
                            self.resource_id, err
                        )
                    )

        return route_tables

    # MetaChecks

    def is_default(self):
        if self.subnet:
            if self.subnet.get("DefaultForAz"):
                return True
        return False

    def its_associated_with_route_tables(self):
        if self.route_tables:
            return self.route_tables
        return False

    def it_has_cidr(self):
        if self.subnet:
            if self.subnet.get("CidrBlock"):
                return self.subnet.get("CidrBlock")
        return False

    def it_has_map_public_ip_on_launch_enabled(self):
        if self.subnet:
            if self.subnet.get("MapPublicIpOnLaunch"):
                return self.subnet.get("MapPublicIpOnLaunch")
        return False

    def checks(self):
        checks = [
            "is_default",
            "its_associated_with_route_tables",
            "it_has_cidr",
            "it_has_map_public_ip_on_launch_enabled",
        ]
        return checks
