"""ResourceType: AwsEc2Subnet"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import ContextBase


class Metacheck(ContextBase):
    def __init__(
        self,
        logger,
        finding,
        mh_filters_config,
        sess,
        drilled=False,
    ):
        self.logger = logger
        self.sess = sess
        self.mh_filters_config = mh_filters_config
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
        # Describe
        self.subnet = self.describe_subnets()
        if not self.subnet:
            return False
        # Associated MetaChecks
        self.route_tables = self.describe_route_tables()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[1]
            if not drilled
            else drilled.split("/")[1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

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

    # Associated MetaChecks
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

    # Context Config

    def cidr(self):
        if self.subnet:
            if self.subnet.get("CidrBlock"):
                return self.subnet.get("CidrBlock")
        return False

    def map_public_ip_on_launch_enabled(self):
        if self.subnet:
            if self.subnet.get("MapPublicIpOnLaunch"):
                return self.subnet.get("MapPublicIpOnLaunch")
        return False

    def default(self):
        if self.subnet:
            if self.subnet.get("DefaultForAz"):
                return True
        return False

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        if self.map_public_ip_on_launch_enabled():
            return True
        return False

    def associations(self):
        associations = {
            "route_tables": self.route_tables,
        }
        return associations

    def checks(self):
        checks = {
            "cidr": self.cidr(),
            "map_public_ip_on_launch_enabled": self.map_public_ip_on_launch_enabled(),
            "default": self.default(),
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
