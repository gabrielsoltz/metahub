"""MetaCheck: AwsEc2RouteTable"""

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
            self.route_table = self.describe_route_tables()
            if not self.route_table: return False
            # Drilled MetaChecks

    # Drilled MetaChecks
    def describe_route_tables(self):
        try:
            response = self.client.describe_route_tables(
                RouteTableIds=[self.resource_id],
            )
            return response["RouteTables"][0]

        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchEntity":
                self.logger.error(
                    "Failed to describe_route_tables {}, {}".format(
                        self.resource_id, err
                    )
                )
            return False

    # MetaChecks
    def is_default(self):
        if self.route_table:
            if (
                self.route_table.get("Associations")
                and self.route_table.get("Associations")[0]["Main"]
            ):
                return True
        return False

    def it_has_route_to_internet_gateway(self):
        routes_to_internet_gateway = []
        if self.route_table:
            if self.route_table.get("Routes"):
                for route in self.route_table.get("Routes"):
                    if route.get("GatewayId") and route.get("GatewayId").startswith(
                        "igw-"
                    ):
                        routes_to_internet_gateway.append(route)
        return routes_to_internet_gateway

    def it_has_route_to_nat_gateway(self):
        routes_to_nat_gateway = []
        if self.route_table:
            if self.route_table.get("Routes"):
                for route in self.route_table.get("Routes"):
                    if route.get("NatGatewayId"):
                        routes_to_nat_gateway.append(route)
        return routes_to_nat_gateway

    def it_has_route_to_transit_gateway(self):
        routes_to_transit_gateway = []
        if self.route_table:
            if self.route_table.get("Routes"):
                for route in self.route_table.get("Routes"):
                    if route.get("TransitGatewayId"):
                        routes_to_transit_gateway.append(route)
        return routes_to_transit_gateway

    def it_has_route_to_vpc_peering(self):
        routes_to_vpc_peering = []
        if self.route_table:
            if self.route_table.get("Routes"):
                for route in self.route_table.get("Routes"):
                    if route.get("VpcPeeringConnectionId"):
                        routes_to_vpc_peering.append(route)
        return routes_to_vpc_peering

    def checks(self):
        checks = [
            "is_default",
            "it_has_route_to_internet_gateway",
            "it_has_route_to_nat_gateway",
            "it_has_route_to_transit_gateway",
            "it_has_route_to_vpc_peering",
        ]
        return checks
