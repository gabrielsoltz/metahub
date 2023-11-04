"""ResourceType: AwsApiGatewayV2Route"""

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
        self.client = get_boto3_client(
            self.logger, "apigatewayv2", self.region, self.sess
        )
        # Describe Resource
        self.route = self.describe_route()
        if not self.route:
            return False
        # Associated MetaChecks
        self.api_gwv2_apis = self._describe_route_api()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[1] if not drilled else drilled
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled
        self.app_id = self.resource_id.split("api-id:")[1].split(":")[0]
        self.route_id = self.resource_id.split("route-id:")[1].split(":")[0]

    # Describe functions

    def describe_route(self):
        try:
            response = self.client.get_route(ApiId=self.app_id, RouteId=self.route_id)
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_route: {}, {}".format(self.route_id, err)
                )
            return False
        return response

    def _describe_route_api(self):
        api_gateway_api = {}
        arn = "arn:aws:apigateway2:{}:{}:/apis/{}".format(
            self.region, self.account, self.app_id
        )
        api_gateway_api[arn] = {}
        return api_gateway_api

    # Context Config

    def authorization_type(self):
        authorization_type = False
        if self.route:
            authorization_type = self.route.get("AuthorizationType")
        return authorization_type

    def route_target(self):
        route_target = False
        if self.route:
            route_target = self.route.get("Target")
        return route_target

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        return None

    def associations(self):
        associations = {
            "api_gateway_v2": self.api_gwv2_apis,
        }
        return associations

    def checks(self):
        checks = {
            "authorization_type": self.authorization_type(),
            "route_target": self.route_target(),
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
