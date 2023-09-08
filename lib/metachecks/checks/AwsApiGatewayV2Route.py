"""MetaCheck: AwsApiGatewayV2Route"""

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
            self.client = get_boto3_client(
                self.logger, "apigatewayv2", self.region, self.sess
            )
            # Describe
            self.app_id = self.resource_id.split("api-id:")[1].split(":")[0]
            self.route_id = self.resource_id.split("route-id:")[1].split(":")[0]
            self.route = self.get_route()
            if not self.route:
                return False
            self.route_authorization_type = self.route["AuthorizationType"]
            self.route_target = self.route["Target"]
            # Drilled MetaChecks

    # Describe function

    def get_route(self):
        try:
            response = self.client.get_route(ApiId=self.app_id, RouteId=self.route_id)
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_route: {}, {}".format(self.route_id, err)
                )
            return False
        return response

    # MetaChecks

    def it_has_authorization_type(self):
        if self.route_authorization_type:
            if self.route_authorization_type != "NONE":
                return self.route_authorization_type
        return False

    def checks(self):
        checks = ["it_has_authorization_type"]
        return checks
