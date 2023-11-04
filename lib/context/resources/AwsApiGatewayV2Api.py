"""MetaCheck: AwsApiGatewayV2Api"""

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
        self.client = get_boto3_client(
            self.logger, "apigatewayv2", self.region, self.sess
        )
        # Describe Resource
        self.api = self.describe_api()
        if not self.api:
            return False
        self.authorizers = self.describe_authorizers()
        # Drilled Associations

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split(":")[-1].split("apis/")[1].split("/")[0]
            if not drilled
            else drilled.split(":")[-1].split("apis/")[1].split("/")[0]
        )

    # Describe functions

    def describe_api(self):
        try:
            response = self.client.get_api(ApiId=self.resource_id)
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_api: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    def describe_authorizers(self):
        try:
            response = self.client.get_authorizers(ApiId=self.resource_id).get("Items")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_authorizers: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    # MetaChecks

    def endpoint(self):
        if self.api["ApiEndpoint"]:
            return self.api["ApiEndpoint"]
        return False

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        if self.endpoint() and not self.authorizers:
            return True
        return False

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "endpoint": self.endpoint(),
            "authorizers": self.authorizers,
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
