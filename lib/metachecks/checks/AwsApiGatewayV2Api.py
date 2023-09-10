"""MetaCheck: AwsApiGatewayV2Api"""

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
                finding["Resources"][0]["Id"]
                .split(":")[-1]
                .split("apis/")[1]
                .split("/")[0]
                if not drilled
                else drilled.split(":")[-1].split("apis/")[1].split("/")[0]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(
                self.logger, "apigatewayv2", self.region, self.sess
            )
            # Describe
            self.api = self.get_api()
            if not self.api:
                return False
            self.authorizers = self.get_authorizers()
            # Drilled MetaChecks

    # Describe function

    def get_api(self):
        try:
            response = self.client.get_api(ApiId=self.resource_id)
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_api: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    def get_authorizers(self):
        try:
            response = self.client.get_api(ApiId=self.resource_id).get("Items")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_authorizers: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    # MetaChecks

    def it_has_endpoint(self):
        if self.api["ApiEndpoint"]:
            return self.api["ApiEndpoint"]
        return False

    def it_has_authorizers(self):
        if self.authorizers:
            return self.authorizers
        return False

    def is_public(self):
        public_dict = {}
        if self.it_has_endpoint() and not self.it_has_authorizers():
            public_dict[self.it_has_endpoint()] = {
                "from_port": 443,
                "to_port": 443,
                "ip_protocol": "tcp",
            }
        if public_dict:
            return public_dict
        return False

    def checks(self):
        checks = ["it_has_endpoint", "it_has_authorizers", "is_public"]
        return checks
