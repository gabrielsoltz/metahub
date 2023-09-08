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

    # MetaChecks

    def it_has_endpoint(self):
        if self.api["ApiEndpoint"]:
            return self.api["ApiEndpoint"]
        return False

    def checks(self):
        checks = ["it_has_endpoint"]
        return checks
