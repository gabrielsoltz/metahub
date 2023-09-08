"""MetaCheck: AwsApiGatewayV2Stage"""

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
                finding["Resources"][0]["Id"].split(":")[-1]
                if not drilled
                else drilled.split(":")[-1]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(
                self.logger, "apigatewayv2", self.region, self.sess
            )
            # Describe
            self.app_id = self.resource_id.split("apis/")[1].split("/")[0]
            self.stage_name = self.resource_id.split("stages/")[1]
            self.stage = self.get_stage()
            if not self.stage:
                return False
            # Drilled MetaChecks
            self.api_gwv2_apis = self.it_associated_with_api_gateway_v2()

    # Describe function

    def get_stage(self):
        try:
            response = self.client.get_stage(
                ApiId=self.app_id, StageName=self.stage_name
            )
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_stage: {}, {}".format(self.stage_name, err)
                )
            return False
        return response

    def it_associated_with_api_gateway_v2(self):
        # temp
        api_gateway_api = {}
        arn = "arn:aws:apigateway2:{}:{}:/apis/{}".format(
            self.region, self.account, self.app_id
        )
        api_gateway_api[arn] = {}
        return api_gateway_api

    # MetaChecks

    def checks(self):
        checks = ["it_associated_with_api_gateway_v2"]
        return checks
