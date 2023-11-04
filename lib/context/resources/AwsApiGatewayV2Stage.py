"""MetaCheck: AwsApiGatewayV2Stage"""

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
        self.stage = self.describe_stage()
        if not self.stage:
            return False
        # Drilled MetaChecks
        self.api_gwv2_apis = self._describe_stage_api()
        self.waf_web_acls = self._describe_stage_waf_web_acls()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_id = (
            finding["Resources"][0]["Id"].split(":")[-1]
            if not drilled
            else drilled.split(":")[-1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled
        self.app_id = self.resource_id.split("apis/")[1].split("/")[0]
        self.stage_name = self.resource_id.split("stages/")[1]

    # Describe functions

    def describe_stage(self):
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

    def _describe_stage_api(self):
        api_gateway_api = {}
        arn = "arn:aws:apigateway2:{}:{}:/apis/{}".format(
            self.region, self.account, self.app_id
        )
        api_gateway_api[arn] = {}
        return api_gateway_api

    def _describe_stage_waf_web_acls(self):
        waf_web_acls = {}
        waf_web_acl_arn = self.stage.get("webAclArn")
        if waf_web_acl_arn:
            waf_web_acls[waf_web_acl_arn] = {}
        return waf_web_acls

    # MetaChecks

    def client_certificate_id(self):
        client_certificate_id = False
        if self.stage:
            client_certificate_id = self.stage.get("clientCertificateId")
        return client_certificate_id

    def associations(self):
        associations = {
            "api_gateway_v2": self.api_gwv2_apis,
            "waf_web_acls": self.waf_web_acls,
        }
        return associations

    def checks(self):
        checks = {
            "client_certificate_id": self.client_certificate_id(),
        }
        return checks
