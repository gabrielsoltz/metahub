"""ResourceType: AwsDynamoDbTable"""

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
        self.client = get_boto3_client(self.logger, "dynamodb", self.region, self.sess)
        # Describe
        self.table = self.describe_table()
        if not self.table:
            return False
        # Associated MetaChecks

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

    # Describe function

    def describe_table(self):
        try:
            response = self.client.describe_table(TableName=self.resource_id).get(
                "Table"
            )
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to describe_table: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    # Context Config

    def name(self):
        return self.table.get("TableName")

    def sse_description(self):
        if self.table.get("SSEDescription"):
            return self.table.get("SSEDescription")
        return False

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        return None

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "name": self.name(),
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
