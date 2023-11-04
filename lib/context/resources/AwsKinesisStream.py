"""ResourceType: AwsKinesisStream"""

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
        self.client = get_boto3_client(self.logger, "kinesis", self.region, self.sess)
        # Describe
        self.stream = self.describe_stream()
        if not self.stream:
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

    def describe_stream(self):
        try:
            response = self.client.describe_stream(StreamName=self.resource_id).get(
                "StreamDescription"
            )
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to describe_stream: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    # Context Config

    def is_encrypted(self):
        if self.stream["EncryptionType"] != "NONE":
            return self.stream["EncryptionType"]
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
            "is_encrypted": self.is_encrypted(),
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
