"""MetaCheck: AwsKinesisStream"""

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
        self.client = get_boto3_client(self.logger, "kinesis", self.region, self.sess)
        # Describe
        self.stream = self.describe_stream()
        if not self.stream:
            return False
        # Drilled MetaChecks

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
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

    # MetaChecks

    def is_encrypted(self):
        if self.stream["EncryptionType"] != "NONE":
            return self.stream["EncryptionType"]
        return False

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "is_encrypted": self.is_encrypted(),
        }
        return checks
