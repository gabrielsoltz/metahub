"""MetaCheck: AwsKinesisStream"""

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
                self.logger, "kinesis", self.region, self.sess
            )
            # Describe
            self.stream = self.describe_stream()
            if not self.stream:
                return False
            # Drilled MetaChecks

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

    def checks(self):
        checks = [
            "is_encrypted",
        ]
        return checks
