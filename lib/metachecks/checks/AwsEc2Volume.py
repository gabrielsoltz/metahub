"""MetaCheck: AwsEc2Volume"""

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
            self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
            # Describe
            self.volume = self.describe_volumes()
            # Drilled MetaChecks

    # Describe function

    def describe_volumes(self):
        try:
            response = self.client.describe_volumes(VolumeIds=[self.resource_id])
            return response["Volumes"]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "InvalidVolume.NotFound":
                self.logger.error(
                    "Failed to describe_volumes {}, {}".format(self.resource_id, err)
                )
            return False

    # MetaChecks

    def is_encrypted(self):
        if self.volume:
            for ebs in self.volume:
                if ebs["Encrypted"]:
                    return True
        return False

    def is_attached(self):
        if self.volume:
            for ebs in self.volume:
                if ebs["Attachments"]:
                    return True
        return False

    def checks(self):
        checks = [
            "is_encrypted",
            "is_attached",
        ]
        return checks
