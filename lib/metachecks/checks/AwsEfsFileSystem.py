"""MetaCheck: AwsEfsFileSystem"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError
from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase
import json
from lib.metachecks.checks.MetaChecksHelpers import PolicyHelper


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
                self.logger, "efs", self.region, self.sess
            )
            # Describe
            self.fs = self.describe_file_systems()
            if not self.fs:
                return False
            self.fs_policy = self.describe_file_system_policy()
            # Drilled MetaChecks

    # Describe function

    def describe_file_systems(self):
        try:
            response = self.client.describe_file_systems(
                    FileSystemId=self.resource_id
            ).get("FileSystems")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "FileSystemNotFound":
                self.logger.error(
                    "Failed to describe_file_systems: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    def describe_file_system_policy(self):
        if self.fs:
            try:
                response = self.client.describe_file_system_policy(FileSystemId=self.resource_id)
            except ClientError as err:
                if not err.response["Error"]["Code"] == "PolicyNotFound":
                    self.logger.error(
                        "Failed to describe_file_system_policy {}, {}".format(self.resource_id, err)
                    )
                return False

            if response["Policy"]:
                policy_json = json.loads(response["Policy"])
                checked_policy = PolicyHelper(
                    self.logger, self.finding, policy_json
                ).check_policy()
                return checked_policy

        return False

    # MetaChecks

    def is_encrypted(self):
        if self.fs[0]["Encrypted"]:
            return True
        return False
    
    def it_has_mount_targets(self):
        if self.fs[0]["NumberOfMountTargets"] > 0:
            return self.fs[0]["NumberOfMountTargets"]
        return False

    def it_has_resource_policy(self):
        if self.fs_policy:
            return self.fs_policy
        return False

    def checks(self):
        checks = [
            "is_encrypted",
            "it_has_mount_targets",
            "it_has_resource_policy",
        ]
        return checks