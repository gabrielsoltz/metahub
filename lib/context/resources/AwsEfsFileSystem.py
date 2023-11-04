"""ResourceType: AwsEfsFileSystem"""

import json

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
        self.client = get_boto3_client(self.logger, "efs", self.region, self.sess)
        # Describe
        self.fs = self.describe_file_systems()
        if not self.fs:
            return False
        self.resource_policy = self.describe_file_system_policy()
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

    def describe_file_systems(self):
        try:
            response = self.client.describe_file_systems(
                FileSystemId=self.resource_id
            ).get("FileSystems")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "FileSystemNotFound":
                self.logger.error(
                    "Failed to describe_file_systems: {}, {}".format(
                        self.resource_id, err
                    )
                )
            return False
        return response

    def describe_file_system_policy(self):
        if self.fs:
            try:
                response = self.client.describe_file_system_policy(
                    FileSystemId=self.resource_id
                )
            except ClientError as err:
                if not err.response["Error"]["Code"] == "PolicyNotFound":
                    self.logger.error(
                        "Failed to describe_file_system_policy {}, {}".format(
                            self.resource_id, err
                        )
                    )
                return False

            if response["Policy"]:
                policy_json = json.loads(response["Policy"])
                return policy_json

        return False

    # Context Config

    def mount_targets(self):
        if self.fs[0]["NumberOfMountTargets"] > 0:
            return self.fs[0]["NumberOfMountTargets"]
        return False

    def is_encrypted(self):
        if self.fs[0]["Encrypted"]:
            return True
        return False

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
            "mount_targets": self.mount_targets(),
            "resource_policy": self.resource_policy,
            "public": self.public(),
        }
        return checks
