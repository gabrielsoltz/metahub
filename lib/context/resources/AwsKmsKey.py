"""MetaCheck: AwsKmsKey"""

import json

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import MetaChecksBase
from lib.context.resources.MetaChecksHelpers import PolicyHelper


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
        self.client = get_boto3_client(self.logger, "kms", self.region, self.sess)
        # Describe
        self.kms_key = self.describe_key()
        if not self.kms_key:
            return False
        self.resource_policy = self.get_key_policy()

        # Drilled Metachecks

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

    # Describe Functions

    def describe_key(self):
        try:
            response = self.client.describe_key(KeyId=self.resource_id)
            return response.get("KeyMetadata")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to describe_key {}, {}".format(self.resource_id, err)
                )
        return False

    def get_key_policy(self):
        try:
            response = self.client.get_key_policy(
                KeyId=self.resource_id, PolicyName="default"
            )
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_key_policy {}, {}".format(self.resource_id, err)
                )
            return False
        if response.get("Policy"):
            checked_policy = PolicyHelper(
                self.logger, self.finding, json.loads(response["Policy"])
            ).check_policy()
            return checked_policy
        return False

    # MetaChecks

    def origin(self):
        origin = False
        if self.kms_key:
            origin = self.kms_key.get("Origin")
        return origin

    def encryption_algorithms(self):
        encryption_algorithms = False
        if self.kms_key:
            encryption_algorithms = self.kms_key.get("EncryptionAlgorithms")
        return encryption_algorithms

    def signing_algorithms(self):
        signing_algorithms = False
        if self.kms_key:
            signing_algorithms = self.kms_key.get("SigningAlgorithms")
        return signing_algorithms

    def is_unrestricted(self):
        if self.resource_policy:
            if self.resource_policy["is_unrestricted"]:
                return self.resource_policy["is_unrestricted"]
        return False

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.resource_policy,
            "origin": self.origin(),
            "encryption_algorithms": self.encryption_algorithms(),
            "signing_algorithms": self.signing_algorithms(),
            "is_unrestricted": self.is_unrestricted(),
        }
        return checks
