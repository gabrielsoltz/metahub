"""MetaCheck: AwsKmsKey"""

import json

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase
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
            self.client = get_boto3_client(self.logger, "kms", self.region, self.sess)
            # Describe
            self.policy = self.get_key_policy()
            if not self.policy:
                return False
            # Drilled Metachecks

    # Describe Functions

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

    def it_has_resource_policy(self):
        return self.policy

    def is_unrestricted(self):
        if self.policy:
            if self.policy["is_unrestricted"]:
                return self.policy["is_unrestricted"]
        return False

    def checks(self):
        checks = [
            "it_has_resource_policy",
            "is_unrestricted",
        ]
        return checks
