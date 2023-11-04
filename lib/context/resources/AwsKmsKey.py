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
        self.policy = self.get_key_policy()
        if not self.policy:
            return False
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

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.it_has_resource_policy(),
            "is_unrestricted": self.is_unrestricted(),
        }
        return checks
