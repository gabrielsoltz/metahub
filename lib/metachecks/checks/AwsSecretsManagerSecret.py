"""MetaCheck: AwsSecretsManagerSecret"""

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import PolicyHelper

import json


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
                finding["Resources"][0]["Id"].split(":")[1]
                if not drilled
                else drilled.split(":")[1]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "secretsmanager", self.region, self.sess)
            # Describe
            self.secret = self.describe_secret()
            if not self.secret:
                return False
            self.policy = self.get_resource_policy()
            # Drilled Metachecks

    # Describe Functions

    def describe_secret(self):
        try:
            response = self.client.describe_secret(SecretId=self.resource_arn)
            return response
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to describe_secret {}, {}".format(self.resource_id, err)
                )
        return False

    def get_resource_policy(self):
        if self.secret:
            response = self.client.get_resource_policy(
                SecretId=self.resource_arn
            )
        if response.get("ResourcePolicy"):
            checked_policy = PolicyHelper(
                self.logger, self.finding, json.loads(response["ResourcePolicy"])
            ).check_policy()
            return checked_policy
        return False

    # MetaChecks

    def it_has_name(self):
        if self.secret:
            try:
                return self.secret["Name"]
            except KeyError:
                return False
        return False

    def it_has_rotation_enabled(self):
        if self.secret:
            try:
                return self.secret["RotationEnabled"]
            except KeyError:
                return False
        return False

    def it_has_resource_policy(self):
        return self.policy

    def is_unrestricted(self):
        if self.policy:
            if self.policy["is_unrestricted"]:
                return True
        return False

    def checks(self):
        checks = [
            "it_has_name",
            "it_has_resource_policy",
            "it_has_rotation_enabled",
            "is_unrestricted",
        ]
        return checks
