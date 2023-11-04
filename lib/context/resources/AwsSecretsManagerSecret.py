"""MetaCheck: AwsSecretsManagerSecret"""

import json
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.config.configuration import days_to_consider_unrotated
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
        self.client = get_boto3_client(
            self.logger, "secretsmanager", self.region, self.sess
        )
        # Describe
        self.secret = self.describe_secret()
        if not self.secret:
            return False
        self.resource_policy = self.get_resource_policy()
        # Drilled Metachecks

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split(":")[1]
            if not drilled
            else drilled.split(":")[1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

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
            response = self.client.get_resource_policy(SecretId=self.resource_arn)
        if response.get("ResourcePolicy"):
            return json.loads(response["ResourcePolicy"])
        return False

    # MetaChecks

    def name(self):
        if self.secret:
            try:
                return self.secret["Name"]
            except KeyError:
                return False
        return False

    def rotation_enabled(self):
        if self.secret:
            try:
                return self.secret["RotationEnabled"]
            except KeyError:
                return False
        return False

    def is_unrotated(self):
        if self.secret:
            current_date = datetime.now(timezone.utc)
            last_change_date = self.secret.get("LastChangedDate")
            date_difference = current_date - last_change_date
            if date_difference.days > days_to_consider_unrotated:
                return str(date_difference.days)
        return False

    def public(self):
        return None

    def trust_policy(self):
        return None

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.resource_policy,
            "name": self.name(),
            "rotation_enabled": self.rotation_enabled(),
            "is_unrotated": self.is_unrotated(),
            "public": self.public(),
        }
        return checks
