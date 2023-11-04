"""MetaCheck: AwsSnsTopic"""

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
        self.client = get_boto3_client(self.logger, "sns", self.region, self.sess)
        # Describe
        self.topic_atributes = self.get_topic_attributes()
        if not self.topic_atributes:
            return False
        self.topic_kms_master_key_id = self.get_topic_atributes_kms_master_key_id()
        # Resource Policy
        self.resource_policy = self.describe_resource_policy()
        # Drilled Metachecks

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]

    # Describe Functions

    def get_topic_attributes(self):
        try:
            response = self.client.get_topic_attributes(TopicArn=self.resource_arn)
            return response.get("Attributes")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_topic_attributes {}, {}".format(
                        self.resource_id, err
                    )
                )
        return False

    def get_topic_atributes_kms_master_key_id(self):
        if self.topic_atributes:
            try:
                return self.topic_atributes["KmsMasterKeyId"]
            except KeyError:
                return False
        return False

    # Resource Policy

    def describe_resource_policy(self):
        if self.topic_atributes:
            try:
                if self.topic_atributes["Policy"]:
                    checked_policy = PolicyHelper(
                        self.logger,
                        self.finding,
                        json.loads(self.topic_atributes["Policy"]),
                    ).check_policy()
                    return checked_policy
            except KeyError:
                return False
        return False

    # MetaChecks

    def subscriptions_confirmed(self):
        if self.topic_atributes:
            try:
                if self.topic_atributes["SubscriptionsConfirmed"]:
                    if int(self.topic_atributes["SubscriptionsConfirmed"]) == 0:
                        return False
                    return self.topic_atributes["SubscriptionsConfirmed"]
            except KeyError:
                return False
        return False

    def name(self):
        if self.topic_atributes:
            try:
                if self.topic_atributes["DisplayName"]:
                    return self.topic_atributes["DisplayName"]
            except KeyError:
                return False
        return False

    def is_unrestricted(self):
        if self.resource_policy:
            if self.resource_policy["is_unrestricted"]:
                return self.resource_policy["is_unrestricted"]
        return False

    def is_encrypted(self):
        if self.topic_kms_master_key_id:
            return self.topic_kms_master_key_id
        return False

    def public(self):
        return None

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.resource_policy,
            "subscriptions_confirmed": self.subscriptions_confirmed(),
            "name": self.name(),
            "is_encrypted": self.is_encrypted(),
            "is_unrestricted": self.is_unrestricted(),
            "public": self.public(),
        }
        return checks
