"""MetaCheck: AwsSnsTopic"""

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
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "sns", self.region, self.sess)
            # Describe
            self.topic_atributes = self.get_topic_attributes()
            if not self.topic_atributes:
                return False
            self.topic_kms_master_key_id = self.get_topic_atributes_kms_master_key_id()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy()
            # Drilled Metachecks

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

    def it_has_resource_policy(self):
        return self.resource_policy

    def is_unrestricted(self):
        if self.resource_policy:
            if self.resource_policy["is_unrestricted"]:
                return True
        return False

    def is_encrypted(self):
        if self.topic_kms_master_key_id:
            return self.topic_kms_master_key_id
        return False

    def it_has_subscriptions_confirmed(self):
        if self.topic_atributes:
            try:
                if self.topic_atributes["SubscriptionsConfirmed"]:
                    if int(self.topic_atributes["SubscriptionsConfirmed"]) == 0:
                        return False
                    return self.topic_atributes["SubscriptionsConfirmed"]
            except KeyError:
                return False
        return False

    def it_has_name(self):
        if self.topic_atributes:
            try:
                if self.topic_atributes["DisplayName"]:
                    return self.topic_atributes["DisplayName"]
            except KeyError:
                return False
        return False

    def checks(self):
        checks = [
            "it_has_resource_policy",
            "is_unrestricted",
            "is_encrypted",
            "it_has_subscriptions_confirmed",
            "it_has_name",
        ]
        return checks
