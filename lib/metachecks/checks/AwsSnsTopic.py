"""MetaCheck: AwsSnsTopic"""

import json

import boto3

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import ResourcePolicyChecker


class Metacheck(MetaChecksBase):
    def __init__(
        self, logger, finding, metachecks, mh_filters_checks, sess, drilled=False
    ):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            self.mh_filters_checks = mh_filters_checks
            if not sess:
                self.client = boto3.client("sns", region_name=self.region)
            else:
                self.client = sess.client(service_name="sns", region_name=self.region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.account_id = finding["AwsAccountId"]
            self.mh_filters_checks = mh_filters_checks
            self.topic_atributes = self._get_topic_attributes()
            self.topic_kms_master_key_id = self._get_topic_atributes_kms_master_key_id()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy(finding, sess)

    # Describe Functions

    def _get_topic_attributes(self):
        response = self.client.get_topic_attributes(TopicArn=self.resource_arn)
        if response["Attributes"]:
            return response["Attributes"]
        return False

    # Resource Policy

    def describe_resource_policy(self, finding, sess):
        if self.topic_atributes:
            try:
                if self.topic_atributes["Policy"]:
                    details = ResourcePolicyChecker(
                        self.logger, finding, json.loads(self.topic_atributes["Policy"])
                    ).check_policy()
                    policy = {
                        "policy_checks": details,
                        "policy": json.loads(self.topic_atributes["Policy"]),
                    }
                    return policy
            except KeyError:
                return False
        return False

    def _get_topic_atributes_kms_master_key_id(self):
        if self.topic_atributes:
            try:
                return self.topic_atributes["KmsMasterKeyId"]
            except KeyError:
                return False
        return False

    # MetaChecks

    def it_has_resource_policy(self):
        return self.resource_policy

    def is_public(self):
        if self.resource_policy:
            if self.resource_policy["policy_checks"]["is_public"]:
                return True
        return False

    def is_encrypted(self):
        if self.topic_kms_master_key_id:
            return self.topic_kms_master_key_id
        return False

    def checks(self):
        checks = ["it_has_resource_policy", "is_public", "is_encrypted"]
        return checks
