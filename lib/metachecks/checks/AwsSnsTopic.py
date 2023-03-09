"""MetaCheck: AwsSnsTopic"""

import boto3
import json

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import ResourcePolicyChecker


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client("sns", region_name=region)
            else:
                self.client = sess.client(service_name="sns", region_name=region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.account_id = finding["AwsAccountId"]
            self.mh_filters_checks = mh_filters_checks
            self.topic_atributes = self._get_topic_attributes()
            self.topic_policy = self._get_topic_atributes_policy()
            if self.topic_policy:
                self.checked_topic_policy = ResourcePolicyChecker(self.logger, finding, self.topic_policy).check_policy()
            self.topic_kms_master_key_id = self._get_topic_atributes_kms_master_key_id()
            
    # Describe Functions

    def _get_topic_attributes(self):
        response = self.client.get_topic_attributes(
            TopicArn=self.resource_arn
        )
        if response["Attributes"]:
            return response["Attributes"]
        return False

    def _get_topic_atributes_policy(self):
        if self.topic_atributes:
            try:
                return json.loads(self.topic_atributes["Policy"])
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

    def it_has_policy(self):
        return self.topic_policy

    def it_has_policy_principal_cross_account(self):
        if self.topic_policy:
            return self.checked_topic_policy["is_principal_cross_account"]
        return False

    def it_has_policy_principal_wildcard(self):
        if self.topic_policy:
            return self.checked_topic_policy["is_principal_wildcard"]
        return False

    def it_has_policy_public(self):
        if self.topic_policy:
            return self.checked_topic_policy["is_public"]
        return False

    def it_has_policy_actions_wildcard(self):
        if self.topic_policy:
            return self.checked_topic_policy["is_actions_wildcard"]
        return False

    def is_public(self):
        if self.topic_policy:
            if self.it_has_policy_public():
                return True
        return False

    def is_encrypted(self):
        if self.topic_kms_master_key_id:
            return self.topic_kms_master_key_id
        return False

    def checks(self):
        checks = [
            "it_has_policy",
            "it_has_policy_principal_cross_account",
            "it_has_policy_principal_wildcard",
            "it_has_policy_public",
            "it_has_policy_actions_wildcard",
            "is_public",
            "is_encrypted"
        ]
        return checks
