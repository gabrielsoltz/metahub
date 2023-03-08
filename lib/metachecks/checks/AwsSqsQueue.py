"""MetaCheck: AwsSqsQueue"""

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
                self.client = boto3.client("sqs", region_name=region)
            else:
                self.client = sess.client(service_name="sqs", region_name=region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.account_id = finding["AwsAccountId"]
            self.mh_filters_checks = mh_filters_checks
            self.queue_url = self._get_queue_url()
            self.queue_attributes = self._get_queue_atributes()
            self.queue_policy = self._get_queue_atributes_policy()
            if self.queue_policy:
                self.checked_queue_policy = ResourcePolicyChecker(self.logger, finding, self.queue_policy).check_policy()
            
    # Describe Functions

    def _get_queue_url(self):
        response = self.client.get_queue_url(
            QueueName=self.resource_id
        )
        return response["QueueUrl"]

    def _get_queue_atributes(self):
        response = self.client.get_queue_attributes(
            QueueUrl=self.queue_url,
            AttributeNames=[
                'All'
            ]
        )
        if response["Attributes"]:
            return response["Attributes"]
        return False

    def _get_queue_atributes_policy(self):
        if self.queue_attributes:
            try:
                return json.loads(self.queue_attributes["Policy"])
            except KeyError:
                return False
        return False

    # MetaChecks

    def is_encrypted(self):
        if self.queue_attributes:
            return self.queue_attributes["SqsManagedSseEnabled"]
    
    def it_has_policy(self):
        return self.queue_policy

    def it_has_policy_principal_cross_account(self):
        if self.queue_policy:
            return self.checked_queue_policy["is_principal_cross_account"]
        return False

    def it_has_policy_principal_wildcard(self):
        if self.queue_policy:
            return self.checked_queue_policy["is_principal_wildcard"]
        return False

    def it_has_policy_public(self):
        if self.queue_policy:
            return self.checked_queue_policy["is_public"]
        return False

    def it_has_policy_actions_wildcard(self):
        if self.queue_policy:
            return self.checked_queue_policy["is_actions_wildcard"]
        return False

    def is_public(self):
        if self.queue_attributes:
            if self.it_has_policy_public():
                return True
        return False

    def checks(self):
        checks = [
            "is_encrypted",
            "it_has_policy",
            "it_has_policy_principal_cross_account",
            "it_has_policy_principal_wildcard",
            "it_has_policy_public",
            "it_has_policy_actions_wildcard",
            "is_public"
        ]
        return checks