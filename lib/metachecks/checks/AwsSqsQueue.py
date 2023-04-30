"""MetaCheck: AwsSqsQueue"""

import boto3
import json

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import ResourcePolicyChecker


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = "aws"
            if not sess:
                self.client = boto3.client("sqs", region_name=self.region)
            else:
                self.client = sess.client(service_name="sqs", region_name=self.region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.account_id = finding["AwsAccountId"]
            self.mh_filters_checks = mh_filters_checks
            self.queue_url = self._get_queue_url()
            self.queue_attributes = self._get_queue_atributes()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy(finding, sess)
            
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

    # Resource Policy

    def describe_resource_policy(self, finding, sess):
        if self.queue_attributes:
            try:
                if self.queue_attributes["Policy"]:
                    details = ResourcePolicyChecker(self.logger, finding, json.loads(self.queue_attributes["Policy"])).check_policy()
                    policy = {"policy_checks": details, "policy": json.loads(self.queue_attributes["Policy"])}
                    return policy
            except KeyError:
                return False
        return False

    # MetaChecks

    def is_encrypted(self):
        if self.queue_attributes:
            return self.queue_attributes["SqsManagedSseEnabled"]
    
    def it_has_resource_policy(self):
        return self.resource_policy

    def is_public(self):
        if self.resource_policy:
            if self.resource_policy["policy_checks"]["is_public"]:
                return True
        return False

    def checks(self):
        checks = [
            "is_encrypted",
            "it_has_resource_policy",
            "is_public"
        ]
        return checks