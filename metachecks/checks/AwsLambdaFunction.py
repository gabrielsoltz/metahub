"""MetaCheck: AwsLambdaFunction"""

import json

import boto3
from metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client("lambda", region_name=region)
            else:
                self.client = sess.client(service_name="lambda", region_name=region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.function = self._get_function()
            self.function_policy = self._describe_function_policy()

    # Describe Functions

    def _get_function(self):
        response = self.client.get_function(
            FunctionName=self.resource_arn
#            Qualifier='string'
        )
        if response["Configuration"]:
            return response["Configuration"]
        return False

    def _describe_function_policy(self):
        response = self.client.get_policy(
            FunctionName=self.resource_arn
#            Qualifier='string'
        )
        if response["Policy"]:
            return json.loads(response["Policy"])
        return False

    # MetaChecks

    def it_has_resource_based_policy_statements(self):
        policy = False
        if self.function_policy:
            policy = self.function_policy
        return policy

    def its_associated_with_a_role(self):
        role = False
        if self.function:
            try:
                role = self.function["Role"]
            except KeyError:
                role = False
        return role

    def checks(self):
        checks = [
            "it_has_resource_based_policy_statements",
            "its_associated_with_a_role"
        ]
        return checks