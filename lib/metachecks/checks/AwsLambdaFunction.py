"""MetaCheck: AwsLambdaFunction"""

import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import ResourcePolicyChecker


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
            if self.function_policy:
                self.checked_function_policy = ResourcePolicyChecker(self.logger, finding, self.function_policy).check_policy()

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
        if self.function:
            try:
                response = self.client.get_policy(
                    FunctionName=self.resource_arn
        #            Qualifier='string'
                )
            except ClientError as err:
                if err.response["Error"]["Code"] == "ResourceNotFoundException":
                    return False
                else:
                    self.logger.error("Failed to get_policy {}, {}".format(self.resource_id, err))
                    return False
            if response["Policy"]:
                return json.loads(response["Policy"])
        return False

    # MetaChecks

    def it_has_policy(self):
        return self.function_policy

    def it_has_policy_public(self):
        if self.function_policy:
            return self.checked_function_policy["is_public"]
        return False

    def it_has_policy_principal_wildcard(self):
        if self.function_policy:
            return self.checked_function_policy["is_principal_wildcard"]
        return False

    def it_has_policy_principal_cross_account(self):
        if self.function_policy:
            return self.checked_function_policy["is_principal_cross_account"]
        return False

    def it_has_policy_actions_wildcard(self):
        if self.function_policy:
            return self.checked_function_policy["is_actions_wildcard"]
        return False

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
            "it_has_policy",
            "it_has_policy_principal_cross_account",
            "it_has_policy_principal_wildcard",
            "it_has_policy_public",
            "it_has_policy_actions_wildcard",
            "its_associated_with_a_role"
        ]
        return checks