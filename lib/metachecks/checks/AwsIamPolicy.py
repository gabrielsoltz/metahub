"""MetaCheck: AwsIamPolicy"""

import boto3

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import ResourcePolicyChecker


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client("iam", region_name=region)
            else:
                self.client = sess.client(service_name="iam", region_name=region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split("/")[-1]
            self.account_id = finding["AwsAccountId"]
            self.mh_filters_checks = mh_filters_checks
            self.policy = self._get_policy()
            self.policy_version = self._get_policy_version()
            if self.policy_version:
                self.checked_policy_version = ResourcePolicyChecker(self.logger, finding, self.policy_version).check_policy()
            self.policy_entities = self._list_entities_for_policy()
            
    # Describe Functions

    def _get_policy(self):
        response = self.client.get_policy(
            PolicyArn=self.resource_arn
        )
        if response["Policy"]:
            return response["Policy"]
        return False

    def _get_policy_version(self):
        response = self.client.get_policy_version(
            PolicyArn=self.resource_arn,
            VersionId=self.policy["DefaultVersionId"]
        )
        return response["PolicyVersion"]["Document"]

    def _list_entities_for_policy(self):
        response = self.client.list_entities_for_policy(
            PolicyArn=self.resource_arn
        )
        return response

    # MetaChecks

    def it_has_name(self):
        if self.policy:
            try:
                return self.policy["PolicyName"]
            except KeyError:
                return False
        return False

    def it_has_description(self):
        if self.policy:
            try:
                return self.policy["Description"]
            except KeyError:
                return False
        return False

    def is_attached(self):
        if self.policy:
            if self.policy["AttachmentCount"] == 0:
                return False
            return self.policy["AttachmentCount"]
        return False

    def is_customer_managed(self):
        if not self.resource_arn.startswith('arn:aws:iam::aws:policy/'):
            return True
        return False

    def its_associated_with_iam_groups(self):
        if self.policy_entities["PolicyGroups"]:
            return self.policy_entities["PolicyGroups"]
        return False

    def its_associated_with_iam_users(self):
        if self.policy_entities["PolicyUsers"]:
            return self.policy_entities["PolicyUsers"]
        return False

    def its_associated_with_iam_roles(self):
        if self.policy_entities["PolicyRoles"]:
            return self.policy_entities["PolicyRoles"]
        return False

    def it_has_policy(self):
        return self.policy_version

    def it_has_policy_principal_cross_account(self):
        if self.policy_version:
            return self.checked_policy_version["is_principal_cross_account"]
        return False

    def it_has_policy_principal_wildcard(self):
        if self.policy_version:
            return self.checked_policy_version["is_principal_wildcard"]
        return False

    def it_has_policy_public(self):
        if self.policy_version:
            return self.checked_policy_version["is_public"]
        return False

    def it_has_policy_actions_wildcard(self):
        if self.policy_version:
            return self.checked_policy_version["is_actions_wildcard"]
        return False

    def checks(self):
        checks = [
            "it_has_name",
            "it_has_description",
            "is_attached",
            "is_customer_managed",
            "its_associated_with_iam_groups",
            "its_associated_with_iam_users",
            "its_associated_with_iam_roles",
            "it_has_policy",
            "it_has_policy_principal_cross_account",
            "it_has_policy_principal_wildcard",
            "it_has_policy_public",
            "it_has_policy_actions_wildcard"
        ]
        return checks