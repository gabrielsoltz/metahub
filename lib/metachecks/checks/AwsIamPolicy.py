"""MetaCheck: AwsIamPolicy"""

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
            self.resource_id = (
                finding["Resources"][0]["Id"].split("/")[1]
                if not drilled
                else drilled.split("/")[1]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "iam", self.region, self.sess)
            # Describe
            self.policy = self.get_policy()
            if not self.policy:
                return False
            self.policy_version = self.get_policy_version()
            if self.policy_version:
                self.checked_policy_version = PolicyHelper(
                    self.logger, finding, self.policy_version
                ).check_policy()
            self.policy_entities = self.list_entities_for_policy()
            # Drilled Metachecks

    # Describe Functions

    def get_policy(self):
        try:
            response = self.client.get_policy(PolicyArn=self.resource_arn)
            return response.get("Policy")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchEntityException":
                self.logger.error(
                    "Failed to get_policy {}, {}".format(self.resource_id, err)
                )
        return False

    def get_policy_version(self):
        response = self.client.get_policy_version(
            PolicyArn=self.resource_arn, VersionId=self.policy["DefaultVersionId"]
        )
        return response["PolicyVersion"]["Document"]

    def list_entities_for_policy(self):
        response = self.client.list_entities_for_policy(PolicyArn=self.resource_arn)
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
        if not self.resource_arn.startswith("arn:aws:iam::aws:policy/"):
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

    def is_principal_cross_account(self):
        if self.policy_version:
            return self.checked_policy_version["is_principal_cross_account"]
        return False

    def is_principal_wildcard(self):
        if self.policy_version:
            return self.checked_policy_version["is_principal_wildcard"]
        return False

    def is_unrestricted(self):
        if self.policy_version:
            return self.checked_policy_version["is_unrestricted"]
        return False

    def is_actions_wildcard(self):
        if self.policy_version:
            return self.checked_policy_version["is_actions_wildcard"]
        return False

    def is_actions_and_resource_wildcard(self):
        if self.policy_version:
            return self.checked_policy_version["is_actions_and_resource_wildcard"]
        return False

    def checks(self):
        checks = [
            "it_has_name",
            "it_has_description",
            "is_customer_managed",
            "is_principal_cross_account",
            "is_principal_wildcard",
            "is_actions_wildcard",
            "is_actions_and_resource_wildcard",
            "its_associated_with_iam_groups",
            "its_associated_with_iam_users",
            "its_associated_with_iam_roles",
            "is_attached",
            "is_unrestricted",
        ]
        return checks
