"""MetaCheck: AwsIamGroup"""


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
                finding["Resources"][0]["Id"].split("/")[-1]
                if not drilled
                else drilled.split("/")[-1]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "iam", self.region, self.sess)
            # Describe
            self.group = self.get_group()
            if not self.group: return False
            self.iam_inline_policies = self.list_group_policies()
            # Drilled MetaChecks
            self.iam_policies = self.list_attached_group_policies()

    # Describe functions

    def get_group(self):
        try:
            group = self.client.get_group(GroupName=self.resource_id).get("Group")
            return group
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchEntity":
                self.logger.error(
                    "Failed to get_group {}, {}".format(self.resource_id, err)
                )
        return False
        

    def list_group_policies(self):
        iam_inline_policies = {}

        try:
            list_group_policies = self.client.list_group_policies(
                GroupName=self.resource_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to list_group_policies {}, {}".format(self.resource_id, err)
                )
                return False
        if list_group_policies["PolicyNames"]:
            for policy_name in list_group_policies["PolicyNames"]:
                policy_document = self.client.get_group_policy(
                    PolicyName=policy_name, GroupName=self.resource_id
                ).get("PolicyDocument")
                checked_policy = PolicyHelper(
                    self.logger, self.finding, policy_document
                ).check_policy()
                iam_inline_policies[policy_name] = checked_policy

        return iam_inline_policies

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def list_attached_group_policies(self):
        iam_policies = {}

        try:
            list_attached_group_policies = self.client.list_attached_group_policies(
                GroupName=self.resource_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to list_attached_group_policies {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
        if list_attached_group_policies["AttachedPolicies"]:
            for attached_policy in list_attached_group_policies["AttachedPolicies"]:
                iam_policies[attached_policy["PolicyArn"]] = {}

        return iam_policies

    # Checks
    def its_associated_with_iam_policies(self):
        if self.iam_policies:
            return self.iam_policies
        return False

    def it_has_iam_inline_policies(self):
        if self.iam_inline_policies:
            return self.iam_inline_policies
        return False

    def is_unrestricted(self):
        if self.iam_policies:
            for policy in self.iam_policies:
                if self.iam_policies[policy].get("is_unrestricted"):
                    return True
        if self.iam_inline_policies:
            for policy in self.iam_inline_policies:
                if self.iam_inline_policies[policy].get("is_unrestricted"):
                    return True
        return False

    def checks(self):
        checks = [
            "its_associated_with_iam_policies",
            "it_has_iam_inline_policies",
            "is_unrestricted",
        ]
        return checks
