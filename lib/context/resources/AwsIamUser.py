"""MetaCheck: AwsIamUser"""


from datetime import datetime, timezone

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.config.configuration import days_to_consider_unrotated
from lib.context.resources.Base import MetaChecksBase
from lib.context.resources.MetaChecksHelpers import PolicyHelper


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        mh_filters_checks,
        sess,
        drilled=False,
    ):
        self.logger = logger
        self.sess = sess
        self.mh_filters_checks = mh_filters_checks
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(self.logger, "iam", self.region, self.sess)
        # Describe
        self.user = self.describe_user()
        if not self.user:
            return False
        self.user_access_keys = self.list_access_keys()
        self.iam_inline_policies = self.list_user_policies()
        # Drilled MetaChecks
        self.iam_policies = self.list_attached_user_policies()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[-1]
            if not drilled
            else drilled.split("/")[-1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

    # Describe functions

    def describe_user(self):
        try:
            user = self.client.get_user(UserName=self.resource_id).get("User")
            return user
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchEntity":
                self.logger.error(
                    "Failed to get_user {}, {}".format(self.resource_id, err)
                )
        return False

    def list_user_policies(self):
        iam_inline_policies = {}

        try:
            list_user_policies = self.client.list_user_policies(
                UserName=self.resource_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to list_user_policies {}, {}".format(self.resource_id, err)
                )
                return False
        if list_user_policies["PolicyNames"]:
            for policy_name in list_user_policies["PolicyNames"]:
                policy_document = self.client.get_user_policy(
                    PolicyName=policy_name, UserName=self.resource_id
                ).get("PolicyDocument")
                checked_policy = PolicyHelper(
                    self.logger, self.finding, policy_document
                ).check_policy()
                iam_inline_policies[policy_name] = checked_policy

        return iam_inline_policies

    def list_access_keys(self):
        iam_user_access_keys = {}

        try:
            list_access_keys = self.client.list_access_keys(UserName=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to list_access_keys {}, {}".format(self.resource_id, err)
                )
                return False
        if list_access_keys["AccessKeyMetadata"]:
            iam_user_access_keys = list_access_keys["AccessKeyMetadata"]

        return iam_user_access_keys

    def list_attached_user_policies(self):
        iam_policies = {}

        try:
            list_attached_user_policies = self.client.list_attached_user_policies(
                UserName=self.resource_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to list_attached_user_policies {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
        if list_attached_user_policies["AttachedPolicies"]:
            for attached_policy in list_attached_user_policies["AttachedPolicies"]:
                iam_policies[attached_policy["PolicyArn"]] = {}

        return iam_policies

    def is_unrestricted(self):
        if self.iam_policies:
            for policy in self.iam_policies:
                if self.iam_policies[policy].get("is_actions_and_resource_wildcard"):
                    return self.iam_policies[policy].get(
                        "is_actions_and_resource_wildcard"
                    )
        if self.iam_inline_policies:
            for policy in self.iam_inline_policies:
                if self.iam_inline_policies[policy].get(
                    "is_actions_and_resource_wildcard"
                ):
                    return self.iam_inline_policies[policy].get(
                        "is_actions_and_resource_wildcard"
                    )
        return False

    def is_unrotated(self):
        if self.user_access_keys:
            current_date = datetime.now(timezone.utc)
            for key in self.user_access_keys:
                if key.get("Status") == "Active":
                    create_date = key.get("CreateDate")
                    date_difference = current_date - create_date
                    if date_difference.days > days_to_consider_unrotated:
                        return str(date_difference.days)
        return False

    def associations(self):
        associations = {
            "iam_policies": self.iam_policies,
        }
        return associations

    def checks(self):
        checks = {
            "iam_inline_policies": self.iam_inline_policies,
            "is_unrestricted": self.is_unrestricted(),
            "is_unrotated": self.is_unrotated(),
        }
        return checks
