"""ResourceType: AwsIamGroup"""

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import ContextBase


class Metacheck(ContextBase):
    def __init__(
        self,
        logger,
        finding,
        mh_filters_config,
        sess,
        drilled=False,
    ):
        self.logger = logger
        self.sess = sess
        self.mh_filters_config = mh_filters_config
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(self.logger, "iam", self.region, self.sess)
        # Describe
        self.group = self.describe_group()
        if not self.group:
            return False
        self.iam_inline_policies = self.list_group_policies()
        # Associated MetaChecks
        self.iam_policies = self.list_attached_group_policies()

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

    def describe_group(self):
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
                iam_inline_policies[policy_name] = policy_document

        return iam_inline_policies

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

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        return None

    def associations(self):
        associations = {
            "iam_policies": self.iam_policies,
        }
        return associations

    def checks(self):
        checks = {
            "iam_inline_policies": self.iam_inline_policies,
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
