"""MetaCheck: AwsIamRole"""


from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
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
        self.role = self.describe_role()
        if not self.role:
            return False
        self.instance_profile = self.list_instance_profiles_for_role()
        self.iam_inline_policies = self.list_role_policies()
        # Drilled MetaChecks
        self.iam_policies = self.list_attached_role_policies()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[1]
            if not drilled
            else drilled.split("/")[1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

    # Describe functions

    def describe_role(self):
        try:
            role = self.client.get_role(RoleName=self.resource_id).get("Role")
            return role
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchEntity":
                self.logger.error(
                    "Failed to get_role {}, {}".format(self.resource_id, err)
                )
        return False

    def list_instance_profiles_for_role(self):
        try:
            instance_profile = self.client.list_instance_profiles_for_role(
                RoleName=self.resource_id
            ).get("InstanceProfiles")
            if instance_profile:
                instance_profile = instance_profile[0].get("Arn")
            else:
                instance_profile = False
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to list_instance_profiles_for_role {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
        return instance_profile

    def list_role_policies(self):
        iam_inline_policies = {}

        try:
            list_role_policies = self.client.list_role_policies(
                RoleName=self.resource_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to list_role_policies {}, {}".format(self.resource_id, err)
                )
                return False
        if list_role_policies["PolicyNames"]:
            for policy_name in list_role_policies["PolicyNames"]:
                policy_document = self.client.get_role_policy(
                    PolicyName=policy_name, RoleName=self.resource_id
                ).get("PolicyDocument")
                checked_policy = PolicyHelper(
                    self.logger, self.finding, policy_document
                ).check_policy()
                # policy = {"policy_checks": checked_policy, "policy": access_policies}
                iam_inline_policies[policy_name] = checked_policy

        return iam_inline_policies

    def list_attached_role_policies(self):
        iam_policies = {}

        try:
            list_attached_role_policies = self.client.list_attached_role_policies(
                RoleName=self.resource_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to list_attached_role_policies {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
        if list_attached_role_policies["AttachedPolicies"]:
            for attached_policy in list_attached_role_policies["AttachedPolicies"]:
                iam_policies[attached_policy["PolicyArn"]] = {}

        return iam_policies

    # MetaChecks

    def assume_policy(self):
        if self.role:
            if self.role.get("AssumeRolePolicyDocument"):
                checked_policy = PolicyHelper(
                    self.logger, self.finding, self.role.get("AssumeRolePolicyDocument")
                ).check_policy()
                return checked_policy
        return False

    def permissions_boundary(self):
        if self.role:
            if self.role.get("PermissionsBoundary"):
                return self.role.get("PermissionsBoundary")
        return False

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
            "instance_profile": self.instance_profile,
            "assume_policy": self.assume_policy(),
            "permissions_boundary": self.permissions_boundary(),
            "is_unrestricted": self.is_unrestricted(),
            "public": self.public(),
        }
        return checks
