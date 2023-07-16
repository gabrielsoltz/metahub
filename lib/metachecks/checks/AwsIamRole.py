"""MetaCheck: AwsIamRole"""

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
            self.role = self.get_role()
            self.instance_profile = self.list_instance_profiles_for_role()
            self.iam_inline_policies = self.list_role_policies()
            # Drilled MetaChecks
            self.iam_policies = self.list_attached_role_policies()

    # Describe functions

    def get_role(self):
        try:
            role = self.client.get_role(RoleName=self.resource_id).get("Role")
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            else:
                self.logger.error(
                    "Failed to get_role {}, {}".format(self.resource_id, err)
                )
                return False
        return role

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

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

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

    def its_associated_with_instance_profile(self):
        if self.instance_profile:
            return self.instance_profile
        return False

    def it_has_assume_role_policy(self):
        if self.role:
            if self.role.get("AssumeRolePolicyDocument"):
                return self.role.get("AssumeRolePolicyDocument")
        return False

    def it_has_permissions_boundary(self):
        if self.role:
            if self.role.get("PermissionsBoundary"):
                return self.role.get("PermissionsBoundary")
        return False

    def checks(self):
        checks = [
            "its_associated_with_iam_policies",
            "it_has_iam_inline_policies",
            "is_unrestricted",
            "its_associated_with_instance_profile",
            "it_has_assume_role_policy",
            "it_has_permissions_boundary",
        ]
        return checks
