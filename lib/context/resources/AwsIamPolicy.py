"""ResourceType: AwsIamPolicy"""

from aws_arn import generate_arn
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
        self.policy = self.describe_policy()
        if not self.policy:
            return False
        self.resource_policy = self.get_policy_version()
        # Associated MetaChecks
        self.policy_entities = self.list_entities_for_policy()
        self.iam_roles = self._list_entities_for_policy_roles()
        self.iam_groups = self._list_entities_for_policy_groups()
        self.iam_users = self._list_entities_for_policy_users()

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

    # Describe Functions

    def describe_policy(self):
        try:
            response = self.client.get_policy(PolicyArn=self.resource_arn)
            return response.get("Policy")
        except ClientError as err:
            if (
                not err.response["Error"]["Code"] == "NoSuchEntityException"
                and not err.response["Error"]["Code"] == "NoSuchEntity"
            ):
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

    def _list_entities_for_policy_roles(self):
        roles = {}
        if self.policy_entities.get("PolicyRoles"):
            for role in self.policy_entities["PolicyRoles"]:
                arn = generate_arn(
                    role.get("RoleName"),
                    "iam",
                    "role",
                    self.region,
                    self.account,
                    self.partition,
                )
                roles[arn] = {}
        return roles

    def _list_entities_for_policy_groups(self):
        groups = {}
        if self.policy_entities.get("PolicyGroups"):
            for group in self.policy_entities["PolicyGroups"]:
                arn = generate_arn(
                    group.get("GroupName"),
                    "iam",
                    "group",
                    self.region,
                    self.account,
                    self.partition,
                )
                groups[arn] = {}
        return groups

    def _list_entities_for_policy_users(self):
        users = {}
        if self.policy_entities.get("PolicyUsers"):
            for user in self.policy_entities["PolicyUsers"]:
                arn = generate_arn(
                    user.get("UserName"),
                    "iam",
                    "user",
                    self.region,
                    self.account,
                    self.partition,
                )
                users[arn] = {}
        return users

    # Context Config

    def name(self):
        if self.policy:
            try:
                return self.policy["PolicyName"]
            except KeyError:
                return False
        return False

    def description(self):
        if self.policy:
            try:
                return self.policy["Description"]
            except KeyError:
                return False
        return False

    def attached(self):
        if self.policy:
            if self.policy["AttachmentCount"] > 0:
                return True
        return False

    def customer_managed(self):
        if not self.resource_arn.startswith("arn:aws:iam::aws:policy/"):
            return True
        return False

    def trust_policy(self):
        return None

    def public(self):
        return None

    def associations(self):
        associations = {
            "iam_roles": self.iam_roles,
            "iam_groups": self.iam_groups,
            "iam_users": self.iam_users,
        }
        return associations

    def checks(self):
        checks = {
            "name": self.name(),
            "description": self.description(),
            "customer_managed": self.customer_managed(),
            "attached": self.attached(),
            "public": self.public(),
            "resource_policy": self.resource_policy,
        }
        return checks
