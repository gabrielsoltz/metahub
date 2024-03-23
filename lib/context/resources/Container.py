"""ResourceType: Container"""

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
        self.client = get_boto3_client(
            self.logger, "ecr-public", self.region, self.sess
        )
        self.container = self.describe_container()
        self.resource_policy = self.get_repository_policy()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        if finding["Resources"][0]["Id"].startswith("arn:aws"):
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
        elif finding["Resources"][0]["Id"].startswith("public.ecr.aws"):
            self.resource_id = finding["Resources"][0]["Id"].split("/")[2].split(":")[0]

    # Describe Functions
    def describe_container(self):
        try:
            response = self.client.describe_repositories(
                repositoryNames=[self.resource_id]
            )
            return response
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to describe_container {}, {}".format(self.resource_id, err)
                )
        return False

    # Resource Policy

    def get_repository_policy(self):
        if self.container:
            try:
                response = self.client.get_repository_policy(
                    repositoryName=self.resource_id
                )
                return response
            except ClientError as err:
                if (
                    not err.response["Error"]["Code"]
                    == "RepositoryPolicyNotFoundException"
                ):
                    self.logger.error(
                        "Failed to get_repository_policy {}, {}".format(
                            self.resource_id, err
                        )
                    )
        return False

    # Context Config

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.resource_policy,
        }
        return checks
