"""ResourceType: AwsAthenaWorkGroup"""

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
        self.client = get_boto3_client(self.logger, "athena", self.region, self.sess)
        # Describe Resource
        self.work_group = self.describe_work_group()
        self.work_group_configuration = self._describe_work_group_configuration()
        if not self.work_group:
            return False
        # Drilled Associations

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[-1]
            if not drilled
            else drilled.split("/")[-1]
        )

    # Describe functions

    def describe_work_group(self):
        try:
            response = self.client.get_work_group(WorkGroup=self.resource_id).get(
                "WorkGroup"
            )
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to describe_work_group: {}, {}".format(
                        self.resource_id, err
                    )
                )
            return False
        return response

    def _describe_work_group_configuration(self):
        if self.work_group:
            if self.work_group.get("Configuration"):
                return self.work_group["Configuration"]
        return False

    # Context

    def name(self):
        if self.work_group:
            if self.work_group.get("Name"):
                return self.work_group["Name"]
        return False

    def status(self):
        if self.work_group:
            if self.work_group.get("State"):
                return self.work_group["State"]
        return False

    def engine(self):
        if self.work_group_configuration:
            if self.work_group_configuration.get("EngineVersion"):
                return self.work_group_configuration["EngineVersion"]
        return False

    def encrypted(self):
        if self.work_group_configuration:
            if self.work_group_configuration.get("EncryptionConfiguration"):
                return self.work_group_configuration["EncryptionConfiguration"]
        return False

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "name": self.name(),
            "status": self.status(),
            "engine": self.engine(),
            "encrypted": self.encrypted(),
        }
        return checks
