"""ResourceType: AwsEc2Volume"""

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
        self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
        # Describe Resource
        self.volume = self.describe_volumes()
        if not self.volume:
            return False
        # Associations
        self.instances = self._describe_volumes_instances()

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

    def describe_volumes(self):
        try:
            response = self.client.describe_volumes(VolumeIds=[self.resource_id])
            return response["Volumes"]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "InvalidVolume.NotFound":
                self.logger.error(
                    "Failed to describe_volumes {}, {}".format(self.resource_id, err)
                )
            return False

    def _describe_volumes_instances(self):
        instances = {}
        if self.volume:
            for ebs in self.volume:
                if ebs.get("Attachments"):
                    for attachment in ebs.get("Attachments"):
                        arn = generate_arn(
                            attachment.get("InstanceId"),
                            "ec2",
                            "instance",
                            self.region,
                            self.account,
                            self.partition,
                        )
                        instances[arn] = {}
        return instances

    # Context Config

    def encrypted(self):
        if self.volume:
            for ebs in self.volume:
                if ebs["Encrypted"]:
                    return True
        return False

    def attached(self):
        if self.volume:
            for ebs in self.volume:
                if ebs["Attachments"]:
                    return True
        return False

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        return None

    def associations(self):
        associations = {
            "instances": self.instances,
        }
        return associations

    def checks(self):
        checks = {
            "encrypted": self.encrypted(),
            "attached": self.attached(),
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
