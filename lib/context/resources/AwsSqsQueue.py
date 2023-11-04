"""ResourceType: AwsSqsQueue"""

import json

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
        self.client = get_boto3_client(self.logger, "sqs", self.region, self.sess)
        # Describe
        self.queue_url = self.get_queue_url()
        if not self.queue_url:
            return False
        self.queue_attributes = self.get_queue_atributes()
        # Resource Policy
        self.resource_policy = self.describe_resource_policy()
        # Associated MetaChecks

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]

    # Describe Functions

    def get_queue_url(self):
        try:
            response = self.client.get_queue_url(QueueName=self.resource_id)
            return response.get("QueueUrl")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "QueueDoesNotExist":
                self.logger.error(
                    "Failed to get_queue_url {}, {}".format(self.resource_id, err)
                )
        return False

    def get_queue_atributes(self):
        response = self.client.get_queue_attributes(
            QueueUrl=self.queue_url, AttributeNames=["All"]
        )
        if response["Attributes"]:
            return response["Attributes"]
        return False

    # Resource Policy

    def describe_resource_policy(self):
        if self.queue_attributes:
            try:
                if self.queue_attributes["Policy"]:
                    return json.loads(self.queue_attributes["Policy"])
            except KeyError:
                return False
        return False

    # Context Config

    def is_encrypted(self):
        if self.queue_attributes:
            return self.queue_attributes["SqsManagedSseEnabled"]

    def trust_policy(self):
        return None

    def public(self):
        return None

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.resource_policy,
            "is_encrypted": self.is_encrypted(),
            "public": self.public(),
        }
        return checks
