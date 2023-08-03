"""MetaCheck: AwsSqsQueue"""

import json

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
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "sqs", self.region, self.sess)
            # Describe
            self.queue_url = self.get_queue_url()
            if not self.queue_url:
                return False
            self.queue_attributes = self.get_queue_atributes()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy()
            # Drilled Metachecks

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
                    checked_policy = PolicyHelper(
                        self.logger,
                        self.finding,
                        json.loads(self.queue_attributes["Policy"]),
                    ).check_policy()
                    # policy = {
                    #     "policy_checks": checked_policy,
                    #     "policy": json.loads(self.queue_attributes["Policy"]),
                    # }
                    return checked_policy
            except KeyError:
                return False
        return False

    # MetaChecks

    def is_encrypted(self):
        if self.queue_attributes:
            return self.queue_attributes["SqsManagedSseEnabled"]

    def it_has_resource_policy(self):
        return self.resource_policy

    def is_unrestricted(self):
        if self.resource_policy:
            if self.resource_policy["is_unrestricted"]:
                return self.resource_policy["is_unrestricted"]
        return False

    def checks(self):
        checks = ["it_has_resource_policy", "is_encrypted", "is_unrestricted"]
        return checks
