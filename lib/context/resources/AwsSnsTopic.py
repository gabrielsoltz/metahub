"""MetaCheck: AwsSnsTopic"""


from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import MetaChecksBase


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
        self.client = get_boto3_client(self.logger, "sns", self.region, self.sess)
        # Describe
        self.topic_atributes = self.get_topic_attributes()
        if not self.topic_atributes:
            return False
        self.topic_kms_master_key_id = self.get_topic_atributes_kms_master_key_id()
        # Resource Policy
        self.resource_policy = self.describe_resource_policy()
        # Drilled Metachecks

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]

    # Describe Functions

    def get_topic_attributes(self):
        try:
            response = self.client.get_topic_attributes(TopicArn=self.resource_arn)
            return response.get("Attributes")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NotFoundException":
                self.logger.error(
                    "Failed to get_topic_attributes {}, {}".format(
                        self.resource_id, err
                    )
                )
        return False

    def get_topic_atributes_kms_master_key_id(self):
        if self.topic_atributes:
            try:
                return self.topic_atributes["KmsMasterKeyId"]
            except KeyError:
                return False
        return False

    # Resource Policy

    def describe_resource_policy(self):
        if self.topic_atributes:
            try:
                if self.topic_atributes["Policy"]:
                    return self.topic_atributes["Policy"]
            except KeyError:
                return False
        return False

    # MetaChecks

    def subscriptions_confirmed(self):
        if self.topic_atributes:
            try:
                if self.topic_atributes["SubscriptionsConfirmed"]:
                    if int(self.topic_atributes["SubscriptionsConfirmed"]) == 0:
                        return False
                    return self.topic_atributes["SubscriptionsConfirmed"]
            except KeyError:
                return False
        return False

    def name(self):
        if self.topic_atributes:
            try:
                if self.topic_atributes["DisplayName"]:
                    return self.topic_atributes["DisplayName"]
            except KeyError:
                return False
        return False

    def is_encrypted(self):
        if self.topic_kms_master_key_id:
            return self.topic_kms_master_key_id
        return False

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
            "subscriptions_confirmed": self.subscriptions_confirmed(),
            "name": self.name(),
            "is_encrypted": self.is_encrypted(),
            "public": self.public(),
        }
        return checks
