"""MetaCheck: AwsEc2NetworkAcl"""

import boto3

from lib.metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(
        self, logger, finding, metachecks, mh_filters_checks, sess, drilled=False
    ):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            self.mh_filters_checks = mh_filters_checks
            region = finding["Region"]
            if not sess:
                self.client = boto3.client("ec2", region_name=region)
            else:
                self.client = sess.client(service_name="ec2", region_name=region)
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.network_acl = self._describe_network_acls()

    # Describe Functions

    def _describe_network_acls(self):
        response = self.client.describe_network_acls(
            Filters=[
                {
                    "Name": "network-acl-id",
                    "Values": [
                        self.resource_id,
                    ],
                },
            ],
        )
        return response["NetworkAcls"]

    # MetaChecks

    def its_associated_with_subnets(self):
        Subnets = []
        if self.network_acl:
            for Association in self.network_acl[0]["Associations"]:
                Subnets.append(Association["SubnetId"])
            return Subnets
        return False

    def is_default(self):
        if self.network_acl:
            return self.network_acl[0]["IsDefault"]
        return False

    def checks(self):
        checks = ["its_associated_with_subnets", "is_default"]
        return checks
