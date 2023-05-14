"""MetaCheck: AwsEc2NetworkAcl"""

from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase


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
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
            # Describe
            self.network_acl = self.describe_network_acls()
            # Drilled MetaChecks

    # Describe Functions

    def describe_network_acls(self):
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

    def is_ingress_rule_unrestricted(self, rule):
        """ """
        if "CidrBlock" in rule:
            if (
                "0.0.0.0/0" in rule["CidrBlock"]
                and rule["Egress"] == False
                and rule["RuleAction"] == "allow"
            ):
                return True
        if "Ipv6CidrBlock" in rule:
            if (
                "::/0" in rule["Ipv6CidrBlock"]
                and rule["Egress"] == False
                and rule["RuleAction"] == "allow"
            ):
                return True
        return False

    def is_egress_rule_unrestricted(self, rule):
        """ """
        if "CidrBlock" in rule:
            if (
                "0.0.0.0/0" in rule["CidrBlock"]
                and rule["Egress"] == True
                and rule["RuleAction"] == "allow"
            ):
                return True
        if "Ipv6CidrBlock" in rule:
            if (
                "::/0" in rule["Ipv6CidrBlock"]
                and rule["Egress"] == True
                and rule["RuleAction"] == "allow"
            ):
                return True
        return False

    def is_ingress_rules_unrestricted(self):
        failed_rules = []
        if self.network_acl:
            for Entry in self.network_acl[0]["Entries"]:
                if self.is_ingress_rule_unrestricted(Entry):
                    failed_rules.append(Entry)
        if failed_rules:
            return failed_rules
        return False

    def is_egress_rules_unrestricted(self):
        failed_rules = []
        if self.network_acl:
            for Entry in self.network_acl[0]["Entries"]:
                if self.is_egress_rule_unrestricted(Entry):
                    failed_rules.append(Entry)
        if failed_rules:
            return failed_rules
        return False

    def is_public(self):
        if self.network_acl:
            if self.is_ingress_rules_unrestricted():
                return True
        return False

    def checks(self):
        checks = [
            "its_associated_with_subnets",
            "is_default",
            "is_ingress_rules_unrestricted",
            "is_egress_rules_unrestricted",
            "is_public",
        ]
        return checks
