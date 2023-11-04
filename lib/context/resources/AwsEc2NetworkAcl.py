"""MetaCheck: AwsEc2NetworkAcl"""

from aws_arn import generate_arn

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
        self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
        # Describe
        self.network_acl = self.describe_network_acls()
        if not self.network_acl:
            return False
        # Drilled MetaChecks
        self.subnets = self._describe_network_acls_subnets()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split("/")[1]

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

    def _describe_network_acls_subnets(self):
        subnets = {}
        if self.network_acl:
            if self.network_acl[0].get("Associations"):
                for association in self.network_acl[0].get("Associations"):
                    arn = generate_arn(
                        association["SubnetId"],
                        "ec2",
                        "vpc",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    subnets[arn] = {}
        return subnets

    # MetaChecks

    def is_default(self):
        if self.network_acl:
            return self.network_acl[0]["IsDefault"]
        return False

    def is_ingress_rule_unrestricted(self, rule):
        """ """
        if "CidrBlock" in rule:
            if (
                "0.0.0.0/0" in rule["CidrBlock"]
                and rule["Egress"] is False
                and rule["RuleAction"] == "allow"
            ):
                return True
        if "Ipv6CidrBlock" in rule:
            if (
                "::/0" in rule["Ipv6CidrBlock"]
                and rule["Egress"] is False
                and rule["RuleAction"] == "allow"
            ):
                return True
        return False

    def is_egress_rule_unrestricted(self, rule):
        """ """
        if "CidrBlock" in rule:
            if (
                "0.0.0.0/0" in rule["CidrBlock"]
                and rule["Egress"] is True
                and rule["RuleAction"] == "allow"
            ):
                return True
        if "Ipv6CidrBlock" in rule:
            if (
                "::/0" in rule["Ipv6CidrBlock"]
                and rule["Egress"] is True
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

    def is_attached(self):
        if self.network_acl:
            if self.subnets:
                return True
        return False

    def public(self):
        return None

    def associations(self):
        associations = {
            "subnets": self.subnets,
        }
        return associations

    def checks(self):
        checks = {
            "is_default": self.is_default(),
            "is_ingress_rules_unrestricted": self.is_ingress_rules_unrestricted(),
            "is_egress_rules_unrestricted": self.is_egress_rules_unrestricted(),
            "is_attached": self.is_attached(),
            "public": self.public(),
        }
        return checks
