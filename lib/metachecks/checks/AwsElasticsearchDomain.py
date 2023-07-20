"""MetaCheck: AwsElasticsearchDomain"""

import json

from aws_arn import generate_arn
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
            self.resource_id = finding["Resources"][0]["Id"].split("/")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "es", self.region, self.sess)
            # Descrbe
            self.elasticsearch_domain = self.describe_elasticsearch_domain()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy()
            # Drilled MetaChecks
            self.security_groups = self.describe_security_groups()
            self.vpcs = self._describe_elasticsearch_domain_vpc()

    # Describe Functions

    def describe_elasticsearch_domain(self):
        try:
            response = self.client.describe_elasticsearch_domain(
                DomainName=self.resource_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.info(
                    "Failed to describe_elasticsearch_domain: {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
            else:
                self.logger.error(
                    "Failed to describe_elasticsearch_domain: {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
        return response["DomainStatus"]

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def describe_security_groups(
        self,
    ):
        security_groups = {}
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("VPCOptions"):
                if self.elasticsearch_domain.get("VPCOptions").get("SecurityGroupIds"):
                    for sg in self.elasticsearch_domain.get("VPCOptions").get(
                        "SecurityGroupIds"
                    ):
                        arn = generate_arn(
                            sg,
                            "ec2",
                            "security_group",
                            self.region,
                            self.account,
                            self.partition,
                        )
                        security_groups[arn] = {}

        return security_groups

    # Resource Policy

    def describe_resource_policy(self):
        if self.elasticsearch_domain:
            try:
                access_policies = json.loads(
                    self.elasticsearch_domain["AccessPolicies"]
                )
                if access_policies:
                    checked_policy = PolicyHelper(
                        self.logger, self.finding, access_policies
                    ).check_policy()
                    # policy = {"policy_checks": checked_policy, "policy": access_policies}
                    return checked_policy
            except KeyError:
                return False
        return False

    # Drilled

    def _describe_elasticsearch_domain_vpc(self):
        vpc = {}
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("VPCOptions"):
                if self.elasticsearch_domain.get("VPCOptions").get("VPCId"):
                    arn = generate_arn(
                        self.elasticsearch_domain.get("VPCOptions").get("VPCId"),
                        "ec2",
                        "vpc",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    vpc[arn] = {}
                    return
        return vpc

    # MetaChecks

    def it_has_private_endpoint(self):
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("Endpoints"):
                return self.elasticsearch_domain.get("Endpoints").get("vpc")
        return False

    def it_has_public_endpoint(self):
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("Endpoint"):
                return self.elasticsearch_domain.get("Endpoint")
        return False

    def it_has_resource_policy(self):
        return self.resource_policy

    def is_unrestricted(self):
        if self.resource_policy:
            if self.resource_policy["is_unrestricted"]:
                return True
        return False

    def is_public(self):
        public_dict = {}
        if self.it_has_public_endpoint() and self.resource_policy["is_unrestricted"]:
            public_dict[self.it_has_public_endpoint()] = [
                {"from_port": "443", "to_port": "443", "ip_protocol": "tcp"}
            ]
        if self.it_has_private_endpoint():
            for sg in self.security_groups:
                if self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                    public_dict[self.it_has_private_endpoint()] = []
                    for rule in self.security_groups[sg].get(
                        "is_ingress_rules_unrestricted"
                    ):
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        ip_protocol = rule.get("IpProtocol")
                        public_dict[self.it_has_private_endpoint()].append(
                            {
                                "from_port": from_port,
                                "to_port": to_port,
                                "ip_protocol": ip_protocol,
                            }
                        )
        if public_dict:
            return public_dict
        return False

    def is_rest_encrypted(self):
        if self.elasticsearch_domain:
            if self.elasticsearch_domain["EncryptionAtRestOptions"]:
                return True
        return False

    def is_transit_encrypted(self):
        if self.elasticsearch_domain:
            if self.elasticsearch_domain["NodeToNodeEncryptionOptions"]:
                return True
        return False

    def is_encrypted(self):
        if self.elasticsearch_domain:
            if self.is_rest_encrypted() and self.is_transit_encrypted():
                return True
        return False

    def its_associated_with_security_groups(self):
        if self.security_groups:
            return self.security_groups
        return False

    def its_associated_with_vpc(self):
        if self.vpcs:
            return self.vpcs
        return False

    def checks(self):
        checks = [
            "it_has_resource_policy",
            "it_has_private_endpoint",
            "it_has_public_endpoint",
            "is_public",
            "is_rest_encrypted",
            "is_transit_encrypted",
            "is_encrypted",
            "its_associated_with_security_groups",
            "its_associated_with_vpc",
            "is_unrestricted",
        ]
        return checks
