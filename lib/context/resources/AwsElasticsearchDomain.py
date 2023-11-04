"""ResourceType: AwsElasticsearchDomain"""

import json

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
        self.client = get_boto3_client(self.logger, "es", self.region, self.sess)
        # Descrbe
        self.elasticsearch_domain = self.describe_elasticsearch_domain()
        if not self.elasticsearch_domain:
            return False
        self.elasticsearch_domain_as = (
            self._describe_elasticsearch_domain_advanced_security()
        )
        # Resource Policy
        self.resource_policy = self.describe_resource_policy()
        # Associated MetaChecks
        self.security_groups = self._describe_elasticsearch_domain_security_groups()
        self.vpcs = self._describe_elasticsearch_domain_vpc()
        self.subnets = self._describe_elasticsearch_domain_subnets()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split("/")[-1]

    # Describe Functions

    def describe_elasticsearch_domain(self):
        try:
            response = self.client.describe_elasticsearch_domain(
                DomainName=self.resource_id
            )
            return response.get("DomainStatus")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to describe_elasticsearch_domain: {}, {}".format(
                        self.resource_id, err
                    )
                )
        return False

    def _describe_elasticsearch_domain_security_groups(
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

    def _describe_elasticsearch_domain_advanced_security(self):
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("AdvancedSecurityOptions"):
                if self.elasticsearch_domain.get("AdvancedSecurityOptions")["Enabled"]:
                    return self.elasticsearch_domain.get("AdvancedSecurityOptions")
        return False

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
        return vpc

    def _describe_elasticsearch_domain_subnets(self):
        subnets = {}
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("VPCOptions"):
                if self.elasticsearch_domain.get("VPCOptions").get("SubnetIds"):
                    for subnet in self.elasticsearch_domain.get("VPCOptions").get(
                        "SubnetIds"
                    ):
                        arn = generate_arn(
                            subnet,
                            "ec2",
                            "subnet",
                            self.region,
                            self.account,
                            self.partition,
                        )
                        subnets[arn] = {}
        return subnets

    def describe_resource_policy(self):
        if self.elasticsearch_domain:
            try:
                access_policies = json.loads(
                    self.elasticsearch_domain["AccessPolicies"]
                )
                if access_policies:
                    return access_policies
            except KeyError:
                return False
        return False

    # Context Config

    def private_endpoint(self):
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("Endpoints"):
                return self.elasticsearch_domain.get("Endpoints").get("vpc")
        return False

    def public_endpoint(self):
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("Endpoint"):
                return self.elasticsearch_domain.get("Endpoint")
        return False

    def internal_user_database(self):
        if self.elasticsearch_domain_as:
            if self.elasticsearch_domain_as.get("InternalUserDatabaseEnabled"):
                return self.elasticsearch_domain.get("InternalUserDatabaseEnabled")
        return False

    def public(self):
        if self.public_endpoint():
            return True
        return False

    def advanced_security_enabled(self):
        return self.elasticsearch_domain_as

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

    def trust_policy(self):
        return None

    def associations(self):
        associations = {
            "security_groups": self.security_groups,
            "vpcs": self.vpcs,
            "subnets": self.subnets,
        }
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.resource_policy,
            "private_endpoint": self.private_endpoint(),
            "public_endpoint": self.public_endpoint(),
            "internal_user_database": self.internal_user_database(),
            "is_rest_encrypted": self.is_rest_encrypted(),
            "is_transit_encrypted": self.is_transit_encrypted(),
            "advanced_security_enabled": self.advanced_security_enabled(),
            "is_encrypted": self.is_encrypted(),
            "public": self.public(),
        }
        return checks
