"""MetaCheck: AwsElasticsearchDomain"""

import json

import boto3
from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import ResourcePolicyChecker


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        metachecks,
        mh_filters_checks,
        sess,
        drilled_down,
        drilled=False,
    ):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            self.mh_filters_checks = mh_filters_checks
            if not sess:
                self.client = boto3.client("es", region_name=self.region)
            else:
                self.client = sess.client(service_name="es", region_name=self.region)
            self.resource_id = finding["Resources"][0]["Id"].split("/")[-1]
            self.resource_arn = finding["Resources"][0]["Id"]
            self.mh_filters_checks = mh_filters_checks
            self.elasticsearch_domain = self._describe_elasticsearch_domain()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy(finding, sess)
            # Drilled MetaChecks
            self.security_groups = self.describe_security_groups()
            if drilled_down:
                self.execute_drilled_metachecks()

    # Describe Functions

    def _describe_elasticsearch_domain(self):
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
        if security_groups:
            return security_groups
        return False

    # Resource Policy

    def describe_resource_policy(self, finding, sess):
        if self.elasticsearch_domain:
            try:
                access_policies = json.loads(
                    self.elasticsearch_domain["AccessPolicies"]
                )
                if access_policies:
                    details = ResourcePolicyChecker(
                        self.logger, finding, access_policies
                    ).check_policy()
                    policy = {"policy_checks": details, "policy": access_policies}
                    return policy
                return access_policies
            except KeyError:
                return False
        return False

    # MetaChecks

    def it_has_endpoint(self):
        if self.elasticsearch_domain:
            return self.elasticsearch_domain.get("Endpoints")
        return False

    def it_has_resource_policy(self):
        return self.resource_policy

    def is_public(self):
        if self.resource_policy:
            if (
                self.resource_policy["policy_checks"]["is_public"]
                and self.it_has_endpoint()
            ):
                return self.it_has_endpoint()
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
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("VPCOptions").get("VPCId"):
                return self.elasticsearch_domain.get("VPCOptions").get("VPCId")
        return False

    def its_associated_with_subnets(self):
        if self.elasticsearch_domain:
            if self.elasticsearch_domain.get("VPCOptions").get("SubnetIds"):
                return self.elasticsearch_domain.get("VPCOptions").get("SubnetIds")
        return False

    def checks(self):
        checks = [
            "it_has_resource_policy",
            "it_has_endpoint",
            "is_public",
            "is_rest_encrypted",
            "is_transit_encrypted",
            "is_encrypted",
            "its_associated_with_security_groups",
            "its_associated_with_vpc",
            "its_associated_with_subnets",
        ]
        return checks
