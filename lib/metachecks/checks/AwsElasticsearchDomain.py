"""MetaCheck: AwsElasticsearchDomain"""

import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import ResourcePolicyChecker


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client("es", region_name=region)
            else:
                self.client = sess.client(service_name="es", region_name=region)
            self.resource_id = finding["Resources"][0]["Id"].split("/")[-1]
            self.resource_arn = finding["Resources"][0]["Id"]
            self.mh_filters_checks = mh_filters_checks
            self.elasticsearch_domain = self._describe_elasticsearch_domain()
            self.elasticsearch_policy = self._describe_elasticsearch_domain_policy()
            if self.elasticsearch_policy:
                self.checked_elasticsearch_policy = ResourcePolicyChecker(self.logger, finding, self.elasticsearch_policy).check_policy()

    # Describe Functions

    def _describe_elasticsearch_domain(self):
        try:
            response = self.client.describe_elasticsearch_domain(
                DomainName=self.resource_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] in [
                "AccessDenied",
                "UnauthorizedOperation",
            ]:
                self.logger.error(
                    "Access denied for describe_elasticsearch_domain: "
                    + self.resource_id
                )
                return False
            else:
                self.logger.error(
                    "Failed to describe_elasticsearch_domain: " + self.resource_id
                )
                return False
        return response["DomainStatus"]
    
    def _describe_elasticsearch_domain_policy(self):
        if self.elasticsearch_domain:
            try:
                access_policies = json.loads(
                    self.elasticsearch_domain["AccessPolicies"]
                )
                return access_policies
            except KeyError:
                return False
        return False
    
    # MetaChecks

    def it_has_public_endpoint(self):
        public_endpoints = []
        if self.elasticsearch_domain:
            if "Endpoint" in self.elasticsearch_domain:
                public_endpoints.append(self.elasticsearch_domain["Endpoint"])
        if public_endpoints:
            return public_endpoints
        return False

    def it_has_policy(self):
        return self.elasticsearch_policy

    def it_has_policy_principal_cross_account(self):
        if self.elasticsearch_policy:
            return self.checked_elasticsearch_policy["is_principal_cross_account"]
        return False

    def it_has_policy_principal_wildcard(self):
        if self.elasticsearch_policy:
            return self.checked_elasticsearch_policy["is_principal_wildcard"]
        return False

    def it_has_policy_public(self):
        if self.elasticsearch_policy:
            return self.checked_elasticsearch_policy["is_public"]
        return False

    def it_has_policy_actions_wildcard(self):
        if self.elasticsearch_policy:
            return self.checked_elasticsearch_policy["is_actions_wildcard"]
        return False

    def is_public(self):
        if self.elasticsearch_domain:
            if self.it_has_policy_public() and self.it_has_public_endpoint():
                return self.it_has_public_endpoint()
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

    def checks(self):
        checks = [
            "it_has_policy",
            "it_has_policy_principal_cross_account",
            "it_has_policy_principal_wildcard",
            "it_has_policy_public",
            "it_has_policy_actions_wildcard",
            "it_has_public_endpoint",
            "is_public",
            "is_rest_encrypted",
            "is_transit_encrypted",
            "is_encrypted",
        ]
        return checks
