"""MetaCheck: AwsElasticsearchDomain"""

import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, metatags, mh_filters_tags, sess):

        self.logger = logger
        if not sess:
            self.client = boto3.client("es")
        else:
            self.client = sess.client(service_name="es")
        if metatags or metachecks:
            self.resource_id = finding["Resources"][0]["Id"].split("/")[-1]
            self.resource_arn = finding["Resources"][0]["Id"]
            if metatags:
                self.mh_filters_tags = mh_filters_tags
                self.tags = self._tags()
            if metachecks:
                self.mh_filters_checks = mh_filters_checks
                self.elasticsearch_domain = self._describe_elasticsearch_domain()

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

    def _tags(self):
        try:
            response = self.client.list_tags(ARN=self.resource_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] in [
                "AccessDenied",
                "UnauthorizedOperation",
            ]:
                self.logger.error("Access denied for list_tags: " + self.resource_id)
                return False
            else:
                self.logger.error("Failed to list_tags: " + self.resource_id)
                return False
        return response["TagList"]

    def it_has_public_endpoint(self):
        public_endpoints = []
        if self.elasticsearch_domain:
            if "Endpoint" in self.elasticsearch_domain:
                public_endpoints.append(self.elasticsearch_domain["Endpoint"])
        if public_endpoints:
            return public_endpoints
        return False

    def it_has_access_policies(self):
        access_policies = {}
        if self.elasticsearch_domain:
            if "AccessPolicies" in self.elasticsearch_domain:
                access_policies = json.loads(
                    self.elasticsearch_domain["AccessPolicies"]
                )["Statement"]
        if access_policies:
            return access_policies
        return False

    def it_has_access_policies_public(self):
        public_policy = []
        if self.it_has_access_policies:
            for statement in self.it_has_access_policies():
                effect = statement["Effect"]
                principal = statement.get("Principal", {})
                not_principal = statement.get("NotPrincipal", None)
                condition = statement.get("Condition", None)
                suffix = "/0"
                if effect == "Allow" and (
                    principal == "*" or principal.get("AWS") == "*"
                ):
                    if condition is not None:
                        if suffix in str(condition.get("IpAddress")):
                            public_policy.append(statement)
                    else:
                        public_policy.append(statement)
                if effect == "Allow" and not_principal is not None:
                    public_policy.append(statement)
        if public_policy:
            return public_policy
        return False

    def is_public(self):
        if self.elasticsearch_domain:
            if self.it_has_access_policies_public() and self.it_has_public_endpoint():
                return True
        return False

    def checks(self):
        checks = [
            "it_has_access_policies",
            "it_has_public_endpoint",
            "it_has_access_policies_public",
            "is_public",
        ]
        return checks
