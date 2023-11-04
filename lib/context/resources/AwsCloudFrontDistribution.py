"""MetaCheck: AwsCloudFrontDistribution"""

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
        self.client = get_boto3_client(
            self.logger, "cloudfront", self.region, self.sess
        )
        # Describe
        self.distribution = self.describe_distribution()
        if not self.distribution:
            return False
        # Drilled MetaChecks
        self.waf_web_acls = self._describe_distribution_waf_web_acls()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[-1]
            if not drilled
            else drilled.split("/")[-11]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

    # Describe functions

    def describe_distribution(self):
        try:
            response = self.client.get_distribution(
                Id=self.resource_id,
            ).get("Distribution")
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchDistribution":
                self.logger.error(
                    "Failed to get_distribution: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    def _describe_distribution_waf_web_acls(self):
        if self.distribution.get("DistributionConfig").get("WebACLId"):
            return {self.distribution.get("DistributionConfig").get("WebACLId"): {}}
        return False

    # MetaChecks

    def name(self):
        if self.distribution.get("DomainName"):
            return self.distribution.get("DomainName")
        return False

    def aliases(self):
        if self.distribution.get("DistributionConfig").get("Aliases").get("Items"):
            return (
                self.distribution.get("DistributionConfig").get("Aliases").get("Items")
            )
        return False

    def origin(self):
        origins = {}
        if self.distribution.get("DistributionConfig").get("Origins"):
            for origin in (
                self.distribution.get("DistributionConfig").get("Origins").get("Items")
            ):
                origins[origin.get("Id")] = origin.get("DomainName")
        return origins

    def default_root_object(self):
        if self.distribution.get("DistributionConfig").get("DefaultRootObject"):
            return self.distribution.get("DistributionConfig").get("DefaultRootObject")
        return False

    def certificate(self):
        if self.distribution.get("DistributionConfig").get("ViewerCertificate"):
            return self.distribution.get("DistributionConfig").get("ViewerCertificate")
        return False

    def field_level_encryption(self):
        if self.distribution.get("DistributionConfig").get("FieldLevelEncryptionId"):
            return self.distribution.get("DistributionConfig").get(
                "FieldLevelEncryptionId"
            )
        return False

    def viewer_protocol_policy(self):
        if (
            self.distribution.get("DistributionConfig")
            .get("DefaultCacheBehavior")
            .get("ViewerProtocolPolicy")
        ):
            return (
                self.distribution.get("DistributionConfig")
                .get("DefaultCacheBehavior")
                .get("ViewerProtocolPolicy")
            )
        return False

    def is_public(self):
        public_dict = {}
        if self.aliases():
            for alias in self.aliases():
                public_dict[alias] = {
                    "from_port": 443,
                    "to_port": 443,
                    "ip_protocol": "tcp",
                }
        elif self.name():
            public_dict[self.name()] = {
                "from_port": 443,
                "to_port": 443,
                "ip_protocol": "tcp",
            }
        if public_dict:
            return public_dict
        return False

    def is_encrypted(self):
        if self.certificate() and self.viewer_protocol_policy():
            if (
                self.viewer_protocol_policy() == "redirect-to-https"
                or self.viewer_protocol_policy() == "https-only"
            ):
                return True
        return False

    def associations(self):
        associations = {
            "waf_web_acls": self.waf_web_acls,
        }
        return associations

    def checks(self):
        checks = {
            "is_public": self.is_public(),
            "is_encrypted": self.is_encrypted(),
            "name": self.name(),
            "aliases": self.aliases(),
            "origin": self.origin(),
            "default_root_object": self.default_root_object(),
            "certificate": self.certificate(),
            "field_level_encryption": self.field_level_encryption(),
            "viewer_protocol_policy": self.viewer_protocol_policy(),
        }
        return checks
