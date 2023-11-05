"""ResourceType: AwsCloudFrontDistribution"""

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
        self.client = get_boto3_client(
            self.logger, "cloudfront", self.region, self.sess
        )
        # Describe
        self.distribution = self.describe_distribution()
        if not self.distribution:
            return False
        # Associated MetaChecks
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

    # Context Config

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

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        return True

    def associations(self):
        associations = {
            "waf_web_acls": self.waf_web_acls,
        }
        return associations

    def checks(self):
        checks = {
            "name": self.name(),
            "aliases": self.aliases(),
            "origin": self.origin(),
            "default_root_object": self.default_root_object(),
            "certificate": self.certificate(),
            "field_level_encryption": self.field_level_encryption(),
            "viewer_protocol_policy": self.viewer_protocol_policy(),
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
