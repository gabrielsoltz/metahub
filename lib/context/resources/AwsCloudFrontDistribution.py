"""ResourceType: AwsCloudFrontDistribution"""

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
        self.client = get_boto3_client(
            self.logger, "cloudfront", self.region, self.sess
        )
        # Describe
        self.distribution = self.describe_distribution()
        if not self.distribution:
            return False
        self.distribution_origins = self._describe_distribution_origins()
        # Associated MetaChecks
        self.waf_web_acls = self._describe_distribution_waf_web_acls()
        self.s3s = self._describe_distribution_origins_s3()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[-1]
            if not drilled
            else drilled.split("/")[-1]
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

    def _describe_distribution_origins(self):
        if self.distribution.get("DistributionConfig").get("Origins"):
            return (
                self.distribution.get("DistributionConfig").get("Origins").get("Items")
            )
        return False

    # Associations

    def _describe_distribution_origins_s3(self):
        s3s = {}
        if self.distribution_origins:
            for origin in self.distribution_origins:
                # S3 using website endpoint
                if "s3-website" in origin.get("DomainName") and origin.get(
                    "DomainName"
                ).endswith(".amazonaws.com"):
                    arn = generate_arn(
                        origin.get("DomainName").split(".s3")[0],
                        "s3",
                        "bucket",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    s3s[arn] = {}
                # S3 not using website endpoint
                elif origin.get("S3OriginConfig"):
                    arn = generate_arn(
                        origin.get("DomainName").split(".s3")[0],
                        "s3",
                        "bucket",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    s3s[arn] = {}
        return s3s

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

    def origins(self):
        if self.distribution_origins:
            return self.distribution_origins
        return False

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
            "s3s": self.s3s,
        }
        return associations

    def checks(self):
        checks = {
            "name": self.name(),
            "aliases": self.aliases(),
            "origins": self.origins(),
            "default_root_object": self.default_root_object(),
            "certificate": self.certificate(),
            "field_level_encryption": self.field_level_encryption(),
            "viewer_protocol_policy": self.viewer_protocol_policy(),
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
