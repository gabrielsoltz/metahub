"""MetaCheck: AwsCloudFrontDistribution"""

from botocore.exceptions import ClientError

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
            self.resource_id = (
                finding["Resources"][0]["Id"].split("/")[-1]
                if not drilled
                else drilled.split("/")[-11]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(
                self.logger, "cloudfront", self.region, self.sess
            )
            # Describe
            self.distribution = self.get_distribution()
            if not self.distribution:
                return False
            # Drilled MetaChecks

    # Describe function

    def get_distribution(self):
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

    # Drilled MetaChecks

    # # MetaChecks
    def it_has_name(self):
        if self.distribution.get("DomainName"):
            return self.distribution.get("DomainName")
        return False

    def it_has_aliases(self):
        if self.distribution.get("DistributionConfig").get("Aliases").get("Items"):
            return (
                self.distribution.get("DistributionConfig").get("Aliases").get("Items")
            )
        return False

    def it_has_origin(self):
        origins = {}
        if self.distribution.get("DistributionConfig").get("Origins"):
            for origin in (
                self.distribution.get("DistributionConfig").get("Origins").get("Items")
            ):
                origins[origin.get("Id")] = origin.get("DomainName")
        return origins

    def it_has_default_root_object(self):
        if self.distribution.get("DistributionConfig").get("DefaultRootObject"):
            return self.distribution.get("DistributionConfig").get("DefaultRootObject")
        return False

    def it_has_certificate(self):
        if self.distribution.get("DistributionConfig").get("ViewerCertificate"):
            return self.distribution.get("DistributionConfig").get("ViewerCertificate")
        return False

    def it_has_waf_web_acl(self):
        if self.distribution.get("DistributionConfig").get("WebACLId"):
            return self.distribution.get("DistributionConfig").get("WebACLId")
        return False

    def is_public(self):
        public_dict = {}
        if self.it_has_aliases():
            for alias in self.it_has_aliases():
                public_dict[alias] = {
                    "from_port": 443,
                    "to_port": 443,
                    "ip_protocol": "tcp",
                }
        elif self.it_has_name():
            public_dict[self.it_has_name()] = {
                "from_port": 443,
                "to_port": 443,
                "ip_protocol": "tcp",
            }
        if public_dict:
            return public_dict
        return False

    # is_encrypted

    def checks(self):
        checks = [
            "it_has_name",
            "it_has_aliases",
            "it_has_origin",
            "it_has_default_root_object",
            "it_has_certificate",
            "it_has_waf_web_acl",
            "is_public",
        ]
        return checks
