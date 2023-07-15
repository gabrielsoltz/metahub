"""MetaCheck: AwsS3Bucket"""

import json

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
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "s3", self.region, self.sess)
            # Describe
            self.bucket_acl = self.get_bucket_acl()
            self.cannonical_user_id = self.get_canonical_user_id()
            self.bucket_website = self.get_bucket_website()
            self.bucket_public_access_block = self.get_bucket_public_access_block()
            # Resource Policy
            self.resource_policy = self.describe_resource_policy()
            # Drilled MetaChecks

    # Describe Functions

    def get_bucket_acl(self):
        try:
            response = self.client.get_bucket_acl(Bucket=self.resource_id)
        except ClientError as err:
            self.logger.error(
                "Failed to get_bucket_acl {}, {}".format(self.resource_id, err)
            )
            return False
        return response["Grants"]

    def get_canonical_user_id(self):
        try:
            response = self.client.list_buckets()
        except ClientError as err:
            self.logger.error(
                "Failed to get_canonical_user_id {}, {}".format(self.resource_id, err)
            )
            return False
        return response["Owner"]["ID"]

    def get_bucket_website(self):
        try:
            response = self.client.get_bucket_website(Bucket=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchWebsiteConfiguration":
                return False
            else:
                self.logger.error(
                    "Failed to get_bucket_website {}, {}".format(self.resource_id, err)
                )
                return False
        return response

    def get_bucket_public_access_block(self):
        try:
            response = self.client.get_public_access_block(Bucket=self.resource_id)
            return response.get("PublicAccessBlockConfiguration")
        except ClientError as err:
            if (
                not err.response["Error"]["Code"]
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                self.logger.error(
                    "Failed to get_public_access_block {}, {}".format(
                        self.resource_id, err
                    )
                )
            return False

    def get_bucket_encryption(self):
        try:
            response = self.client.get_bucket_encryption(Bucket=self.resource_id)
        except ClientError as err:
            if (
                not err.response["Error"]["Code"]
                == "ServerSideEncryptionConfigurationNotFoundError"
            ):
                self.logger.error(
                    "Failed to get_bucket_encryption {}, {}".format(
                        self.resource_id, err
                    )
                )
            return False
        return response["ServerSideEncryptionConfiguration"]["Rules"]

    # Resource Policy

    def describe_resource_policy(self):
        try:
            response = self.client.get_bucket_policy(Bucket=self.resource_id)
        except ClientError as err:
            if not err.response["Error"]["Code"] == "NoSuchBucketPolicy":
                self.logger.error(
                    "Failed to get_bucket_policy {}, {}".format(self.resource_id, err)
                )
            return False

        if response["Policy"]:
            policy_json = json.loads(response["Policy"])
            checked_policy = PolicyHelper(
                self.logger, self.finding, policy_json
            ).check_policy()
            return checked_policy

        return False

    # MetaChecks

    def it_has_bucket_acl(self):
        bucket_acl = False
        if self.bucket_acl:
            bucket_acl = self.bucket_acl
        return bucket_acl

    def it_has_bucket_acl_cross_account(self):
        acl_with_cross_account = []
        if self.bucket_acl:
            for grant in self.bucket_acl:
                if grant["Grantee"]["Type"] == "CanonicalUser":
                    if grant["Grantee"]["ID"] != self.cannonical_user_id:
                        # perm = grant["Permission"]
                        acl_with_cross_account.append(grant)
        if acl_with_cross_account:
            return acl_with_cross_account
        return False

    def it_has_bucket_acl_public(self):
        public_acls = []
        if self.bucket_acl:
            for grant in self.bucket_acl:
                if grant["Grantee"]["Type"] == "Group":
                    # use only last part of URL as a key:
                    #   http://acs.amazonaws.com/groups/global/AuthenticatedUsers
                    #   http://acs.amazonaws.com/groups/global/AllUsers
                    who = grant["Grantee"]["URI"].split("/")[-1]
                    if who == "AllUsers" or who == "AuthenticatedUsers":
                        # perm = grant["Permission"]
                        # group all permissions (READ(_ACP), WRITE(_ACP), FULL_CONTROL) by AWS predefined groups
                        # public_acls.setdefault(who, []).append(perm)
                        public_acls.append(grant)
        if public_acls:
            return public_acls
        return False

    def it_has_resource_policy(self):
        return self.resource_policy

    def it_has_public_access_block_enabled(self):
        if self.bucket_public_access_block:
            for key, value in self.bucket_public_access_block.items():
                if value == False:
                    return False
            return True
        return False

    def it_has_website_enabled(self):
        if self.bucket_website:
            if self.region == "us-east-1":
                url = "http://%s.s3-website-%s.amazonaws.com" % (
                    self.resource_id,
                    self.region,
                )
            else:
                url = "http://%s.s3-website.%s.amazonaws.com" % (
                    self.resource_id,
                    self.region,
                )
            return url
        return False

    def is_unrestricted(self):
        if self.resource_policy:
            if (
                self.resource_policy["is_unrestricted"]
                or self.it_has_bucket_acl_public()
            ):
                return True
        return False

    def is_public(self):
        public_dict = {}
        if self.it_has_website_enabled():
            if self.resource_policy:
                if (
                    self.resource_policy["is_unrestricted"]
                    or self.it_has_bucket_acl_public()
                ):
                    public_dict[self.it_has_website_enabled()] = []
                    from_port = "443"
                    to_port = "443"
                    ip_protocol = "tcp"
                    public_dict[self.it_has_website_enabled()].append(
                        {
                            "from_port": from_port,
                            "to_port": to_port,
                            "ip_protocol": ip_protocol,
                        }
                    )
        if public_dict:
            return public_dict
        return False

    def is_encrypted(self):
        if self.get_bucket_encryption():
            return True
        return False

    def checks(self):
        checks = [
            "it_has_bucket_acl",
            "it_has_bucket_acl_cross_account",
            "it_has_bucket_acl_public",
            "it_has_resource_policy",
            "it_has_public_access_block_enabled",
            "is_public",
            "is_unrestricted",
            "is_encrypted",
            "it_has_website_enabled",
        ]
        return checks
