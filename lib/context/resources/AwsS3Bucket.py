"""ResourceType: AwsS3Bucket"""

import json

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
        self.client = get_boto3_client(self.logger, "s3", self.region, self.sess)
        self.s3control_client = get_boto3_client(
            self.logger, "s3control", self.region, self.sess
        )
        # Describe
        self.cannonical_user_id = self.list_bucket()
        if not self.cannonical_user_id:
            return False
        self.bucket_acl = self.get_bucket_acl()
        self.bucket_website = self.get_bucket_website()
        self.bucket_public_access_block = self.get_bucket_public_access_block()
        self.account_public_access_block = self.get_account_bucket_public_access_block()
        # Resource Policy
        self.resource_policy = self.describe_resource_policy()
        # Associated MetaChecks

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]

    # Describe Functions

    def list_bucket(self):
        """List buckets and check if the bucket is in the list"""
        try:
            response = self.client.list_buckets(Buckets=[{"Name": self.resource_id}])
            buckets = response.get("Buckets")
            for bucket in buckets:
                if bucket["Name"] == self.resource_id:
                    return response["Owner"]["ID"]
            return False
        except ClientError as err:
            self.logger.error(
                "Failed to list_bucket {}, {}".format(self.resource_id, err)
            )
        return False

    def get_bucket_acl(self):
        try:
            response = self.client.get_bucket_acl(Bucket=self.resource_id)
        except ClientError as err:
            self.logger.error(
                "Failed to get_bucket_acl {}, {}".format(self.resource_id, err)
            )
            return False
        return response["Grants"]

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

    def get_account_bucket_public_access_block(self):
        try:
            response = self.s3control_client.get_public_access_block(
                AccountId=self.account
            )
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
            return policy_json

        return False

    # Context Config

    def bucket_acl_cross_account(self):
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

    def bucket_acl_public(self):
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

    def public_access_block_enabled(self):
        if self.bucket_public_access_block:
            for key, value in self.bucket_public_access_block.items():
                if value is False:
                    return False
            return self.bucket_public_access_block
        return False

    def account_public_access_block_enabled(self):
        if self.account_public_access_block:
            for key, value in self.account_public_access_block.items():
                if value is False:
                    return False
            return self.account_public_access_block
        return False

    def website_enabled(self):
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

    def is_encrypted(self):
        if self.get_bucket_encryption():
            return True
        return False

    def public(self):
        if self.website_enabled():
            return True
        return False

    def trust_policy(self):
        return None

    def associations(self):
        associations = {}
        return associations

    def checks(self):
        checks = {
            "resource_policy": self.resource_policy,
            "website_enabled": self.website_enabled(),
            "bucket_acl": self.bucket_acl,
            "bucket_acl_cross_account": self.bucket_acl_cross_account(),
            "bucket_acl_public": self.bucket_acl_public(),
            "public_access_block_enabled": self.public_access_block_enabled(),
            "account_public_access_block_enabled": self.account_public_access_block_enabled(),
            "public": self.public(),
            "is_encrypted": self.is_encrypted(),
        }
        return checks
