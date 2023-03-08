"""MetaCheck: AwsS3Bucket"""

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
                self.client = boto3.client("s3", region_name=region)
            else:
                self.client = sess.client(service_name="s3", region_name=region)
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.region = region
            self.account_id = finding["AwsAccountId"]
            self.mh_filters_checks = mh_filters_checks
            self.bucket_acl = self._get_bucket_acl()
            self.bucket_policy = self._get_bucket_policy()
            if self.bucket_policy:
                self.checked_bucket_policy = ResourcePolicyChecker(self.logger, finding, self.bucket_policy).check_policy()
            self.cannonical_user_id = self._get_canonical_user_id()
            self.bucket_website = self._get_bucket_website()
            self.bucket_public_access_block = self._get_bucket_public_access_block()
    
    # Describe Functions

    def _get_canonical_user_id(self):
        try:
            response = self.client.list_buckets()
        except ClientError as err:
            self.logger.error("Failed to get_canonical_user_id {}, {}".format(self.resource_id, err))
            return False
        return response["Owner"]["ID"]

    def _get_bucket_encryption(self):
        try:
            response = self.client.get_bucket_encryption(Bucket=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return False
            else:
                self.logger.error("Failed to get_bucket_encryption {}, {}".format(self.resource_id, err))
                return False
        return response["ServerSideEncryptionConfiguration"]["Rules"]

    def _get_bucket_acl(self):
        try:
            response = self.client.get_bucket_acl(Bucket=self.resource_id)
        except ClientError as err:
            self.logger.error("Failed to get_bucket_acl {}, {}".format(self.resource_id, err))
            return False
        return response["Grants"]

    def _get_bucket_policy(self):
        try:
            response = self.client.get_bucket_policy(Bucket=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return False
            else:
                self.logger.error("Failed to get_bucket_policy {}, {}".format(self.resource_id, err))
                return False
        return json.loads(response["Policy"])

    def _get_bucket_website(self):
        try:
            response = self.client.get_bucket_website(Bucket=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchWebsiteConfiguration":
                return False
            else:
                self.logger.error("Failed to get_bucket_website {}, {}".format(self.resource_id, err))
                return False
        return response

    def _get_bucket_public_access_block(self):
        try:
            response = self.client.get_public_access_block(Bucket=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return False
            else:
                self.logger.error("Failed to get_public_access_block {}, {}".format(self.resource_id, err))
                return False
        return response['PublicAccessBlockConfiguration']

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
                        perm = grant["Permission"]
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
                        perm = grant["Permission"]
                        # group all permissions (READ(_ACP), WRITE(_ACP), FULL_CONTROL) by AWS predefined groups
                        # public_acls.setdefault(who, []).append(perm)
                        public_acls.append(grant)
        if public_acls:
            return public_acls
        return False

    def it_has_policy(self):
        bucket_policy = False
        if self.bucket_policy:
            bucket_policy = self.bucket_policy
        return bucket_policy

    def it_has_policy_public(self):
        if self.bucket_policy:
            return self.checked_bucket_policy["is_public"]
        return False

    def it_has_policy_principal_wildcard(self):
        if self.bucket_policy:
            return self.checked_bucket_policy["is_principal_wildcard"]
        return False

    def it_has_policy_principal_cross_account(self):
        if self.bucket_policy:
            return self.checked_bucket_policy["is_principal_cross_account"]
        return False

    def it_has_policy_actions_wildcard(self):
        if self.bucket_policy:
            return self.checked_bucket_policy["is_actions_wildcard"]
        return False

    def it_has_public_access_block_enabled(self):
        if self.bucket_public_access_block:
            return self.bucket_public_access_block
        return False

    def it_has_website_enabled(self):
        if self.bucket_website:
            if self.region == "us-east-1":
                url = "http://%s.s3-website-%s.amazonaws.com" % (self.resource_id, self.region)
            else:
                url = "http://%s.s3-website.%s.amazonaws.com" % (self.resource_id, self.region)
            return url
        return False

    def is_unrestricted(self):
        if self.it_has_bucket_policy_public() or self.it_has_bucket_acl_public():
            return True
        return False

    def is_public(self):
        if self.it_has_website_enabled():
            if self.it_has_bucket_policy_public() or self.it_has_bucket_acl_public():
                self.it_has_website_enabled()
        return False

    def is_encrypted(self):
        if self._get_bucket_encryption():
            return True
        return False

    def checks(self):
        checks = [
            "it_has_bucket_acl",
            "it_has_bucket_acl_cross_account",
            "it_has_bucket_acl_public",
            "it_has_policy",
            "it_has_policy_principal_cross_account",
            "it_has_policy_principal_wildcard",
            "it_has_policy_public",
            "it_has_policy_actions_wildcard",
            "it_has_public_access_block_enabled",
            "is_public",
            "is_unrestricted",
            "is_encrypted",
            "it_has_website_enabled"
        ]
        return checks
