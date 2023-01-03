"""MetaCheck: AwsS3Bucket"""

import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from metachecks.checks.Base import MetaChecksBase


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
            self.cannonical_user_id = self._get_canonical_user_id()
            self.bucket_website = self._get_bucket_website()

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

    def it_has_bucket_policy(self):
        bucket_policy = False
        if self.bucket_policy:
            bucket_policy = self.bucket_policy
        return bucket_policy

    def it_has_bucket_acl(self):
        bucket_acl = False
        if self.bucket_acl:
            bucket_acl = self.bucket_acl
        return bucket_acl

    def is_bucket_acl_public(self):
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
                        public_acls.append(perm)
        if public_acls:
            return public_acls
        return False

    def it_has_bucket_acl_with_cross_account(self):
        acl_with_cross_account = []
        if self.bucket_acl:
            for grant in self.bucket_acl:
                if grant["Grantee"]["Type"] == "CanonicalUser":
                    if grant["Grantee"]["ID"] != self.cannonical_user_id:
                        perm = grant["Permission"]
                        acl_with_cross_account.append(perm)
        if acl_with_cross_account:
            return acl_with_cross_account
        return False

    def is_bucket_policy_public(self):
        public_policy = []
        if self.bucket_policy:
            for statement in self.bucket_policy["Statement"]:
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

    def it_has_bucket_policy_allow_with_wildcard_principal(self):
        policy_with_allow_and_wildcard_principal = []
        if self.bucket_policy:
            for statement in self.bucket_policy["Statement"]:
                effect = statement["Effect"]
                principal = statement.get("Principal", {})
                not_principal = statement.get("NotPrincipal", None)
                condition = statement.get("Condition", None)
                suffix = "/0"
                if effect == "Allow":
                    if principal == "*" or principal.get("AWS") == "*":
                        policy_with_allow_and_wildcard_principal.append(statement)
        if policy_with_allow_and_wildcard_principal:
            return policy_with_allow_and_wildcard_principal
        return False

    def it_has_bucket_policy_allow_with_wildcard_actions(self):
        policy_with_allow_and_wildcard_actions = []
        if self.bucket_policy:
            for statement in self.bucket_policy["Statement"]:
                effect = statement["Effect"]
                try:
                    action = statement["Action"]
                except KeyError:
                    action = ""
                principal = statement.get("Principal", {})
                not_principal = statement.get("NotPrincipal", None)
                condition = statement.get("Condition", None)
                suffix = "/0"
                if effect == "Allow":
                    if action == "*" or action == "s3:*":
                        policy_with_allow_and_wildcard_actions.append(statement)
        if policy_with_allow_and_wildcard_actions:
            return policy_with_allow_and_wildcard_actions
        return False

    def it_has_bucket_policy_allow_with_cross_account_principal(self):
        policy_allow_with_cross_account_principal = []
        if self.bucket_policy:
            for statement in self.bucket_policy["Statement"]:
                effect = statement["Effect"]
                principal = statement.get("Principal", {})
                not_principal = statement.get("NotPrincipal", None)
                condition = statement.get("Condition", None)
                suffix = "/0"
                if effect == "Allow":
                    if principal == "*" or principal.get("AWS") == "*":
                        policy_allow_with_cross_account_principal.append("*")
                    else:
                        if "AWS" in principal:
                            principals = principal["AWS"]
                        elif "Service" in principal:
                            principals = []
                        else:
                            principals = principal
                        if type(principals) is not list:
                            principals = [principals]
                        for p in principals:
                            try:
                                account_id = p.split(":")[4]
                                if account_id != self.account_id:
                                    if account_id not in ("cloudfront"):
                                        policy_allow_with_cross_account_principal.append(
                                            account_id
                                        )
                            except IndexError:
                                self.logger.error(
                                    "Parsing principal %s for bucket %s doesn't looks like ARN, ignoring.. ",
                                    p,
                                    self.resource_id,
                                )
                                # To DO: check identifiers-unique-ids
                                # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
            if policy_allow_with_cross_account_principal:
                return policy_allow_with_cross_account_principal
        return False

    def is_website_enabled(self):
        if self.bucket_website:
            if self.region == "us-east-1":
                url = "http://%s.s3-website-%s.amazonaws.com" % (self.resource_id, self.region)
            else:
                url = "http://%s.s3-website.%s.amazonaws.com" % (self.resource_id, self.region)
            return url
        return False

    def is_public(self):
        if self.is_bucket_policy_public() or self.is_bucket_acl_public():
            return True
        return False

    def is_encrypted(self):
        if self._get_bucket_encryption():
            return True
        return False

    def checks(self):
        checks = [
            "is_bucket_acl_public",
            "is_bucket_policy_public",
            "is_public",
            "it_has_bucket_policy",
            "it_has_bucket_acl",
            "it_has_bucket_acl_with_cross_account",
            "it_has_bucket_policy_allow_with_wildcard_principal",
            "it_has_bucket_policy_allow_with_wildcard_actions",
            "it_has_bucket_policy_allow_with_cross_account_principal",
            "is_encrypted",
            "is_website_enabled"
        ]
        return checks
