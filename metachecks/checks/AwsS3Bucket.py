"""MetaCheck: AwsS3Bucket"""

import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class Metacheck:
    def __init__(self, logger, finding, metachecks, mh_filters_checks, metatags, mh_filters_tags, sess):
        self.logger = logger
        if not sess:
            self.client = boto3.client("s3")
        else:
            self.client = sess.client(service_name="s3")
        if metatags or metachecks:
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            if metatags:
                self.mh_filters_tags = mh_filters_tags
                self.tags = self._tags()
            if metachecks:
                self.mh_filters_checks = mh_filters_checks
                self.bucket_acl = self._get_bucket_acl()
                self.bucket_policy = self._get_bucket_policy()

    def _get_bucket_acl(self):
        try:
            response = self.client.get_bucket_acl(Bucket=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] in [
                "AccessDenied",
                "UnauthorizedOperation",
            ]:
                self.logger.error(
                    "Access denied for get_bucket_acl: " + self.resource_id
                )
                return False
            elif err.response["Error"]["Code"] == "NoSuchBucket":
                # deletion was not fully propogated to S3 backend servers
                # so bucket is still available in listing but actually not exists
                pass
                return False
            else:
                self.logger.error("Failed to get_bucket_acl: " + self.resource_id)
                return False
        return response["Grants"]

    def _get_bucket_policy(self):
        try:
            response = self.client.get_bucket_policy(Bucket=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return False
            elif err.response["Error"]["Code"] == "NoSuchBucket":
                # deletion was not fully propogated to S3 backend servers
                # so bucket is still available in listing but actually not exists
                return False
            elif err.response["Error"]["Code"] == "AccessDenied":
                self.logger.error(
                    "Access denied for get_bucket_policy: " + self.resource_id
                )
                return False
            else:
                self.logger.error("Failed to get_bucket_policy: " + self.resource_id)
                return False
        return json.loads(response["Policy"])

    def _tags(self):
        try:
            response = self.client.get_bucket_tagging(Bucket=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] in [
                "AccessDenied",
                "UnauthorizedOperation",
            ]:
                self.logger.error(
                    "Access denied for get_bucket_tagging: " + self.resource_id
                )
                return False
            elif err.response["Error"]["Code"] == "NoSuchTagSet":
                return False
            else:
                self.logger.error("Failed to get_bucket_tagging: " + self.resource_id)
                return False
        return response["TagSet"]
    
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

    def is_public(self):
        if self.is_bucket_policy_public() or self.is_bucket_acl_public():
            return True
        return False

    def checks(self):
        checks = ["is_bucket_acl_public", "is_bucket_policy_public", "is_public", "it_has_bucket_policy", "it_has_bucket_acl"]
        return checks

    def output_tags(self):
        mh_values_tags = {}
        mh_matched_tags = False if self.mh_filters_tags else True
        if self.tags:
            for tag in self.tags:
                mh_values_tags.update({tag["Key"]: tag["Value"]})
            compare = {k: mh_values_tags[k] for k in mh_values_tags if k in self.mh_filters_tags and mh_values_tags[k] == self.mh_filters_tags[k]}
            self.logger.info(
                "Evaluating MetaTag filter. Expected: "
                + str(self.mh_filters_tags)
                + " Found: "
                + str(bool(compare))
            )
            if self.mh_filters_tags and bool(compare):
                mh_matched_tags = True
        return mh_values_tags, mh_matched_tags

    def output_checks(self):
        mh_values_checks = {}
        # If there is no filters, we force match to True
        mh_matched_checks = False if self.mh_filters_checks else True

        mh_matched_checks_all_checks = True
        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values_checks.update({check: hndl})
            if check in self.mh_filters_checks:
                self.logger.info(
                    "Evaluating MetaCheck filter ("
                    + check
                    + "). Expected: "
                    + str(self.mh_filters_checks[check])
                    + " Found: "
                    + str(bool(hndl))
                )
                if self.mh_filters_checks[check] and bool(hndl):
                    mh_matched_checks = True
                elif not self.mh_filters_checks[check] and not hndl:
                    mh_matched_checks = True
                else:
                    mh_matched_checks_all_checks = False
        
        # All checks needs to be matched
        if not mh_matched_checks_all_checks:
            mh_matched_checks = False

        return mh_values_checks, mh_matched_checks
