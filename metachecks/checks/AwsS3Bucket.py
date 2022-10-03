'''MetaCheck: AwsS3Bucket'''

import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError

class Metacheck:

    def __init__(self, logger, finding, mh_filters, sess):
        self.logger = logger
        if not sess:
            self.client = boto3.client('s3')
        else:
            self.client = sess.client(service_name='s3')
        if finding:
            self.mh_filters = mh_filters
            self.resource_id = finding["Resources"][0]["Id"].split(':')[-1]
            self.bucket_acl = self._get_bucket_acl()
            self.bucket_policy = self._get_bucket_policy()
            self.tags = self._tags()
            self.tag_Owner = self._find_tag('Owner')
            self.tag_Name = self._find_tag('Name')
            self.tag_Environment = self._find_tag('Environment')


    def _get_bucket_acl(self):
        try:
            response = self.client.get_bucket_acl(Bucket=self.resource_id)
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                self.logger.error("Access denied for get_bucket_acl: " + self.resource_id)
                return False
            elif err.response['Error']['Code'] == "NoSuchBucket":
                # deletion was not fully propogated to S3 backend servers
                # so bucket is still available in listing but actually not exists
                pass
                return False
            else:
                self.logger.error("Failed to get_bucket_acl: " + self.resource_id)
                return False
        return response['Grants']

    def _get_bucket_policy(self):
        try:
            response = self.client.get_bucket_policy(Bucket=self.resource_id)
        except ClientError as err:
            if err.response['Error']['Code'] == "NoSuchBucketPolicy":
                return False
            elif err.response['Error']['Code'] == "NoSuchBucket":
                # deletion was not fully propogated to S3 backend servers
                # so bucket is still available in listing but actually not exists
                return False
            elif err.response['Error']['Code'] == "AccessDenied":
                self.logger.error("Access denied for get_bucket_policy: " + self.resource_id)
                return False
            else:
                self.logger.error("Failed to get_bucket_policy: " + self.resource_id)
                return False
        return json.loads(response['Policy'])

    def _tags(self):
        try:
            response = self.client.get_bucket_tagging(Bucket=self.resource_id)
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                self.logger.error("Access denied for get_bucket_tagging: " + self.resource_id)
                return False
            elif err.response['Error']['Code'] == "NoSuchTagSet":
                return False
            else:
                self.logger.error("Failed to get_bucket_tagging: " + self.resource_id)
                return False
        return response['TagSet']

    def _find_tag(self, tag):
        if self.tags:
            for _tag in self.tags:
                if _tag['Key'] == tag:
                    return _tag['Value']
        return False

    def is_bucket_acl_public(self):
        public_acls = []
        if self.bucket_acl:
            for grant in self.bucket_acl:
                if grant["Grantee"]["Type"] == "Group":
                    # use only last part of URL as a key:
                    #   http://acs.amazonaws.com/groups/global/AuthenticatedUsers
                    #   http://acs.amazonaws.com/groups/global/AllUsers
                    who = grant["Grantee"]["URI"].split("/")[-1]
                    if who == "AllUsers" or \
                    who == "AuthenticatedUsers":
                        perm = grant["Permission"]
                        # group all permissions (READ(_ACP), WRITE(_ACP), FULL_CONTROL) by AWS predefined groups
                        # public_acls.setdefault(who, []).append(perm)
                        public_acls.append(perm)
        if public_acls: return public_acls
        return False

    def is_bucket_policy_public(self):
        public_policy = []
        if self.bucket_policy:
            for statement in self.bucket_policy['Statement']:
                effect = statement['Effect']
                principal = statement.get('Principal', {})
                not_principal = statement.get('NotPrincipal', None)
                condition = statement.get('Condition', None)
                suffix = "/0"
                if effect == "Allow" and \
                (principal == "*" or principal.get("AWS") == "*"):
                    if condition is not None:
                        if suffix in str(condition.get("IpAddress")):
                            public_policy.append(statement)
                    else:
                        public_policy.append(statement)
                if effect == "Allow" and \
                not_principal is not None:
                    public_policy.append(statement)
        if public_policy: return public_policy
        return False

    def is_public(self):
        if self.is_bucket_policy_public() or self.is_bucket_acl_public():
            return True
        return False

    def checks(self):
        checks = [
            'is_bucket_acl_public',
            'is_bucket_policy_public',
            'is_public'
            ]
        return checks

    def output(self):
        mh_values = {}
        mh_matched = False if self.mh_filters else True
        if not self.checks(): mh_matched = True

        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values.update({check: hndl})
            if check in self.mh_filters and hndl:
                mh_matched = True

        # Tags
        mh_values.update({'tag_Name': self.tag_Name})
        mh_values.update({'tag_Owner': self.tag_Owner})
        mh_values.update({'tag_Environment': self.tag_Environment})
                
        return mh_values, mh_matched